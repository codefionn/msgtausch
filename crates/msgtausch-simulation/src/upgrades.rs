//! Loopback helpers for exercising HTTP/1.1 protocol upgrades end to end.

use std::{
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpStream},
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use anyhow::{Context, Result, ensure};

pub(crate) struct UpgradeExchange {
    pub(crate) response: Vec<u8>,
    pub(crate) tunnel_sent: u64,
    pub(crate) tunnel_received: u64,
}

pub(crate) fn execute(
    proxy: SocketAddr,
    origin: &str,
    id: u32,
    path: &str,
    body: &str,
) -> Result<UpgradeExchange> {
    let mut stream = TcpStream::connect_timeout(&proxy, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "GET http://{origin}{path} HTTP/1.1\r\nHost: {origin}\r\nX-Sim-Id: {id}\r\nConnection: Upgrade\r\nUpgrade: msgtausch-simulation\r\n\r\n"
    )?;
    let response = read_headers(&mut stream)?;
    ensure!(
        response.starts_with(b"HTTP/1.1 101"),
        "upgrade was not accepted: {}",
        String::from_utf8_lossy(&response)
    );
    let payload = format!("upgrade:{id}:{body}");
    stream.write_all(payload.as_bytes())?;
    stream.shutdown(Shutdown::Write)?;
    let mut echoed = Vec::new();
    stream.read_to_end(&mut echoed)?;
    ensure!(
        echoed == payload.as_bytes(),
        "upgrade payload was not relayed intact"
    );

    let mut complete_response = response;
    complete_response.extend_from_slice(&echoed);
    Ok(UpgradeExchange {
        response: complete_response,
        tunnel_sent: payload.len() as u64,
        tunnel_received: echoed.len() as u64,
    })
}

/// Handles the fixture's upgrade endpoint after its request headers were read.
/// Returns `true` when the stream has been consumed as an upgraded connection.
pub(crate) fn respond_if_requested(
    stream: &mut TcpStream,
    headers: &str,
    requests: &AtomicU64,
) -> Result<bool> {
    let wants_upgrade = headers.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("upgrade")
                && value.trim().eq_ignore_ascii_case("msgtausch-simulation")
        })
    });
    if !wants_upgrade {
        return Ok(false);
    }
    let request_line = headers
        .lines()
        .next()
        .context("missing upgrade request line")?;
    let mut request_parts = request_line.split_whitespace();
    ensure!(
        request_parts.next() == Some("GET"),
        "upgrade request used an unexpected method: {request_line}"
    );
    let path = request_parts
        .next()
        .context("upgrade request has no target")?;
    ensure!(
        path.starts_with('/'),
        "upgrade request was not rewritten to origin form: {request_line}"
    );
    ensure!(
        headers.lines().any(|line| line.starts_with("X-Sim-Id: ")),
        "upgrade request lost X-Sim-Id"
    );
    ensure!(
        headers.lines().any(|line| {
            line.split_once(':').is_some_and(|(name, value)| {
                name.eq_ignore_ascii_case("connection")
                    && value
                        .split(',')
                        .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
        }),
        "upgrade request omitted Connection: Upgrade"
    );
    requests.fetch_add(1, Ordering::Relaxed);
    stream.write_all(
        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: msgtausch-simulation\r\n\r\n",
    )?;
    let mut payload = Vec::new();
    stream.read_to_end(&mut payload)?;
    stream.write_all(&payload)?;
    Ok(true)
}

fn read_headers(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut headers = Vec::new();
    let mut byte = [0; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        stream
            .read_exact(&mut byte)
            .context("reading upgrade response headers")?;
        headers.push(byte[0]);
        ensure!(
            headers.len() <= 64 * 1024,
            "upgrade response headers are too large"
        );
    }
    Ok(headers)
}
