//! Black-box compatibility checks for unusual HTTP/1 response framing.

use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::Duration,
};

use anyhow::{Context, Result, ensure};

use crate::{
    ConfigFixtures, Origins, ProxyProcess, RunOptions, proxy_config, reserve_addresses,
    wait_for_listener,
};

const BODY_LIMIT: usize = 8 * 1024 * 1024;

/// Runs the legacy HTTP matrix against a fresh production proxy and a raw
/// loopback origin. The origin writes response bytes itself, because normal
/// HTTP libraries refuse to produce the malformed responses this check needs.
pub fn run(options: &RunOptions) -> Result<()> {
    let temp = tempfile::tempdir().context("creating legacy HTTP simulation directory")?;
    let origin = LegacyOrigin::start()?;
    let origins = Origins::start()?;
    let [proxy_address, metrics_address] = reserve_addresses()?;
    let config = proxy_config(
        proxy_address,
        metrics_address,
        &origins,
        ConfigFixtures {
            socks: None,
            http_forward: None,
            dns: None,
            domain_list: None,
        },
    );
    let config_path = temp.path().join("config.json");
    std::fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;

    let mut proxy = ProxyProcess::start(&options.binary, &config_path)?;
    let result = (|| {
        wait_for_listener(proxy_address, options.timeout, &mut proxy)?;
        wait_for_listener(metrics_address, options.timeout, &mut proxy)?;

        expect_response(
            proxy_address,
            origin.address,
            "/http10-close",
            "HTTP/1.0",
            200,
            b"http10-close",
        )?;
        expect_response(
            proxy_address,
            origin.address,
            "/http11-close",
            "HTTP/1.1",
            200,
            b"http11-close",
        )?;
        expect_response(
            proxy_address,
            origin.address,
            "/chunked-trailers",
            "HTTP/1.1",
            200,
            b"chunked trailers",
        )?;
        expect_response(
            proxy_address,
            origin.address,
            "/early-hints",
            "HTTP/1.1",
            200,
            b"early hints",
        )?;
        expect_response_with_method(
            proxy_address,
            origin.address,
            "/head",
            "HEAD",
            "HTTP/1.1",
            200,
            b"",
        )?;
        expect_response(
            proxy_address,
            origin.address,
            "/no-content",
            "HTTP/1.1",
            204,
            b"",
        )?;

        expect_rejected(
            proxy_address,
            origin.address,
            &origin.requests,
            "/truncated-content-length",
        )?;
        expect_response(
            proxy_address,
            origin.address,
            "/health",
            "HTTP/1.1",
            200,
            b"healthy",
        )?;
        expect_rejected(
            proxy_address,
            origin.address,
            &origin.requests,
            "/conflicting-framing-content-length-first",
        )?;
        expect_response(
            proxy_address,
            origin.address,
            "/health",
            "HTTP/1.1",
            200,
            b"healthy",
        )?;
        expect_rejected(
            proxy_address,
            origin.address,
            &origin.requests,
            "/conflicting-framing-transfer-encoding-first",
        )?;
        expect_response(
            proxy_address,
            origin.address,
            "/health",
            "HTTP/1.1",
            200,
            b"healthy",
        )
        .context("checking recovery after Transfer-Encoding first conflict")?;
        ensure!(
            origin.requests() == 12,
            "legacy origin handled {} requests, expected 12",
            origin.requests()
        );
        Ok(())
    })();

    match result {
        Ok(()) => proxy.stop(options.shutdown_timeout),
        Err(error) => {
            let _ = proxy.stop(options.shutdown_timeout);
            Err(error.context(format!("proxy stderr:\n{}", proxy.stderr())))
        }
    }
}

struct LegacyOrigin {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicU64>,
    thread: Option<thread::JoinHandle<()>>,
}

impl LegacyOrigin {
    fn start() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let thread_stop = stop.clone();
        let requests = Arc::new(AtomicU64::new(0));
        let thread_requests = requests.clone();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let requests = thread_requests.clone();
                        thread::spawn(move || {
                            let _ = serve(stream, &requests);
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2));
                    }
                    Err(_) => break,
                }
            }
        });
        Ok(Self {
            address,
            stop,
            requests,
            thread: Some(thread),
        })
    }
    fn requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }
}

impl Drop for LegacyOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve(mut stream: TcpStream, requests: &AtomicU64) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let request = read_headers(&mut stream)?;
    let request = String::from_utf8_lossy(&request);
    let target = request
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("legacy origin request had no target")?;
    let path = target
        .split_once("://")
        .and_then(|(_, rest)| rest.find('/').map(|offset| &rest[offset..]))
        .unwrap_or(target)
        .split('?')
        .next()
        .unwrap_or("/");
    requests.fetch_add(1, Ordering::Relaxed);
    let response = match path {
        "/health" => regular(b"healthy"),
        "/http10-close" => b"HTTP/1.0 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhttp10-close".to_vec(),
        "/http11-close" => b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\nhttp11-close".to_vec(),
        "/chunked-trailers" => b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTrailer: X-Legacy-Trailer\r\nConnection: close\r\n\r\n8;part=one\r\nchunked \r\n8;part=two\r\ntrailers\r\n0\r\nX-Legacy-Trailer: present\r\n\r\n".to_vec(),
        "/early-hints" => [b"HTTP/1.1 103 Early Hints\r\nLink: </legacy.css>; rel=preload\r\n\r\n".as_slice(), regular(b"early hints").as_slice()].concat(),
        "/head" => b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\n".to_vec(),
        "/no-content" => b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n".to_vec(),
        "/truncated-content-length" => b"HTTP/1.1 200 OK\r\nContent-Length: 32\r\nConnection: close\r\n\r\ntoo short".to_vec(),
        "/conflicting-framing-content-length-first" => conflicting(true),
        "/conflicting-framing-transfer-encoding-first" => conflicting(false),
        _ => b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n".to_vec(),
    };
    stream.write_all(&response)?;
    Ok(())
}

fn regular(body: &[u8]) -> Vec<u8> {
    format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    )
    .bytes()
    .chain(body.iter().copied())
    .collect()
}

fn conflicting(content_length_first: bool) -> Vec<u8> {
    let framing = if content_length_first {
        "Content-Length: 5\r\nTransfer-Encoding: chunked\r\n"
    } else {
        "Transfer-Encoding: chunked\r\nContent-Length: 5\r\n"
    };
    format!("HTTP/1.1 200 OK\r\n{framing}Connection: close\r\n\r\n5\r\nhello\r\n0\r\n\r\n")
        .into_bytes()
}

fn expect_response(
    proxy: SocketAddr,
    origin: SocketAddr,
    path: &str,
    version: &str,
    status: u16,
    body: &[u8],
) -> Result<()> {
    expect_response_with_method(proxy, origin, path, "GET", version, status, body)
}

fn expect_response_with_method(
    proxy: SocketAddr,
    origin: SocketAddr,
    path: &str,
    method: &str,
    version: &str,
    status: u16,
    body: &[u8],
) -> Result<()> {
    let response = request(proxy, origin, path, method, version)?;
    ensure!(
        response.status == status,
        "{path}: expected status {status}, got {}",
        response.status
    );
    ensure!(
        response.body == body,
        "{path}: unexpected body {:?}",
        response.body
    );
    if method == "HEAD" {
        ensure!(
            response.content_length.is_some(),
            "{path}: missing representation length"
        );
    }
    Ok(())
}

fn expect_rejected(
    proxy: SocketAddr,
    origin: SocketAddr,
    requests: &AtomicU64,
    path: &str,
) -> Result<()> {
    let before = requests.load(Ordering::Relaxed);
    let result = request(proxy, origin, path, "GET", "HTTP/1.1");
    let deadline = std::time::Instant::now() + Duration::from_secs(1);
    while requests.load(Ordering::Relaxed) == before && std::time::Instant::now() < deadline {
        thread::sleep(Duration::from_millis(2));
    }
    ensure!(
        requests.load(Ordering::Relaxed) > before,
        "{path}: proxy did not reach the legacy origin"
    );
    match result {
        Ok(response) => ensure!(
            response.status >= 400,
            "{path}: malformed upstream response reached client as {}",
            response.status
        ),
        Err(error) => ensure!(
            is_expected_rejection(&error),
            "{path}: proxy request failed before rejecting the malformed response: {error:#}"
        ),
    }
    Ok(())
}

fn is_expected_rejection(error: &anyhow::Error) -> bool {
    error
        .chain()
        .filter_map(|cause| cause.downcast_ref::<std::io::Error>())
        .any(|cause| {
            matches!(
                cause.kind(),
                std::io::ErrorKind::UnexpectedEof
                    | std::io::ErrorKind::ConnectionReset
                    | std::io::ErrorKind::ConnectionAborted
            )
        })
}

struct Response {
    status: u16,
    body: Vec<u8>,
    content_length: Option<usize>,
}

fn request(
    proxy: SocketAddr,
    origin: SocketAddr,
    path: &str,
    method: &str,
    version: &str,
) -> Result<Response> {
    let mut stream = TcpStream::connect_timeout(&proxy, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    write!(
        stream,
        "{method} http://{origin}{path} {version}\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
    )?;
    read_response(&mut stream, method)
}

fn read_response(stream: &mut TcpStream, method: &str) -> Result<Response> {
    let mut headers = read_headers(stream)?;
    let mut response_status = status(&headers)?;
    while (100..200).contains(&response_status) && response_status != 101 {
        headers = read_headers(stream)?;
        response_status = status(&headers)?;
    }
    let header_text = String::from_utf8_lossy(&headers);
    let content_length = header_text
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim())
        })
        .map(str::parse)
        .transpose()?;
    if let Some(length) = content_length {
        ensure!(
            length <= BODY_LIMIT,
            "response Content-Length exceeds body limit"
        );
    }
    if method == "HEAD" || matches!(response_status, 101 | 204 | 304) {
        return Ok(Response {
            status: response_status,
            body: Vec::new(),
            content_length,
        });
    }
    let chunked = header_text.lines().any(|line| {
        line.split_once(':').is_some_and(|(name, value)| {
            name.eq_ignore_ascii_case("transfer-encoding")
                && value.trim().eq_ignore_ascii_case("chunked")
        })
    });
    ensure!(
        !(chunked && content_length.is_some()),
        "downstream response contains both Transfer-Encoding and Content-Length"
    );
    let mut body = Vec::new();
    if let Some(length) = content_length {
        body.resize(length, 0);
        stream.read_exact(&mut body)?;
    } else if chunked {
        loop {
            let line = read_line(stream)?;
            let length =
                usize::from_str_radix(line.split(';').next().unwrap_or_default().trim(), 16)?;
            if length == 0 {
                while !read_line(stream)?.is_empty() {}
                break;
            }
            ensure!(
                body.len().saturating_add(length) <= BODY_LIMIT,
                "chunked response exceeds body limit"
            );
            let start = body.len();
            body.resize(start + length, 0);
            stream.read_exact(&mut body[start..])?;
            ensure!(
                read_line(stream)?.is_empty(),
                "chunk was not CRLF terminated"
            );
        }
    } else {
        let mut chunk = [0; 8192];
        loop {
            let count = stream.read(&mut chunk)?;
            if count == 0 {
                break;
            }
            ensure!(
                body.len().saturating_add(count) <= BODY_LIMIT,
                "close-delimited response exceeds body limit"
            );
            body.extend_from_slice(&chunk[..count]);
        }
    }
    Ok(Response {
        status: response_status,
        body,
        content_length,
    })
}

fn status(headers: &[u8]) -> Result<u16> {
    String::from_utf8_lossy(headers)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("response has no HTTP status")?
        .parse()
        .context("response has invalid HTTP status")
}

fn read_line(stream: &mut TcpStream) -> Result<String> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        ensure!(
            bytes.len() <= 64 * 1024,
            "legacy response line exceeded limit"
        );
        if bytes.ends_with(b"\r\n") {
            bytes.truncate(bytes.len() - 2);
            return String::from_utf8(bytes).context("legacy response line was not UTF-8");
        }
    }
}

fn read_headers(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    loop {
        let mut byte = [0];
        stream.read_exact(&mut byte)?;
        bytes.push(byte[0]);
        ensure!(
            bytes.len() <= 64 * 1024,
            "legacy response headers exceeded limit"
        );
        if bytes.ends_with(b"\r\n\r\n") {
            return Ok(bytes);
        }
    }
}
