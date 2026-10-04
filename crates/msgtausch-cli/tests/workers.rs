//! Starts the real binary with several workers and drives it over TCP.

use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command},
    thread,
    time::{Duration, Instant},
};

const BODY: &str = "origin-ok";

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// A local origin that answers every request with a short fixed body.
fn start_origin() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            thread::spawn(move || {
                let mut seen = Vec::new();
                let mut byte = [0u8; 1];
                while !seen.ends_with(b"\r\n\r\n") {
                    match stream.read(&mut byte) {
                        Ok(1) => seen.push(byte[0]),
                        _ => return,
                    }
                }
                let _ = write!(
                    stream,
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
                    BODY.len()
                );
            });
        }
    });
    address
}

struct Proxy {
    child: Child,
    log: PathBuf,
    address: SocketAddr,
}

impl Proxy {
    fn start(directory: &Path, port: u16, workers: usize) -> Self {
        let config = directory.join("config.json");
        write_config(&config, port, workers);
        let log = directory.join("output.log");
        let log_file = fs::File::create(&log).unwrap();
        let child = Command::new(env!("CARGO_BIN_EXE_msgtausch"))
            .arg("--config")
            .arg(&config)
            .env("NO_COLOR", "1")
            .env_remove("RUST_LOG")
            .stdout(log_file.try_clone().unwrap())
            .stderr(log_file)
            .spawn()
            .unwrap();
        let address: SocketAddr = format!("127.0.0.1:{port}").parse().unwrap();
        let mut proxy = Self {
            child,
            log,
            address,
        };
        proxy.wait_for_log("workers started");
        proxy
    }

    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    fn wait_for_log(&mut self, needle: &str) {
        self.wait_for_log_count(needle, 1);
    }

    fn wait_for_log_count(&mut self, needle: &str, count: usize) {
        let deadline = Instant::now() + Duration::from_secs(20);
        while self.log().matches(needle).count() < count {
            if let Some(status) = self.child.try_wait().unwrap() {
                panic!("proxy exited early ({status}): {}", self.log());
            }
            assert!(Instant::now() < deadline, "timeout: {}", self.log());
            thread::sleep(Duration::from_millis(50));
        }
    }

    fn stop(&mut self, signal: i32) {
        unsafe { libc::kill(self.child.id() as i32, signal) };
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                assert!(status.success(), "exit {status}: {}", self.log());
                return;
            }
            assert!(Instant::now() < deadline, "no exit: {}", self.log());
            thread::sleep(Duration::from_millis(50));
        }
    }
}

impl Drop for Proxy {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn write_config(path: &Path, port: u16, workers: usize) {
    fs::write(
        path,
        format!(
            r#"{{
  "servers": [{{"type": "standard", "listen-address": "127.0.0.1:{port}", "enabled": true}}],
  "timeout-seconds": 10,
  "worker-threads": {workers},
  "forwards": [{{"type": "default-network", "classifier": {{"type": "true"}}}}]
}}"#
        ),
    )
    .unwrap();
}

fn read_response(stream: &mut TcpStream) -> String {
    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    response
}

fn http_forward(proxy: SocketAddr, origin: SocketAddr) {
    let mut stream = TcpStream::connect(proxy).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
    )
    .unwrap();
    let response = read_response(&mut stream);
    assert!(response.starts_with("HTTP/1.1 200"), "{response}");
    assert!(response.ends_with(BODY), "{response}");
}

fn connect_tunnel(proxy: SocketAddr, origin: SocketAddr) {
    let mut stream = TcpStream::connect(proxy).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    write!(
        stream,
        "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n"
    )
    .unwrap();
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        assert_eq!(stream.read(&mut byte).unwrap(), 1, "CONNECT head closed");
        head.push(byte[0]);
    }
    let head = String::from_utf8(head).unwrap();
    assert!(head.starts_with("HTTP/1.1 200"), "{head}");
    write!(stream, "GET / HTTP/1.1\r\nHost: {origin}\r\n\r\n").unwrap();
    let response = read_response(&mut stream);
    assert!(response.ends_with(BODY), "{response}");
}

/// 8 client threads, 30 iterations each, one HTTP forward and one CONNECT per
/// iteration: 480 connections.
fn drive(proxy: SocketAddr, origin: SocketAddr) {
    let clients: Vec<_> = (0..8)
        .map(|_| {
            thread::spawn(move || {
                for _ in 0..30 {
                    http_forward(proxy, origin);
                    connect_tunnel(proxy, origin);
                }
            })
        })
        .collect();
    for client in clients {
        client.join().unwrap();
    }
}

#[test]
fn four_workers_serve_http_and_connect() {
    let directory = tempfile::tempdir().unwrap();
    let origin = start_origin();
    let mut proxy = Proxy::start(directory.path(), free_port(), 4);
    assert!(proxy.log().contains("workers=4"), "{}", proxy.log());
    drive(proxy.address, origin);
    proxy.stop(libc::SIGTERM);
}

#[test]
fn single_worker_still_works() {
    let directory = tempfile::tempdir().unwrap();
    let origin = start_origin();
    let mut proxy = Proxy::start(directory.path(), free_port(), 1);
    assert!(proxy.log().contains("workers=1"), "{}", proxy.log());
    drive(proxy.address, origin);
    proxy.stop(libc::SIGINT);
}

#[test]
fn sighup_restarts_all_workers_on_the_new_config() {
    let directory = tempfile::tempdir().unwrap();
    let origin = start_origin();
    let port = free_port();
    let mut proxy = Proxy::start(directory.path(), port, 4);
    drive(proxy.address, origin);

    write_config(&directory.path().join("config.json"), port, 2);
    unsafe { libc::kill(proxy.child.id() as i32, libc::SIGHUP) };
    proxy.wait_for_log_count("workers started", 2);
    assert!(proxy.log().contains("workers=2"), "{}", proxy.log());
    drive(proxy.address, origin);
    proxy.stop(libc::SIGTERM);
}

#[test]
fn bind_failure_exits_non_zero() {
    let directory = tempfile::tempdir().unwrap();
    let occupied = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = occupied.local_addr().unwrap().port();
    let config = directory.path().join("config.json");
    write_config(&config, port, 4);
    let status = Command::new(env!("CARGO_BIN_EXE_msgtausch"))
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap()
        .status;
    assert!(!status.success());
}
