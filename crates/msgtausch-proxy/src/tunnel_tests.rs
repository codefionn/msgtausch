use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use compio::runtime;
use msgtausch_config::Config;

use crate::{ProxyMetrics, ProxyRuntime};

#[derive(Default)]
struct Recorder {
    errors: Mutex<Vec<&'static str>>,
    finished: AtomicUsize,
}

impl ProxyMetrics for Recorder {
    fn tunnel_finished(&self, _sent: u64, _received: u64, _duration: Duration) {
        self.finished.fetch_add(1, Ordering::SeqCst);
    }

    fn proxy_error(&self, kind: &'static str) {
        self.errors.lock().unwrap().push(kind);
    }
}

#[derive(Clone, Copy)]
enum Kind {
    Connect,
    Upgrade,
}

/// Blocking origin that optionally answers an upgrade request, then echoes.
fn start_origin(upgrade: bool) -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || {
        while let Ok((mut stream, _)) = listener.accept() {
            thread::spawn(move || {
                if upgrade {
                    read_headers(&mut stream);
                    let _ = stream.write_all(
                        b"HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n",
                    );
                }
                let mut buffer = [0; 256];
                while let Ok(count) = stream.read(&mut buffer) {
                    if count == 0 || stream.write_all(&buffer[..count]).is_err() {
                        break;
                    }
                }
            });
        }
    });
    address
}

fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut headers = Vec::new();
    let mut byte = [0];
    while !headers.ends_with(b"\r\n\r\n") {
        stream.read_exact(&mut byte).unwrap();
        headers.push(byte[0]);
    }
    headers
}

async fn start_proxy(timeout_seconds: u64) -> (SocketAddr, Arc<Recorder>) {
    let listener = compio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let recorder = Arc::new(Recorder::default());
    let config = Config {
        timeout_seconds,
        ..Config::default()
    };
    let proxy = Arc::new(ProxyRuntime::from_config(&config, recorder.clone()).unwrap());
    runtime::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        let _ = proxy.serve_connection(stream, peer).await;
    })
    .detach();
    (address, recorder)
}

/// Opens a tunnel through the proxy and returns the client socket.
fn open_tunnel(proxy: SocketAddr, origin: SocketAddr, kind: Kind) -> TcpStream {
    let mut stream = TcpStream::connect(proxy).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(10)))
        .unwrap();
    match kind {
        Kind::Connect => write!(
            stream,
            "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n"
        ),
        Kind::Upgrade => write!(
            stream,
            "GET http://{origin}/ HTTP/1.1\r\nHost: {origin}\r\nConnection: Upgrade\r\nUpgrade: test\r\n\r\n"
        ),
    }
    .unwrap();
    let response = read_headers(&mut stream);
    let expected: &[u8] = match kind {
        Kind::Connect => b"HTTP/1.1 200",
        Kind::Upgrade => b"HTTP/1.1 101",
    };
    assert!(
        response.starts_with(expected),
        "unexpected handshake: {}",
        String::from_utf8_lossy(&response)
    );
    stream
}

async fn active_tunnel_outlives_idle_timeout(kind: Kind) {
    let origin = start_origin(matches!(kind, Kind::Upgrade));
    let (proxy, recorder) = start_proxy(1).await;
    runtime::spawn_blocking(move || {
        let mut stream = open_tunnel(proxy, origin, kind);
        let started = Instant::now();
        while started.elapsed() < Duration::from_millis(2600) {
            stream.write_all(b"ping").unwrap();
            let mut echo = [0; 4];
            stream
                .read_exact(&mut echo)
                .expect("active tunnel must stay open past the idle timeout");
            assert_eq!(&echo, b"ping");
            thread::sleep(Duration::from_millis(300));
        }
    })
    .await
    .unwrap();
    assert!(
        !recorder.errors.lock().unwrap().contains(&"tunnel_timeout"),
        "active tunnel must not record tunnel_timeout"
    );
}

async fn idle_tunnel_times_out(kind: Kind) {
    let origin = start_origin(matches!(kind, Kind::Upgrade));
    let (proxy, recorder) = start_proxy(1).await;
    let elapsed = runtime::spawn_blocking(move || {
        let mut stream = open_tunnel(proxy, origin, kind);
        let started = Instant::now();
        let mut buffer = [0; 1];
        let read = stream.read(&mut buffer);
        assert!(matches!(read, Ok(0) | Err(_)), "idle tunnel must close");
        started.elapsed()
    })
    .await
    .unwrap();
    assert!(
        elapsed >= Duration::from_millis(900),
        "closed too early: {elapsed:?}"
    );
    assert!(
        elapsed < Duration::from_secs(5),
        "closed too late: {elapsed:?}"
    );
    for _ in 0..50 {
        if recorder.errors.lock().unwrap().contains(&"tunnel_timeout") {
            return;
        }
        compio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("idle tunnel must record tunnel_timeout");
}

#[compio::test]
async fn connect_tunnel_with_traffic_outlives_idle_timeout() {
    active_tunnel_outlives_idle_timeout(Kind::Connect).await;
}

#[compio::test]
async fn upgrade_tunnel_with_traffic_outlives_idle_timeout() {
    active_tunnel_outlives_idle_timeout(Kind::Upgrade).await;
}

#[compio::test]
async fn idle_connect_tunnel_closes_and_records_timeout() {
    idle_tunnel_times_out(Kind::Connect).await;
}

#[compio::test]
async fn idle_upgrade_tunnel_closes_and_records_timeout() {
    idle_tunnel_times_out(Kind::Upgrade).await;
}
