use std::{
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

use anyhow::{Context, Result, ensure};
use compio::runtime;
use msgtausch_config::{Config, InterceptionConfig};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, ServerConfig, ServerConnection,
    SignatureScheme, StreamOwned,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::ring::default_provider,
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
};

use crate::ProxyRuntime;

#[compio::test]
async fn intercepted_https_reuses_the_upstream_tls_connection() {
    let origin = TlsOrigin::start(ResponseConnection::KeepAlive).unwrap();
    let proxy = start_intercepting_proxy().await;

    run_intercepted_client(proxy, origin.address, 2)
        .await
        .unwrap();

    assert_eq!(origin.requests(), 2);
    assert_eq!(
        origin.accepts(),
        1,
        "sequential intercepted HTTPS requests must share one upstream TCP/TLS connection"
    );
}

#[compio::test]
async fn intercepted_https_does_not_reuse_an_upstream_connection_closed_by_the_server() {
    let origin = TlsOrigin::start(ResponseConnection::Close).unwrap();
    let proxy = start_intercepting_proxy().await;

    run_intercepted_client(proxy, origin.address, 2)
        .await
        .unwrap();

    assert_eq!(
        origin.requests(),
        2,
        "a failed stale connection must not replay a request"
    );
    assert_eq!(
        origin.accepts(),
        2,
        "the second request must open a fresh upstream TCP/TLS connection"
    );
}

async fn start_intercepting_proxy() -> SocketAddr {
    let listener = compio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let proxy = Arc::new(ProxyRuntime::with_noop_metrics(&interception_config()).unwrap());
    runtime::spawn(async move {
        let (stream, peer) = listener.accept().await.unwrap();
        proxy.serve_connection(stream, peer).await.unwrap();
    })
    .detach();
    address
}

async fn run_intercepted_client(
    proxy: SocketAddr,
    origin: SocketAddr,
    requests: usize,
) -> Result<()> {
    runtime::spawn_blocking(move || {
        let mut tunnel = TcpStream::connect(proxy).context("connecting to proxy")?;
        tunnel.set_read_timeout(Some(Duration::from_secs(5)))?;
        tunnel.set_write_timeout(Some(Duration::from_secs(5)))?;
        write!(
            tunnel,
            "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\n\r\n"
        )?;
        let connect = read_headers(&mut tunnel)?;
        ensure!(
            connect.starts_with(b"HTTP/1.1 200"),
            "CONNECT was rejected: {}",
            String::from_utf8_lossy(&connect)
        );

        let name = ServerName::try_from(origin.ip().to_string())?.to_owned();
        let connection = ClientConnection::new(Arc::new(accept_any_client_config()), name)?;
        let mut stream = StreamOwned::new(connection, tunnel);
        for request in 0..requests {
            write!(stream, "GET /{request} HTTP/1.1\r\nHost: {origin}\r\n\r\n")?;
            stream.flush()?;
            let response = read_headers(&mut stream)?;
            ensure!(
                response.starts_with(b"HTTP/1.1 200"),
                "intercepted request {request} failed: {}",
                String::from_utf8_lossy(&response)
            );
            let mut body = [0; 2];
            stream.read_exact(&mut body)?;
            ensure!(body == *b"ok", "intercepted response body was wrong");
        }
        Ok(())
    })
    .await
    .map_err(|error| anyhow::anyhow!("joining intercepted client failed: {error:?}"))?
}

fn interception_config() -> Config {
    let (ca_file, ca_key_file) = test_ca_paths();
    Config {
        timeout_seconds: 5,
        interception: InterceptionConfig {
            enabled: true,
            https: true,
            ca_file: Some(ca_file),
            ca_key_file: Some(ca_key_file),
            insecure_skip_verify: true,
            ..InterceptionConfig::default()
        },
        ..Config::default()
    }
}

fn test_ca_paths() -> (PathBuf, PathBuf) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    (
        root.join("tests/compose-intercept/ca/test_ca.crt"),
        root.join("tests/compose-intercept/ca/test_ca.key"),
    )
}

#[derive(Clone, Copy)]
enum ResponseConnection {
    KeepAlive,
    Close,
}

struct TlsOrigin {
    address: SocketAddr,
    stopping: Arc<AtomicBool>,
    accepts: Arc<AtomicUsize>,
    requests: Arc<AtomicUsize>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TlsOrigin {
    fn start(connection: ResponseConnection) -> Result<Self> {
        let (certificate, private_key) = test_tls_identity()?;
        let tls = Arc::new(
            ServerConfig::builder()
                .with_no_client_auth()
                .with_single_cert(vec![certificate], private_key)?,
        );
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stopping = Arc::new(AtomicBool::new(false));
        let accepts = Arc::new(AtomicUsize::new(0));
        let requests = Arc::new(AtomicUsize::new(0));
        let thread_stopping = stopping.clone();
        let thread_accepts = accepts.clone();
        let thread_requests = requests.clone();
        let thread = thread::spawn(move || {
            while !thread_stopping.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        thread_accepts.fetch_add(1, Ordering::SeqCst);
                        let tls = tls.clone();
                        let requests = thread_requests.clone();
                        thread::spawn(move || {
                            let _ = serve_tls_origin(stream, tls, connection, &requests);
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                    }
                    Err(_) => return,
                }
            }
        });
        Ok(Self {
            address,
            stopping,
            accepts,
            requests,
            thread: Some(thread),
        })
    }

    fn accepts(&self) -> usize {
        self.accepts.load(Ordering::SeqCst)
    }

    fn requests(&self) -> usize {
        self.requests.load(Ordering::SeqCst)
    }
}

impl Drop for TlsOrigin {
    fn drop(&mut self) {
        self.stopping.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn test_tls_identity() -> Result<(CertificateDer<'static>, PrivateKeyDer<'static>)> {
    use rustls::pki_types::pem::PemObject;

    let (certificate, key) = test_ca_paths();
    let certificate = CertificateDer::from_pem_slice(&std::fs::read(certificate)?)?;
    let key = PrivatePkcs8KeyDer::from_pem_slice(&std::fs::read(key)?)?.into();
    Ok((certificate, key))
}

fn serve_tls_origin(
    stream: TcpStream,
    tls: Arc<ServerConfig>,
    connection: ResponseConnection,
    requests: &AtomicUsize,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut stream = StreamOwned::new(ServerConnection::new(tls)?, stream);
    loop {
        let request = read_headers(&mut stream)?;
        ensure!(
            request.starts_with(b"GET /"),
            "origin received an unexpected request"
        );
        requests.fetch_add(1, Ordering::SeqCst);
        let header = match connection {
            ResponseConnection::KeepAlive => {
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n".as_slice()
            }
            ResponseConnection::Close => {
                b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\n".as_slice()
            }
        };
        stream.write_all(header)?;
        stream.write_all(b"ok")?;
        stream.flush()?;
        if matches!(connection, ResponseConnection::Close) {
            stream.conn.send_close_notify();
            stream.flush()?;
            return Ok(());
        }
    }
}

fn read_headers(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut headers = Vec::new();
    let mut byte = [0; 1];
    while !headers.ends_with(b"\r\n\r\n") {
        ensure!(headers.len() < 32 * 1024, "HTTP headers were too large");
        stream.read_exact(&mut byte)?;
        headers.push(byte[0]);
    }
    Ok(headers)
}

fn accept_any_client_config() -> ClientConfig {
    ClientConfig::builder()
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
        .with_no_client_auth()
}

#[derive(Debug)]
struct AcceptAnyCertificate;

impl ServerCertVerifier for AcceptAnyCertificate {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}
