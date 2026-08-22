//! Black-box TLS interception simulation.
//!
//! This deliberately uses blocking loopback sockets. The simulator must not
//! share the proxy's async runtime or interception implementation, otherwise a
//! matching bug on both sides can make the test pass.

use std::{
    fs,
    io::{BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use rcgen::generate_simple_self_signed;
use rustls::{
    ClientConfig, ClientConnection, RootCertStore, ServerConfig, ServerConnection, StreamOwned,
    pki_types::ServerName,
};

/// Options shared with the ordinary simulation runner.
#[derive(Clone, Debug)]
pub struct TlsInterceptionOptions {
    pub binary: PathBuf,
    pub timeout: Duration,
    pub shutdown_timeout: Duration,
}

/// Run one real CONNECT interception exchange against the production binary.
///
/// The downstream client trusts the configured interception CA, so the test
/// proves the proxy minted a usable leaf for the CONNECT host. The origin has a
/// different self-signed certificate; accepting it requires the proxy's
/// configured upstream `insecure-skip-verify` path. Neither TLS session is
/// terminated by the simulation client on behalf of the proxy.
pub fn run(options: &TlsInterceptionOptions) -> Result<()> {
    ensure!(
        options.binary.is_file(),
        "proxy binary {} does not exist",
        options.binary.display()
    );
    let temp = tempfile::tempdir().context("creating TLS interception simulation directory")?;
    let origin = TlsOrigin::start()?;
    let [proxy, metrics] = reserve_addresses()?;
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let ca = root.join("tests/compose-intercept/ca/test_ca.crt");
    let ca_key = root.join("tests/compose-intercept/ca/test_ca.key");
    ensure!(
        ca.is_file() && ca_key.is_file(),
        "TLS interception test CA is missing from tests/compose-intercept/ca"
    );
    let config = serde_json::json!({
        "servers": [{"type": "standard", "listen-address": proxy.to_string(), "enabled": true}],
        "timeout-seconds": 5,
        "forwards": [{"type": "default-network", "classifier": {"type": "true"}}],
        "interception": {
            "enabled": true,
            "https": true,
            "ca-file": ca,
            "ca-key-file": ca_key,
            "insecure-skip-verify": true
        },
        "observability": {"prometheus-listen-address": metrics.to_string()}
    });
    let config_path = temp.path().join("config.json");
    fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
    let mut process = ProxyProcess::start(&options.binary, &config_path)?;
    let work = (|| -> Result<()> {
        wait_for_listener(proxy, options.timeout, &mut process)?;
        wait_for_listener(metrics, options.timeout, &mut process)?;
        let baseline_metrics = scrape_metrics(metrics)?;
        let mut tunnel = TcpStream::connect_timeout(&proxy, Duration::from_secs(2))?;
        tunnel.set_read_timeout(Some(Duration::from_secs(5)))?;
        tunnel.set_write_timeout(Some(Duration::from_secs(5)))?;
        write!(
            tunnel,
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            origin.address, origin.address
        )?;
        let response = read_headers(&mut tunnel)?;
        ensure!(
            response.starts_with(b"HTTP/1.1 200"),
            "CONNECT was rejected: {}",
            String::from_utf8_lossy(&response)
        );

        let tls = client_config(&ca)?;
        let server_name = ServerName::try_from(origin.address.ip().to_string())?.to_owned();
        let connection = ClientConnection::new(Arc::new(tls), server_name)?;
        let mut stream = StreamOwned::new(connection, tunnel);
        stream.write_all(
            b"GET /intercepted HTTP/1.1\r\nHost: simulation\r\nConnection: close\r\n\r\n",
        )?;
        let response = read_to_end(&mut stream)?;
        let response = String::from_utf8(response)?;
        ensure!(
            response.starts_with("HTTP/1.1 200"),
            "intercepted request failed: {response}"
        );
        ensure!(
            response.contains("tls-origin:/intercepted"),
            "intercepted response body was wrong: {response}"
        );
        ensure!(
            origin.requests() == 1,
            "TLS origin handled {}, expected 1",
            origin.requests()
        );
        let metrics = wait_for_metrics(metrics, options.timeout, |metrics| {
            metric_delta(&baseline_metrics, metrics, "msgtausch_http_requests_total") == 2.0
        })?;
        ensure!(
            metric_delta(&baseline_metrics, &metrics, "msgtausch_connections_total") == 1.0,
            "TLS interception connection metric was wrong"
        );
        ensure!(
            metric_delta(
                &baseline_metrics,
                &metrics,
                "msgtausch_access_decisions_total"
            ) == 1.0,
            "TLS interception access decision metric was wrong"
        );
        ensure!(
            metric_delta(&baseline_metrics, &metrics, "msgtausch_routes_total") == 1.0,
            "TLS interception route metric was wrong"
        );
        ensure!(
            metric_delta(&baseline_metrics, &metrics, "msgtausch_route_errors_total") == 0.0,
            "TLS interception unexpectedly recorded a route error"
        );
        Ok(())
    })();
    let stopped = process.stop(options.shutdown_timeout);
    work.and(stopped)
}

fn reserve_addresses() -> Result<[SocketAddr; 2]> {
    let listeners = [
        TcpListener::bind("127.0.0.1:0")?,
        TcpListener::bind("127.0.0.1:0")?,
    ];
    let addresses = [listeners[0].local_addr()?, listeners[1].local_addr()?];
    Ok(addresses)
}

fn client_config(ca: &Path) -> Result<ClientConfig> {
    let mut roots = RootCertStore::empty();
    let mut input = BufReader::new(fs::File::open(ca)?);
    for certificate in rustls_pemfile::certs(&mut input) {
        roots
            .add(certificate?)
            .context("adding interception CA to TLS client roots")?;
    }
    ensure!(!roots.is_empty(), "interception CA has no certificates");
    Ok(ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth())
}

struct TlsOrigin {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicU64>,
    thread: Option<thread::JoinHandle<()>>,
}

impl TlsOrigin {
    fn start() -> Result<Self> {
        let certified = generate_simple_self_signed(vec!["localhost".into()])?;
        let private_key: rustls::pki_types::PrivateKeyDer<'static> = certified
            .signing_key
            .serialize_der()
            .try_into()
            .map_err(|error: &'static str| anyhow::anyhow!(error))?;
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], private_key)?;
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicU64::new(0));
        let thread_stop = stop.clone();
        let thread_requests = requests.clone();
        let config = Arc::new(config);
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let requests = thread_requests.clone();
                        let config = config.clone();
                        thread::spawn(move || {
                            let _ = serve_tls_origin(stream, config, &requests);
                        });
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(2))
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

impl Drop for TlsOrigin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_tls_origin(
    stream: TcpStream,
    config: Arc<ServerConfig>,
    requests: &AtomicU64,
) -> Result<()> {
    let connection = ServerConnection::new(config)?;
    let mut stream = StreamOwned::new(connection, stream);
    stream
        .get_mut()
        .set_read_timeout(Some(Duration::from_secs(5)))?;
    let request = read_headers(&mut stream)?;
    ensure!(
        request.starts_with(b"GET /intercepted HTTP/1.1"),
        "TLS origin received unexpected request"
    );
    requests.fetch_add(1, Ordering::Relaxed);
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 23\r\nConnection: close\r\n\r\ntls-origin:/intercepted")?;
    stream.conn.send_close_notify();
    stream.flush()?;
    Ok(())
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

fn read_to_end(stream: &mut impl Read) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    match stream.read_to_end(&mut response) {
        Ok(_) => Ok(response),
        // The proxy closes its HTTP/1.1 downstream connection after the
        // response. rustls correctly reports the missing close_notify, but the
        // bytes are already complete and HTTP's Content-Length frames them.
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(response),
        Err(error) => Err(error.into()),
    }
}

fn scrape_metrics(address: SocketAddr) -> Result<String> {
    let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(2)))?;
    write!(
        stream,
        "GET /metrics HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
    )?;
    let mut response = String::new();
    stream.read_to_string(&mut response)?;
    response
        .split_once("\r\n\r\n")
        .map(|(_, body)| body.to_owned())
        .context("metrics response has no body")
}

fn wait_for_metrics(
    address: SocketAddr,
    timeout: Duration,
    ready: impl Fn(&str) -> bool,
) -> Result<String> {
    let deadline = Instant::now() + timeout;
    let mut last = String::new();
    while Instant::now() < deadline {
        last = scrape_metrics(address)?;
        if ready(&last) {
            return Ok(last);
        }
        thread::sleep(Duration::from_millis(10));
    }
    bail!("TLS interception metrics did not settle within {timeout:?}: {last}")
}

fn metric_delta(baseline: &str, current: &str, name: &str) -> f64 {
    metric_total(current, name) - metric_total(baseline, name)
}

fn metric_total(metrics: &str, name: &str) -> f64 {
    metrics
        .lines()
        .filter_map(|line| {
            let (sample, value) = line.rsplit_once(' ')?;
            sample
                .split_once('{')
                .map_or(sample, |(metric, _)| metric)
                .eq(name)
                .then(|| value.parse::<f64>().ok())
                .flatten()
        })
        .sum()
}

struct ProxyProcess {
    child: Child,
}
impl ProxyProcess {
    fn start(binary: &Path, config: &Path) -> Result<Self> {
        Ok(Self {
            child: Command::new(binary)
                .arg("--config")
                .arg(config)
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()?,
        })
    }
    fn stop(&mut self, timeout: Duration) -> Result<()> {
        if self.child.try_wait()?.is_none() {
            #[cfg(unix)]
            unsafe {
                if libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) != 0 {
                    return Err(std::io::Error::last_os_error().into());
                }
            }
            #[cfg(not(unix))]
            self.child.kill()?;
        }
        let deadline = Instant::now() + timeout;
        while Instant::now() < deadline {
            if let Some(status) = self.child.try_wait()? {
                ensure!(status.success(), "proxy exited unsuccessfully: {status}");
                return Ok(());
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        bail!("proxy did not stop within {timeout:?}")
    }
}
impl Drop for ProxyProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn wait_for_listener(
    address: SocketAddr,
    timeout: Duration,
    process: &mut ProxyProcess,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        if let Some(status) = process.child.try_wait()? {
            bail!("proxy exited before {address} was ready: {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    bail!("listener {address} did not become ready within {timeout:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tls_origin_completes_a_real_handshake() {
        let origin = TlsOrigin::start().unwrap();
        let stream = TcpStream::connect(origin.address).unwrap();
        let config = ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAnyCertificate))
            .with_no_client_auth();
        let connection = ClientConnection::new(
            Arc::new(config),
            ServerName::try_from("localhost").unwrap().to_owned(),
        )
        .unwrap();
        let mut stream = StreamOwned::new(connection, stream);
        stream
            .write_all(b"GET /intercepted HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        let response = String::from_utf8(read_to_end(&mut stream).unwrap()).unwrap();
        assert!(response.contains("tls-origin:/intercepted"));
        assert_eq!(origin.requests(), 1);
    }

    #[derive(Debug)]
    struct AcceptAnyCertificate;
    impl rustls::client::danger::ServerCertVerifier for AcceptAnyCertificate {
        fn verify_server_cert(
            &self,
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &[rustls::pki_types::CertificateDer<'_>],
            _: &ServerName<'_>,
            _: &[u8],
            _: rustls::pki_types::UnixTime,
        ) -> std::result::Result<rustls::client::danger::ServerCertVerified, rustls::Error>
        {
            Ok(rustls::client::danger::ServerCertVerified::assertion())
        }
        fn verify_tls12_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn verify_tls13_signature(
            &self,
            _: &[u8],
            _: &rustls::pki_types::CertificateDer<'_>,
            _: &rustls::DigitallySignedStruct,
        ) -> std::result::Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error>
        {
            Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
        }
        fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
            rustls::crypto::ring::default_provider()
                .signature_verification_algorithms
                .supported_schemes()
        }
    }
}
