//! A black-box loopback throughput harness for `msgtausch`.
//!
//! It starts a small HTTP origin, drives a proxy over real TCP connections,
//! and checks every response against a deterministic payload. The harness does
//! not link the proxy crates, so its measurements include listener, routing,
//! parsing, and copy costs.

use std::{
    fs,
    io::{BufRead, BufReader, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering as AtomicOrdering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};

const MAX_HEADERS: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Protocol {
    Http,
    Connect,
}

impl Protocol {
    pub const fn label(self) -> &'static str {
        match self {
            Self::Http => "http",
            Self::Connect => "connect",
        }
    }
}

#[derive(Clone, Debug)]
pub struct RunOptions {
    pub proxy: Option<SocketAddr>,
    pub binary: std::path::PathBuf,
    pub protocol: Protocol,
    pub requests: usize,
    pub concurrency: usize,
    pub body_size: usize,
    pub warmup: usize,
    pub duration: Option<Duration>,
    pub deadline: Duration,
    pub request_timeout: Duration,
    pub max_errors: usize,
    pub max_error_rate: f64,
}

#[derive(Clone, Debug)]
pub struct Summary {
    pub protocol: Protocol,
    pub duration: Duration,
    pub attempted: usize,
    pub succeeded: usize,
    pub failed: usize,
    pub bytes: u64,
    pub requests_per_second: f64,
    pub bytes_per_second: f64,
    pub latency_p50: Duration,
    pub latency_p95: Duration,
    pub latency_p99: Duration,
    pub deadline_expired: bool,
}

impl Summary {
    pub fn format_report(&self) -> String {
        format!(
            "protocol={} duration={:.3}s attempted={} succeeded={} failed={}\nrequests/sec={:.2} throughput={}\nlatency p50={:.3}ms p95={:.3}ms p99={:.3}ms",
            self.protocol.label(),
            self.duration.as_secs_f64(),
            self.attempted,
            self.succeeded,
            self.failed,
            self.requests_per_second,
            format_bytes_per_second(self.bytes_per_second),
            self.latency_p50.as_secs_f64() * 1_000.0,
            self.latency_p95.as_secs_f64() * 1_000.0,
            self.latency_p99.as_secs_f64() * 1_000.0,
        )
    }
}

fn format_bytes_per_second(bytes_per_second: f64) -> String {
    const UNITS: [&str; 5] = ["B/s", "KiB/s", "MiB/s", "GiB/s", "TiB/s"];
    let mut value = bytes_per_second.max(0.0);
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.2} {}", UNITS[unit])
}

pub fn run(options: &RunOptions) -> Result<Summary> {
    validate(options)?;
    let payload = Arc::new(deterministic_payload(options.body_size));
    let origin = Origin::start(payload.clone())?;
    let mut child = None;
    let proxy = match options.proxy {
        Some(address) => address,
        None => {
            let address = reserve_address()?;
            let config = tempfile::tempdir().context("creating proxy config directory")?;
            let config_path = config.path().join("config.json");
            let contents = serde_json::to_vec_pretty(&serde_json::json!({
                "servers": [{
                    "type": "standard",
                    "listen-address": address.to_string(),
                    "enabled": true
                }],
                "timeout-seconds": options.request_timeout.as_secs().max(1),
                "forwards": [{"type": "default-network", "classifier": {"type": "true"}}]
            }))
            .context("serializing proxy config")?;
            fs::write(&config_path, contents).context("writing proxy config")?;
            let mut process = ProxyProcess::start(&options.binary, &config_path)?;
            wait_for_listener(
                address,
                options.deadline.min(Duration::from_secs(10)),
                &mut process,
            )?;
            child = Some((process, config));
            address
        }
    };

    let outcome = run_against(proxy, origin.address, payload, options);
    drop(child);
    outcome
}

fn validate(options: &RunOptions) -> Result<()> {
    ensure!(options.concurrency > 0, "concurrency must be at least 1");
    ensure!(options.body_size > 0, "body-size must be at least 1");
    ensure!(!options.deadline.is_zero(), "deadline must be positive");
    ensure!(
        !options.request_timeout.is_zero(),
        "request-timeout must be positive"
    );
    ensure!(
        options.max_error_rate.is_finite() && (0.0..=1.0).contains(&options.max_error_rate),
        "max-error-rate must be between 0 and 1"
    );
    ensure!(
        options.requests > 0 || options.duration.is_some(),
        "requests may be 0 only with --duration"
    );
    Ok(())
}

fn run_against(
    proxy: SocketAddr,
    origin: SocketAddr,
    payload: Arc<Vec<u8>>,
    options: &RunOptions,
) -> Result<Summary> {
    for _ in 0..options.warmup {
        execute(
            proxy,
            origin,
            options.protocol,
            &payload,
            options.request_timeout,
        )
        .context("warmup request failed")?;
    }

    let started = Instant::now();
    let stop_at = options.duration.map(|duration| started + duration);
    let deadline_at = started + options.deadline;
    let next = Arc::new(AtomicUsize::new(0));
    let (results, receiver) = mpsc::channel();
    let workers = (0..options.concurrency)
        .map(|_| {
            let next = next.clone();
            let results = results.clone();
            let payload = payload.clone();
            let options = options.clone();
            thread::spawn(move || {
                loop {
                    let now = Instant::now();
                    if now >= deadline_at || stop_at.is_some_and(|at| now >= at) {
                        return;
                    }
                    let index = next.fetch_add(1, AtomicOrdering::Relaxed);
                    if options.requests > 0 && index >= options.requests {
                        return;
                    }
                    let started = Instant::now();
                    let result = execute(
                        proxy,
                        origin,
                        options.protocol,
                        &payload,
                        options.request_timeout,
                    );
                    let elapsed = started.elapsed();
                    if results.send(RequestResult { elapsed, result }).is_err() {
                        return;
                    }
                }
            })
        })
        .collect::<Vec<_>>();
    drop(results);

    let mut succeeded = 0;
    let mut failed = 0;
    let mut bytes = 0_u64;
    let mut latencies = Vec::new();
    let mut first_error = None;
    for result in receiver {
        match result.result {
            Ok(response_bytes) => {
                succeeded += 1;
                bytes += response_bytes as u64;
                latencies.push(result.elapsed);
            }
            Err(error) => {
                failed += 1;
                first_error.get_or_insert_with(|| error.to_string());
            }
        }
    }
    for worker in workers {
        worker
            .join()
            .map_err(|_| anyhow::anyhow!("throughput worker panicked"))?;
    }
    let elapsed = started.elapsed();
    let attempted = succeeded + failed;
    let deadline_expired =
        Instant::now() >= deadline_at && options.duration.is_none() && options.requests > attempted;
    let error_rate = if attempted == 0 {
        1.0
    } else {
        failed as f64 / attempted as f64
    };
    if deadline_expired {
        bail!(
            "deadline expired after {attempted} of {} requests",
            options.requests
        );
    }
    if failed > options.max_errors || error_rate > options.max_error_rate {
        bail!(
            "throughput run had {failed}/{attempted} failed requests (first error: {})",
            first_error.unwrap_or_else(|| "no requests completed".into())
        );
    }
    if attempted == 0 {
        bail!("throughput run did not complete a request");
    }
    latencies.sort_unstable();
    Ok(Summary {
        protocol: options.protocol,
        duration: elapsed,
        attempted,
        succeeded,
        failed,
        bytes,
        requests_per_second: succeeded as f64 / elapsed.as_secs_f64(),
        bytes_per_second: bytes as f64 / elapsed.as_secs_f64(),
        latency_p50: percentile(&latencies, 0.50),
        latency_p95: percentile(&latencies, 0.95),
        latency_p99: percentile(&latencies, 0.99),
        deadline_expired,
    })
}

struct RequestResult {
    elapsed: Duration,
    result: Result<usize>,
}

fn execute(
    proxy: SocketAddr,
    origin: SocketAddr,
    protocol: Protocol,
    expected: &[u8],
    timeout: Duration,
) -> Result<usize> {
    let stream = TcpStream::connect_timeout(&proxy, timeout)
        .with_context(|| format!("connecting to proxy {proxy}"))?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let mut stream = BufReader::with_capacity(16 * 1024, stream);
    if protocol == Protocol::Connect {
        write!(
            stream.get_mut(),
            "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
        )?;
        ensure!(
            status(&read_headers(&mut stream)?)? == 200,
            "proxy rejected CONNECT"
        );
    }
    let target = if protocol == Protocol::Http {
        format!("http://{origin}/data")
    } else {
        "/data".into()
    };
    write!(
        stream.get_mut(),
        "GET {target} HTTP/1.1\r\nHost: {origin}\r\nConnection: close\r\n\r\n"
    )?;
    let headers = read_headers(&mut stream)?;
    ensure!(
        status(&headers)? == 200,
        "origin returned status {}",
        status(&headers)?
    );
    let content_length = header_value(&headers, "content-length")
        .context("origin response has no content-length")?
        .parse::<usize>()
        .context("invalid origin content-length")?;
    ensure!(
        content_length == expected.len(),
        "origin reported {content_length} bytes, expected {}",
        expected.len()
    );
    let mut received = vec![0_u8; content_length];
    stream
        .read_exact(&mut received)
        .context("reading response body")?;
    ensure!(
        received == expected,
        "response payload did not match deterministic fixture"
    );
    Ok(received.len())
}

fn deterministic_payload(size: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15_u64;
    (0..size)
        .map(|_| {
            state ^= state << 7;
            state ^= state >> 9;
            state as u8
        })
        .collect()
}

fn read_headers(reader: &mut impl BufRead) -> Result<Vec<u8>> {
    let mut headers = Vec::new();
    while headers.len() < MAX_HEADERS {
        let read = reader
            .read_until(b'\n', &mut headers)
            .context("reading response headers")?;
        ensure!(
            read > 0,
            "connection closed before response headers completed"
        );
        if headers.ends_with(b"\r\n\r\n") {
            return Ok(headers);
        }
    }
    bail!("response headers exceed {MAX_HEADERS} bytes")
}

fn status(headers: &[u8]) -> Result<u16> {
    let line = std::str::from_utf8(headers)
        .context("response headers are not UTF-8")?
        .lines()
        .next()
        .context("response has no status line")?;
    line.split_whitespace()
        .nth(1)
        .context("response status line has no status")?
        .parse()
        .context("response status is invalid")
}

fn header_value<'a>(headers: &'a [u8], name: &str) -> Option<&'a str> {
    std::str::from_utf8(headers)
        .ok()?
        .lines()
        .skip(1)
        .find_map(|line| {
            let (key, value) = line.split_once(':')?;
            key.eq_ignore_ascii_case(name).then_some(value.trim())
        })
}

fn percentile(values: &[Duration], percentile: f64) -> Duration {
    if values.is_empty() {
        return Duration::ZERO;
    }
    let index = ((values.len() as f64 * percentile).ceil() as usize).saturating_sub(1);
    values[index.min(values.len() - 1)]
}

fn reserve_address() -> Result<SocketAddr> {
    Ok(TcpListener::bind("127.0.0.1:0")?.local_addr()?)
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
        if let Some(status) = process.exit_status()? {
            bail!("proxy exited before {address} became ready with {status}");
        }
        thread::sleep(Duration::from_millis(10));
    }
    bail!("proxy listener {address} did not become ready within {timeout:?}")
}

struct ProxyProcess(Child);

impl ProxyProcess {
    fn start(binary: &Path, config: &Path) -> Result<Self> {
        ensure!(
            binary.is_file(),
            "proxy binary {} does not exist",
            binary.display()
        );
        let child = Command::new(binary)
            .arg("--config")
            .arg(config)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .with_context(|| format!("starting proxy {}", binary.display()))?;
        Ok(Self(child))
    }

    fn exit_status(&mut self) -> Result<Option<std::process::ExitStatus>> {
        self.0.try_wait().context("checking proxy process status")
    }
}

impl Drop for ProxyProcess {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct Origin {
    address: SocketAddr,
    stopping: Arc<AtomicBool>,
    thread: Option<thread::JoinHandle<()>>,
}

impl Origin {
    fn start(payload: Arc<Vec<u8>>) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0").context("binding origin")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stopping = Arc::new(AtomicBool::new(false));
        let stop = stopping.clone();
        let thread = thread::spawn(move || {
            while !stop.load(AtomicOrdering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let payload = payload.clone();
                        thread::spawn(move || {
                            let _ = respond(stream, &payload);
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
            thread: Some(thread),
        })
    }
}

impl Drop for Origin {
    fn drop(&mut self) {
        self.stopping.store(true, AtomicOrdering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn respond(stream: TcpStream, payload: &[u8]) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let mut reader = BufReader::with_capacity(16 * 1024, stream);
    let headers = read_headers(&mut reader)?;
    let mut stream = reader.into_inner();
    let request = std::str::from_utf8(&headers).context("origin request is not UTF-8")?;
    let valid = request
        .lines()
        .next()
        .is_some_and(|line| line == "GET /data HTTP/1.1");
    if !valid {
        stream.write_all(
            b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        )?;
        return Ok(());
    }
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    )?;
    stream.write_all(payload)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_payload_is_repeatable() {
        assert_eq!(deterministic_payload(256), deterministic_payload(256));
        assert_ne!(deterministic_payload(255), deterministic_payload(256));
    }

    #[test]
    fn percentiles_use_nearest_rank() {
        let values = [1, 2, 3, 4]
            .into_iter()
            .map(Duration::from_millis)
            .collect::<Vec<_>>();
        assert_eq!(percentile(&values, 0.50), Duration::from_millis(2));
        assert_eq!(percentile(&values, 0.95), Duration::from_millis(4));
    }

    #[test]
    fn throughput_uses_iec_units_at_boundaries() {
        assert_eq!(format_bytes_per_second(0.0), "0.00 B/s");
        assert_eq!(format_bytes_per_second(1023.0), "1023.00 B/s");
        assert_eq!(format_bytes_per_second(1024.0), "1.00 KiB/s");
        assert_eq!(format_bytes_per_second(1_048_575.0), "1024.00 KiB/s");
        assert_eq!(format_bytes_per_second(1_048_576.0), "1.00 MiB/s");
        assert_eq!(format_bytes_per_second(1_572_864.0), "1.50 MiB/s");
        assert_eq!(format_bytes_per_second(1_073_741_823.0), "1024.00 MiB/s");
        assert_eq!(format_bytes_per_second(1_073_741_824.0), "1.00 GiB/s");
        assert_eq!(format_bytes_per_second(1_099_511_627_776.0), "1.00 TiB/s");
    }

    #[test]
    fn report_uses_one_human_readable_throughput_value() {
        let report = Summary {
            protocol: Protocol::Http,
            duration: Duration::from_secs(1),
            attempted: 1,
            succeeded: 1,
            failed: 0,
            bytes: 1_048_576,
            requests_per_second: 1.0,
            bytes_per_second: 1_048_576.0,
            latency_p50: Duration::from_millis(1),
            latency_p95: Duration::from_millis(2),
            latency_p99: Duration::from_millis(3),
            deadline_expired: false,
        }
        .format_report();
        assert!(report.contains("throughput=1.00 MiB/s"));
        assert!(!report.contains("bytes/sec"));
    }

    #[test]
    fn origin_serves_the_expected_payload() {
        let payload = Arc::new(deterministic_payload(1024));
        let origin = Origin::start(payload.clone()).unwrap();
        let stream = TcpStream::connect(origin.address).unwrap();
        let mut stream = BufReader::new(stream);
        write!(
            stream.get_mut(),
            "GET /data HTTP/1.1\r\nHost: {}\r\nConnection: close\r\n\r\n",
            origin.address
        )
        .unwrap();
        let headers = read_headers(&mut stream).unwrap();
        assert_eq!(status(&headers).unwrap(), 200);
        let mut response = vec![0; payload.len()];
        stream.read_exact(&mut response).unwrap();
        assert_eq!(response, *payload);
    }
}
