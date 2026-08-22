use std::{
    fmt,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream},
    path::PathBuf,
    process::{Child, Command, Stdio},
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};
use clap::Parser;
use tempfile::{Builder, NamedTempFile};

const DEFAULT_URLS: &[&str] = &[
    "http://example.com/",
    "http://example.org/",
    "https://example.com/",
    "https://example.org/",
    "https://www.cloudflare.com/cdn-cgi/trace",
    "https://api.github.com/zen",
    "https://www.wikipedia.org/",
    "https://www.google.com/generate_204",
];
const RESPONSE_BYTES: u64 = 1024;
const READY_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Parser)]
#[command(about = "Run opt-in real-internet smoke tests through msgtausch")]
struct Cli {
    /// Use an existing HTTP proxy instead of starting target/debug/msgtausch.
    #[arg(long, value_name = "HOST:PORT")]
    proxy: Option<String>,

    /// Proxy binary to start when --proxy is omitted.
    #[arg(long, default_value = "target/debug/msgtausch", value_name = "PATH")]
    binary: PathBuf,

    /// Upper bound for each request.
    #[arg(long, default_value_t = 15, value_name = "SECONDS")]
    timeout_seconds: u64,

    /// URLs to request. Supplying one or more replaces the default HTTP and HTTPS checks.
    #[arg(value_name = "URL")]
    urls: Vec<String>,
}

struct SpawnedProxy {
    child: Child,
    stderr: Arc<Mutex<Vec<u8>>>,
    stderr_thread: Option<thread::JoinHandle<()>>,
    _config: NamedTempFile,
}

impl SpawnedProxy {
    fn start(binary: &std::path::Path, proxy_address: &str, timeout: Duration) -> Result<Self> {
        let mut config = Builder::new()
            .suffix(".json")
            .tempfile()
            .context("creating temporary proxy config")?;
        write!(
            config,
            r#"{{"servers":[{{"type":"standard","listen-address":"{proxy_address}"}}],"timeout-seconds":{}}}"#,
            timeout.as_secs().max(1)
        )
        .context("writing temporary proxy config")?;
        config.flush().context("flushing temporary proxy config")?;

        if !binary.is_file() {
            bail!(
                "proxy binary {} is missing; run `cargo build -p msgtausch-cli` first or pass --binary",
                binary.display()
            );
        }
        let mut child = Command::new(binary)
            .arg("--config")
            .arg(config.path())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("starting {}", binary.display()))?;
        let stderr = Arc::new(Mutex::new(Vec::new()));
        let captured = Arc::clone(&stderr);
        let pipe = child.stderr.take().expect("stderr was piped");
        let stderr_thread = thread::spawn(move || {
            let mut reader = pipe;
            let mut bytes = Vec::new();
            let _ = reader.read_to_end(&mut bytes);
            *captured.lock().expect("stderr capture lock poisoned") = bytes;
        });

        Ok(Self {
            child,
            stderr,
            stderr_thread: Some(stderr_thread),
            _config: config,
        })
    }

    fn wait_until_ready(&mut self, address: &str) -> Result<()> {
        let socket = parse_socket_address(address)?;
        let deadline = Instant::now() + READY_TIMEOUT;
        loop {
            if TcpStream::connect_timeout(&socket, Duration::from_millis(200)).is_ok() {
                return Ok(());
            }
            if let Some(status) = self.child.try_wait().context("checking proxy process")? {
                let stderr = self.stop_and_stderr();
                bail!("msgtausch exited before it was ready ({status})\n{stderr}");
            }
            if Instant::now() >= deadline {
                let stderr = self.stop_and_stderr();
                bail!("msgtausch did not listen on {address} within 10 seconds\n{stderr}");
            }
            thread::sleep(Duration::from_millis(100));
        }
    }

    fn stop_and_stderr(&mut self) -> String {
        let bytes = self.stderr.lock().expect("stderr capture lock poisoned");
        drop(bytes);
        self.stop();
        let bytes = self.stderr.lock().expect("stderr capture lock poisoned");
        format_stderr(&bytes)
    }

    fn stop(&mut self) {
        if matches!(self.child.try_wait(), Ok(None)) {
            #[cfg(unix)]
            unsafe {
                libc::kill(self.child.id() as i32, libc::SIGTERM);
            }
            #[cfg(not(unix))]
            {
                let _ = self.child.kill();
            }
        }

        let deadline = Instant::now() + Duration::from_secs(2);
        while Instant::now() < deadline {
            match self.child.try_wait() {
                Ok(Some(_)) | Err(_) => break,
                Ok(None) => thread::sleep(Duration::from_millis(50)),
            }
        }
        if matches!(self.child.try_wait(), Ok(None)) {
            let _ = self.child.kill();
        }
        let _ = self.child.wait();
        if let Some(handle) = self.stderr_thread.take() {
            let _ = handle.join();
        }
    }
}

impl Drop for SpawnedProxy {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Debug)]
struct CheckResult {
    url: String,
    outcome: CheckOutcome,
}

#[derive(Debug)]
enum CheckOutcome {
    Pass { status: u16, bytes: usize },
    Fail(String),
}

impl fmt::Display for CheckResult {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.outcome {
            CheckOutcome::Pass { status, bytes } => {
                write!(formatter, "PASS {status} {bytes}B {}", self.url)
            }
            CheckOutcome::Fail(error) => write!(formatter, "FAIL {}: {error}", self.url),
        }
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    if cli.timeout_seconds == 0 {
        bail!("--timeout-seconds must be greater than zero");
    }
    let urls = if cli.urls.is_empty() {
        DEFAULT_URLS.iter().map(ToString::to_string).collect()
    } else {
        cli.urls
    };
    for url in &urls {
        validate_url(url)?;
    }

    let mut spawned = None;
    let timeout = Duration::from_secs(cli.timeout_seconds);
    let proxy_address = match cli.proxy {
        Some(address) => {
            validate_proxy_address(&address)?;
            address
        }
        None => {
            let address = reserve_loopback_address()?;
            let mut proxy = SpawnedProxy::start(&cli.binary, &address, timeout)?;
            proxy.wait_until_ready(&address)?;
            spawned = Some(proxy);
            address
        }
    };

    let agent = make_agent(&proxy_address, timeout)?;
    let results: Vec<_> = urls.iter().map(|url| check_url(&agent, url)).collect();
    for result in &results {
        println!("{result}");
    }
    let passed = results
        .iter()
        .filter(|result| matches!(result.outcome, CheckOutcome::Pass { .. }))
        .count();
    println!("Summary: {passed}/{} passed", results.len());

    drop(spawned);
    if passed == results.len() {
        Ok(())
    } else {
        Err(anyhow!("internet smoke test failed"))
    }
}

fn make_agent(proxy_address: &str, timeout: Duration) -> Result<ureq::Agent> {
    let proxy =
        ureq::Proxy::new(&format!("http://{proxy_address}")).context("invalid proxy address")?;
    Ok(ureq::Agent::config_builder()
        .proxy(Some(proxy))
        .timeout_global(Some(timeout))
        .max_redirects(0)
        .http_status_as_error(false)
        .build()
        .new_agent())
}

fn check_url(agent: &ureq::Agent, url: &str) -> CheckResult {
    let outcome = (|| -> Result<CheckOutcome> {
        let response = agent
            .get(url)
            .call()
            .with_context(|| format!("GET {url}"))?;
        let status = response.status().as_u16();
        if !(200..400).contains(&status) {
            bail!("HTTP {status}");
        }
        let mut reader = response.into_body().into_reader().take(RESPONSE_BYTES);
        let mut body = Vec::new();
        reader
            .read_to_end(&mut body)
            .context("reading response body")?;
        Ok(CheckOutcome::Pass {
            status,
            bytes: body.len(),
        })
    })()
    .unwrap_or_else(|error| CheckOutcome::Fail(error.to_string()));
    CheckResult {
        url: url.into(),
        outcome,
    }
}

fn reserve_loopback_address() -> Result<String> {
    let listener = TcpListener::bind("127.0.0.1:0").context("reserving a local proxy port")?;
    let address = listener
        .local_addr()
        .context("reading reserved proxy address")?;
    Ok(address.to_string())
}

fn parse_socket_address(address: &str) -> Result<SocketAddr> {
    address
        .parse()
        .with_context(|| format!("{address} must be an IP address and port"))
}

fn validate_proxy_address(address: &str) -> Result<()> {
    let Some((host, port)) = address.rsplit_once(':') else {
        bail!("--proxy must be HOST:PORT");
    };
    if host.trim().is_empty() || port.parse::<u16>().ok().filter(|port| *port != 0).is_none() {
        bail!("--proxy must be HOST:PORT with a nonzero port");
    }
    Ok(())
}

fn validate_url(url: &str) -> Result<()> {
    let lower = url.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        Ok(())
    } else {
        bail!("URL must start with http:// or https://: {url}")
    }
}

fn format_stderr(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    if text.is_empty() {
        String::new()
    } else {
        format!("proxy stderr:\n{text}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_cover_http_https_and_multiple_hosts() {
        assert!(DEFAULT_URLS.len() >= 6);
        assert!(DEFAULT_URLS.iter().any(|url| url.starts_with("http://")));
        assert!(DEFAULT_URLS.iter().any(|url| url.starts_with("https://")));
        assert!(DEFAULT_URLS.iter().all(|url| validate_url(url).is_ok()));
    }

    #[test]
    fn accepts_http_and_https_urls() {
        assert!(validate_url("http://example.com/").is_ok());
        assert!(validate_url("HTTPS://example.com/").is_ok());
        assert!(validate_url("ftp://example.com/").is_err());
    }

    #[test]
    fn validates_proxy_addresses() {
        assert!(validate_proxy_address("proxy.example:8080").is_ok());
        assert!(validate_proxy_address("127.0.0.1:1").is_ok());
        assert!(validate_proxy_address("proxy.example:0").is_err());
        assert!(validate_proxy_address("proxy.example").is_err());
    }

    #[test]
    fn formats_results_concisely() {
        let pass = CheckResult {
            url: "http://example.com/".into(),
            outcome: CheckOutcome::Pass {
                status: 200,
                bytes: 42,
            },
        };
        let fail = CheckResult {
            url: "https://example.com/".into(),
            outcome: CheckOutcome::Fail("connection refused".into()),
        };
        assert_eq!(pass.to_string(), "PASS 200 42B http://example.com/");
        assert_eq!(
            fail.to_string(),
            "FAIL https://example.com/: connection refused"
        );
    }

    #[test]
    fn only_prints_stderr_when_present() {
        assert_eq!(format_stderr(b""), "");
        assert_eq!(
            format_stderr(b"configuration error\n"),
            "proxy stderr:\nconfiguration error\n"
        );
    }
}
