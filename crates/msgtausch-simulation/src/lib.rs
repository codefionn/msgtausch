//! Deterministic black-box checks for the production `msgtausch` binary.
//!
//! The simulator uses loopback TCP, UDP DNS, and HTTP fixtures, never the
//! proxy's internal crates. A passing run proves the released binary accepted
//! config, chose a route, relayed bytes, exported metrics, and handled SIGTERM.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::{Read, Write},
    net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::{Path, PathBuf},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

pub const SCHEMA_VERSION: u32 = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Scenario {
    pub schema_version: u32,
    pub seed: u64,
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    pub operations: Vec<Operation>,
}

const fn default_concurrency() -> usize {
    1
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Operation {
    pub id: u32,
    pub protocol: Protocol,
    pub method: String,
    pub path: String,
    pub body: String,
    #[serde(default)]
    pub route: ExpectedRoute,
    #[serde(default)]
    pub outcome: ExpectedOutcome,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Protocol {
    Http,
    Connect,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectedRoute {
    #[default]
    Direct,
    Socks5,
    HttpProxy,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ExpectedOutcome {
    #[default]
    Success,
    Blocked,
    RouteFailure,
}

impl ExpectedRoute {
    fn metric_name(self) -> &'static str {
        match self {
            Self::Direct => "direct",
            Self::Socks5 => "socks5",
            Self::HttpProxy => "http_proxy",
        }
    }

    const fn all() -> [Self; 3] {
        [Self::Direct, Self::Socks5, Self::HttpProxy]
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub operation_id: Option<u32>,
    pub component: String,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SimulationReport {
    pub seed: u64,
    pub operations: usize,
    pub completed: usize,
    pub metrics: String,
    pub comparisons: Vec<MetricComparison>,
    pub events: Vec<Event>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MetricComparison {
    pub metric: String,
    pub labels: String,
    pub expected: f64,
    pub actual: f64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FailureArtifact {
    pub schema_version: u32,
    pub seed: u64,
    pub scenario: Scenario,
    pub redacted_config: serde_json::Value,
    pub events: Vec<Event>,
    pub metrics: String,
    #[serde(default)]
    pub proxy_stderr: String,
    pub error: String,
}

#[derive(Clone, Debug)]
pub struct RunOptions {
    pub binary: PathBuf,
    pub artifact_dir: PathBuf,
    pub timeout: Duration,
    pub shutdown_timeout: Duration,
    pub enable_forwards: bool,
    pub enable_policy_fixtures: bool,
}

pub fn generate(seed: u64) -> Scenario {
    const METHODS: &[&str] = &[
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "PURGE",
    ];
    const BODY_SIZES: &[usize] = &[0, 1, 31, 1024, 16 * 1024];
    let mut random = StableRandom(seed);
    let count = 30 + random.range(16) as usize;
    let operations = (0..count)
        .map(|index| {
            let method = METHODS[(random.next() as usize) % METHODS.len()].to_owned();
            // Protocol and route deliberately use different periods. The old
            // generator accidentally tied both to id % 3 and missed half of
            // the protocol/route cross-product.
            let protocol = if index % 2 == 0 {
                Protocol::Http
            } else {
                Protocol::Connect
            };
            let size = BODY_SIZES[(random.next() as usize) % BODY_SIZES.len()];
            let body = patterned_body(seed, index, size);
            let outcome = if index > 0 && index % 17 == 0 {
                ExpectedOutcome::RouteFailure
            } else if index > 0 && index % 13 == 0 {
                ExpectedOutcome::Blocked
            } else {
                ExpectedOutcome::Success
            };
            Operation {
                id: index as u32,
                protocol,
                method,
                path: format!("/scenario/{seed}/{index}?value={}", random.range(10_000)),
                body,
                route: ExpectedRoute::Direct,
                outcome,
            }
        })
        .collect();
    Scenario {
        schema_version: SCHEMA_VERSION,
        seed,
        concurrency: 4,
        operations,
    }
}

fn patterned_body(seed: u64, index: usize, length: usize) -> String {
    let pattern = format!("{seed:x}-{index:x}|");
    pattern.chars().cycle().take(length).collect()
}

pub fn run(scenario: Scenario, options: &RunOptions) -> Result<SimulationReport> {
    let seed = scenario.seed;
    run_scenario(scenario, options).with_context(|| format!("simulation seed={seed} failed"))
}

fn run_scenario(mut scenario: Scenario, options: &RunOptions) -> Result<SimulationReport> {
    ensure!(
        (1..=SCHEMA_VERSION).contains(&scenario.schema_version),
        "unsupported scenario schema {}",
        scenario.schema_version
    );
    ensure!(
        scenario.concurrency > 0,
        "scenario concurrency must be non-zero"
    );
    let operation_ids = scenario
        .operations
        .iter()
        .map(|operation| operation.id)
        .collect::<BTreeSet<_>>();
    ensure!(
        operation_ids.len() == scenario.operations.len(),
        "scenario operation IDs must be unique"
    );
    for operation in &scenario.operations {
        ensure!(
            !operation.method.is_empty(),
            "operation {} has no method",
            operation.id
        );
        ensure!(
            operation.path.starts_with('/'),
            "operation {} path must start with /",
            operation.id
        );
    }
    scenario.schema_version = SCHEMA_VERSION;
    if (options.enable_forwards || options.enable_policy_fixtures)
        && scenario
            .operations
            .iter()
            .all(|operation| operation.route == ExpectedRoute::Direct)
    {
        materialize_forward_routes(&mut scenario);
    }

    let mut events = Vec::new();
    let mut metrics = String::new();
    let temp = tempfile::tempdir().context("creating simulation directory")?;
    let origins = Origins::start().context("starting simulation origins")?;
    let mut failures = FailureTargets::reserve()?;
    let forwarding = options.enable_forwards || options.enable_policy_fixtures;
    let socks = forwarding.then(SocksFixture::start).transpose()?;
    let http_forward = forwarding.then(HttpConnectFixture::start).transpose()?;
    let dns = options
        .enable_policy_fixtures
        .then(DnsFixture::start)
        .transpose()?;
    let domain_list = options
        .enable_policy_fixtures
        .then(DomainListFixture::start)
        .transpose()?;
    let [proxy_address, metrics_address] = reserve_addresses()?;
    let config = proxy_config(
        proxy_address,
        metrics_address,
        &origins,
        ConfigFixtures {
            socks: socks.as_ref(),
            http_forward: http_forward.as_ref(),
            dns: dns.as_ref(),
            domain_list: domain_list.as_ref(),
            failures: &failures,
        },
    );
    let config_path = temp.path().join("config.json");
    fs::write(&config_path, serde_json::to_vec_pretty(&config)?)?;
    events.push(Event {
        operation_id: None,
        component: "runner".into(),
        detail: format!("proxy={proxy_address} metrics={metrics_address}"),
    });

    let result = (|| -> Result<SimulationReport> {
        let mut proxy = ProxyProcess::start(&options.binary, &config_path)?;
        let work = (|| -> Result<SimulationReport> {
            wait_for_listener(proxy_address, options.timeout, &mut proxy)
                .context("waiting for proxy readiness")?;
            wait_for_listener(metrics_address, options.timeout, &mut proxy)
                .context("waiting for metrics readiness")?;
            failures.release();
            let baseline_metrics = scrape_when(metrics_address, options.timeout, |metrics| {
                metric_number_or_zero(metrics, "msgtausch_connections_active", &[])
                    .is_ok_and(|value| value == 0.0)
            })
            .context("waiting for proxy readiness connection to close")?;
            let deadline = Instant::now() + options.timeout;
            let mut completed = 0;
            let mut exchanges = Vec::with_capacity(scenario.operations.len());
            for chunk in scenario.operations.chunks(scenario.concurrency) {
                ensure!(Instant::now() < deadline, "scenario exceeded its deadline");
                let chunk_results = thread::scope(|scope| {
                    chunk
                        .iter()
                        .map(|operation| {
                            let target = origins.authority(
                                operation,
                                options.enable_policy_fixtures,
                                &failures,
                            );
                            scope.spawn(move || execute(proxy_address, &target, operation))
                        })
                        .collect::<Vec<_>>()
                        .into_iter()
                        .map(|handle| {
                            handle
                                .join()
                                .map_err(|_| anyhow::anyhow!("simulation client panicked"))?
                        })
                        .collect::<Result<Vec<_>>>()
                })?;
                for (operation, exchange) in chunk.iter().zip(chunk_results) {
                    validate_response(operation, &exchange.response).with_context(|| {
                        format!(
                            "operation {} through {} failed",
                            operation.id,
                            operation.route.metric_name()
                        )
                    })?;
                    exchanges.push(exchange);
                    completed += 1;
                    events.push(Event {
                        operation_id: Some(operation.id),
                        component: "client".into(),
                        detail: format!(
                            "{} {:?} via {} {:?} completed",
                            operation.method,
                            operation.protocol,
                            operation.route.metric_name(),
                            operation.outcome
                        ),
                    });
                }
            }
            metrics = scrape_when(metrics_address, options.timeout, |current| {
                metrics_have_settled(&baseline_metrics, current, &scenario)
            })
            .context("waiting for detached proxy metrics to settle")?;
            let comparisons =
                reconcile_metrics(&baseline_metrics, &metrics, &scenario, &origins, &exchanges)?;
            reconcile_forwards(&scenario, socks.as_ref(), http_forward.as_ref())?;
            if let Some(dns) = &dns {
                reconcile_dns(&scenario, dns, &baseline_metrics, &metrics)?;
            }
            if let Some(domain_list) = &domain_list {
                ensure!(
                    domain_list.requests() >= 1,
                    "domains-url fixture was never fetched"
                );
            }
            events.extend(origins.events());
            if let Some(fixture) = &socks {
                events.extend(fixture.events());
            }
            if let Some(fixture) = &http_forward {
                events.extend(fixture.events());
            }
            if let Some(fixture) = &dns {
                events.extend(fixture.events());
            }
            if let Some(fixture) = &domain_list {
                events.extend(fixture.events());
            }
            Ok(SimulationReport {
                seed: scenario.seed,
                operations: scenario.operations.len(),
                completed,
                metrics: metrics.clone(),
                comparisons,
                events: events.clone(),
            })
        })();
        match work {
            Ok(report) => {
                proxy.stop(options.shutdown_timeout)?;
                Ok(report)
            }
            Err(error) => {
                let shutdown = proxy.stop(options.shutdown_timeout).err();
                let stderr = proxy.stderr();
                let detail = shutdown
                    .map(|shutdown| format!("proxy shutdown also failed: {shutdown:#}\n"))
                    .unwrap_or_default();
                Err(error.context(format!("{detail}proxy stderr:\n{stderr}")))
            }
        }
    })();

    match result {
        Ok(report) => Ok(report),
        Err(error) => {
            if let Some(fixture) = &socks {
                events.extend(fixture.events());
            }
            if let Some(fixture) = &http_forward {
                events.extend(fixture.events());
            }
            if let Some(fixture) = &dns {
                events.extend(fixture.events());
            }
            if let Some(fixture) = &domain_list {
                events.extend(fixture.events());
            }
            events.extend(origins.events());
            let artifact = FailureArtifact {
                schema_version: SCHEMA_VERSION,
                seed: scenario.seed,
                scenario: scenario.clone(),
                redacted_config: redact_config(config),
                events,
                metrics,
                proxy_stderr: error_stderr(&error),
                error: format!("{error:#}"),
            };
            fs::create_dir_all(&options.artifact_dir)?;
            let path = options
                .artifact_dir
                .join(format!("failure-{}.json", scenario.seed));
            fs::write(&path, serde_json::to_vec_pretty(&artifact)?)?;
            Err(error)
        }
    }
}

pub fn replay(path: &Path, options: &RunOptions) -> Result<SimulationReport> {
    let artifact: FailureArtifact = serde_json::from_slice(
        &fs::read(path).with_context(|| format!("reading replay artifact {}", path.display()))?,
    )?;
    run(artifact.scenario, options)
}

fn error_stderr(error: &anyhow::Error) -> String {
    error
        .chain()
        .map(ToString::to_string)
        .find_map(|part| {
            part.find("proxy stderr:\n")
                .map(|index| part[index + "proxy stderr:\n".len()..].to_owned())
        })
        .unwrap_or_default()
}

fn materialize_forward_routes(scenario: &mut Scenario) {
    for operation in &mut scenario.operations {
        operation.route = ExpectedRoute::all()[operation.id as usize % ExpectedRoute::all().len()];
    }
}

struct ConfigFixtures<'a> {
    socks: Option<&'a SocksFixture>,
    http_forward: Option<&'a HttpConnectFixture>,
    dns: Option<&'a DnsFixture>,
    domain_list: Option<&'a DomainListFixture>,
    failures: &'a FailureTargets,
}

fn proxy_config(
    proxy: SocketAddr,
    metrics: SocketAddr,
    origins: &Origins,
    fixtures: ConfigFixtures<'_>,
) -> serde_json::Value {
    let ConfigFixtures {
        socks,
        http_forward,
        dns,
        domain_list,
        failures,
    } = fixtures;
    let mut forwards = Vec::new();
    if let Some(socks) = socks {
        let socks_classifier = if let Some(domain_list) = domain_list {
            serde_json::json!({"type": "and", "classifiers": [
                {"type": "or", "classifiers": [
                    {"type": "port", "port": origins.address(ExpectedRoute::Socks5).port()},
                    {"type": "port", "port": failures.address(ExpectedRoute::Socks5).port()}
                ]},
                {"type": "domains-url", "url": domain_list.url(), "format": "plain", "timeout": 2}
            ]})
        } else {
            serde_json::json!({"type": "or", "classifiers": [
                {"type": "port", "port": origins.address(ExpectedRoute::Socks5).port()},
                {"type": "port", "port": failures.address(ExpectedRoute::Socks5).port()}
            ]})
        };
        forwards.push(serde_json::json!({"type": "socks5", "address": socks.address.to_string(), "classifier": socks_classifier}));
    }
    if let Some(http_forward) = http_forward {
        forwards.push(serde_json::json!({"type": "http-proxy", "address": http_forward.address.to_string(), "classifier": {"type": "or", "classifiers": [
            {"type": "port", "port": origins.address(ExpectedRoute::HttpProxy).port()},
            {"type": "port", "port": failures.address(ExpectedRoute::HttpProxy).port()}
        ]}}));
    }
    forwards.push(serde_json::json!({"type": "default-network", "classifier": {"type": "true"}}));
    let mut config = serde_json::json!({"servers": [{"type": "standard", "listen-address": proxy.to_string(), "enabled": true}], "timeout-seconds": 5, "forwards": forwards, "blocklist": {"type": "domain", "op": "is", "domain": "blocked.msgtausch.test"}, "observability": {"prometheus-listen-address": metrics.to_string()}});
    if let Some(dns) = dns {
        config["dns"] = serde_json::json!({"enabled": true, "servers": [{"address": dns.address.to_string(), "type": "udp", "timeout-seconds": 2}]});
    }
    config
}

fn redact_config(mut config: serde_json::Value) -> serde_json::Value {
    fn redact(value: &mut serde_json::Value) {
        match value {
            serde_json::Value::Object(values) => {
                for (key, value) in values {
                    if matches!(key.as_str(), "password" | "ca-key-passwd") {
                        *value = serde_json::Value::String("<redacted>".into());
                    } else {
                        redact(value);
                    }
                }
            }
            serde_json::Value::Array(values) => values.iter_mut().for_each(redact),
            _ => {}
        }
    }
    redact(&mut config);
    config
}

fn reserve_addresses<const N: usize>() -> Result<[SocketAddr; N]> {
    let listeners = (0..N)
        .map(|_| TcpListener::bind("127.0.0.1:0"))
        .collect::<std::io::Result<Vec<_>>>()?;
    listeners
        .iter()
        .map(TcpListener::local_addr)
        .collect::<std::io::Result<Vec<_>>>()?
        .try_into()
        .map_err(|_| anyhow::anyhow!("reserved the wrong number of loopback addresses"))
}

fn wait_for_listener(
    address: SocketAddr,
    timeout: Duration,
    proxy: &mut ProxyProcess,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&address, Duration::from_millis(100)).is_ok() {
            return Ok(());
        }
        if let Some(status) = proxy.exit_status()? {
            bail!(
                "proxy exited before {address} became ready with {status}; proxy stderr:\n{}",
                proxy.stderr()
            );
        }
        thread::sleep(Duration::from_millis(10));
    }
    bail!(
        "listener {address} did not become ready within {timeout:?}; proxy stderr:\n{}",
        proxy.stderr()
    )
}

struct Exchange {
    response: Vec<u8>,
    tunnel_sent: u64,
    tunnel_received: u64,
}

fn execute(proxy: SocketAddr, origin: &str, operation: &Operation) -> Result<Exchange> {
    let mut stream = TcpStream::connect_timeout(&proxy, Duration::from_secs(2))?;
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    if operation.protocol == Protocol::Connect {
        write!(
            stream,
            "CONNECT {origin} HTTP/1.1\r\nHost: {origin}\r\nConnection: keep-alive\r\n\r\n"
        )?;
        let mut response = read_headers(&mut stream)?;
        if operation.outcome != ExpectedOutcome::Success {
            let length = response_content_length(&response)?;
            let mut body = vec![0; length];
            stream.read_exact(&mut body)?;
            response.extend(body);
            return Ok(Exchange {
                response,
                tunnel_sent: 0,
                tunnel_received: 0,
            });
        }
        ensure!(
            response_status(&response)? == 200,
            "CONNECT was not accepted"
        );
    }
    let target = if operation.protocol == Protocol::Http {
        format!("http://{origin}{}", operation.path)
    } else {
        operation.path.clone()
    };
    let request = format!(
        "{} {} HTTP/1.1\r\nHost: {}\r\nX-Sim-Id: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        operation.method,
        target,
        origin,
        operation.id,
        operation.body.len(),
        operation.body
    );
    stream.write_all(request.as_bytes())?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response)?;
    let tunneled =
        operation.protocol == Protocol::Connect && operation.outcome == ExpectedOutcome::Success;
    Ok(Exchange {
        tunnel_sent: if tunneled { request.len() as u64 } else { 0 },
        tunnel_received: if tunneled { response.len() as u64 } else { 0 },
        response,
    })
}

fn validate_response(operation: &Operation, response: &[u8]) -> Result<()> {
    let expected_status = match operation.outcome {
        ExpectedOutcome::Success => 200,
        ExpectedOutcome::Blocked => 403,
        ExpectedOutcome::RouteFailure => 502,
    };
    let status = response_status(response)?;
    ensure!(
        status == expected_status,
        "response status was {status}, expected {expected_status}: {}",
        String::from_utf8_lossy(response)
    );
    if operation.outcome == ExpectedOutcome::Success && operation.method != "HEAD" {
        let expected = format!(
            "{}|{}|{}|{}",
            operation.id, operation.method, operation.path, operation.body
        );
        ensure!(
            String::from_utf8_lossy(response).contains(&expected),
            "response integrity mismatch"
        );
    }
    if operation.outcome == ExpectedOutcome::Blocked
        && !(operation.protocol == Protocol::Http && operation.method == "HEAD")
    {
        ensure!(
            String::from_utf8_lossy(response).contains("Host not allowed"),
            "blocked response did not identify the policy decision"
        );
    }
    Ok(())
}

fn response_status(response: &[u8]) -> Result<u16> {
    String::from_utf8_lossy(response)
        .lines()
        .next()
        .and_then(|line| line.split_whitespace().nth(1))
        .context("response has no HTTP status")?
        .parse()
        .context("response has an invalid HTTP status")
}

fn response_content_length(response: &[u8]) -> Result<usize> {
    String::from_utf8_lossy(response)
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())
                .flatten()
        })
        .context("response has no valid Content-Length")
}

fn reconcile_metrics(
    baseline: &str,
    metrics: &str,
    scenario: &Scenario,
    origins: &Origins,
    exchanges: &[Exchange],
) -> Result<Vec<MetricComparison>> {
    let mut comparisons = Vec::new();
    compare_delta(
        &mut comparisons,
        baseline,
        metrics,
        "msgtausch_connections_total",
        &[],
        scenario.operations.len() as f64,
    )?;
    compare_absolute(
        &mut comparisons,
        metrics,
        "msgtausch_connections_active",
        &[],
        0.0,
    )?;

    let blocked = scenario
        .operations
        .iter()
        .filter(|operation| operation.outcome == ExpectedOutcome::Blocked)
        .count();
    compare_delta(
        &mut comparisons,
        baseline,
        metrics,
        "msgtausch_access_decisions_total",
        &[("decision", "allow")],
        (scenario.operations.len() - blocked) as f64,
    )?;
    compare_delta(
        &mut comparisons,
        baseline,
        metrics,
        "msgtausch_access_decisions_total",
        &[("decision", "block")],
        blocked as f64,
    )?;
    compare_family_total(
        &mut comparisons,
        baseline,
        metrics,
        "msgtausch_access_decisions_total",
        scenario.operations.len() as f64,
    )?;

    let mut requests = BTreeMap::<(&str, &str), usize>::new();
    for operation in &scenario.operations {
        let method = if operation.protocol == Protocol::Connect {
            "CONNECT"
        } else {
            bounded_method(&operation.method)
        };
        let status = match operation.outcome {
            ExpectedOutcome::Success => "2xx",
            ExpectedOutcome::Blocked => "4xx",
            ExpectedOutcome::RouteFailure => "5xx",
        };
        *requests.entry((method, status)).or_default() += 1;
    }
    for ((method, status), expected) in requests {
        compare_delta(
            &mut comparisons,
            baseline,
            metrics,
            "msgtausch_http_requests_total",
            &[("method", method), ("status_class", status)],
            expected as f64,
        )?;
    }
    compare_family_total(
        &mut comparisons,
        baseline,
        metrics,
        "msgtausch_http_requests_total",
        scenario.operations.len() as f64,
    )?;
    compare_delta(
        &mut comparisons,
        baseline,
        metrics,
        "msgtausch_http_request_duration_seconds_count",
        &[],
        scenario.operations.len() as f64,
    )?;
    validate_histogram_delta(
        baseline,
        metrics,
        "msgtausch_http_request_duration_seconds",
        scenario.operations.len() as f64,
    )?;

    for route in ExpectedRoute::all() {
        let expected = scenario
            .operations
            .iter()
            .filter(|operation| {
                operation.route == route && operation.outcome != ExpectedOutcome::Blocked
            })
            .count() as u64;
        compare_delta(
            &mut comparisons,
            baseline,
            metrics,
            "msgtausch_routes_total",
            &[("route", route.metric_name())],
            expected as f64,
        )?;
        let expected_errors = scenario
            .operations
            .iter()
            .filter(|operation| {
                operation.route == route && operation.outcome == ExpectedOutcome::RouteFailure
            })
            .count() as f64;
        compare_delta(
            &mut comparisons,
            baseline,
            metrics,
            "msgtausch_route_errors_total",
            &[("route", route.metric_name())],
            expected_errors,
        )?;
        let expected_origin = scenario
            .operations
            .iter()
            .filter(|operation| {
                operation.route == route && operation.outcome == ExpectedOutcome::Success
            })
            .count() as u64;
        ensure!(
            origins.requests(route) == expected_origin,
            "{} origin observed {}, expected {expected_origin}",
            route.metric_name(),
            origins.requests(route)
        );
    }
    let expected_routed = (scenario.operations.len() - blocked) as f64;
    let expected_route_errors = scenario
        .operations
        .iter()
        .filter(|operation| operation.outcome == ExpectedOutcome::RouteFailure)
        .count() as f64;
    compare_family_total(
        &mut comparisons,
        baseline,
        metrics,
        "msgtausch_routes_total",
        expected_routed,
    )?;
    compare_family_total(
        &mut comparisons,
        baseline,
        metrics,
        "msgtausch_route_errors_total",
        expected_route_errors,
    )?;

    let expected_blocked = blocked as f64;
    let expected_connect_errors = scenario
        .operations
        .iter()
        .filter(|operation| {
            operation.outcome == ExpectedOutcome::RouteFailure
                && operation.protocol == Protocol::Connect
        })
        .count() as f64;
    let expected_http_errors = scenario
        .operations
        .iter()
        .filter(|operation| {
            operation.outcome == ExpectedOutcome::RouteFailure
                && operation.protocol == Protocol::Http
        })
        .count() as f64;
    for (kind, expected) in [
        ("blocked", expected_blocked),
        ("connect", expected_connect_errors),
        ("http_forward", expected_http_errors),
    ] {
        compare_delta(
            &mut comparisons,
            baseline,
            metrics,
            "msgtausch_errors_total",
            &[("kind", kind)],
            expected,
        )?;
    }
    compare_family_total(
        &mut comparisons,
        baseline,
        metrics,
        "msgtausch_errors_total",
        expected_blocked + expected_connect_errors + expected_http_errors,
    )?;

    let tunnel_sent: u64 = exchanges.iter().map(|exchange| exchange.tunnel_sent).sum();
    let tunnel_received: u64 = exchanges
        .iter()
        .map(|exchange| exchange.tunnel_received)
        .sum();
    let tunnels = scenario
        .operations
        .iter()
        .filter(|operation| {
            operation.protocol == Protocol::Connect && operation.outcome == ExpectedOutcome::Success
        })
        .count() as f64;
    compare_delta(
        &mut comparisons,
        baseline,
        metrics,
        "msgtausch_tunnel_bytes_sent_total",
        &[],
        tunnel_sent as f64,
    )?;
    compare_delta(
        &mut comparisons,
        baseline,
        metrics,
        "msgtausch_tunnel_bytes_received_total",
        &[],
        tunnel_received as f64,
    )?;
    compare_delta(
        &mut comparisons,
        baseline,
        metrics,
        "msgtausch_tunnel_duration_seconds_count",
        &[],
        tunnels,
    )?;
    validate_histogram_delta(
        baseline,
        metrics,
        "msgtausch_tunnel_duration_seconds",
        tunnels,
    )?;
    Ok(comparisons)
}

fn reconcile_forwards(
    scenario: &Scenario,
    socks: Option<&SocksFixture>,
    http_forward: Option<&HttpConnectFixture>,
) -> Result<()> {
    let expected_socks = scenario
        .operations
        .iter()
        .filter(|operation| {
            operation.route == ExpectedRoute::Socks5
                && operation.outcome == ExpectedOutcome::Success
        })
        .count() as u64;
    let expected_http = scenario
        .operations
        .iter()
        .filter(|operation| {
            operation.route == ExpectedRoute::HttpProxy
                && operation.outcome == ExpectedOutcome::Success
        })
        .count() as u64;
    if expected_socks > 0 {
        let fixture = socks.context("SOCKS route was selected without a SOCKS fixture")?;
        ensure!(
            fixture.requests() == expected_socks,
            "SOCKS fixture observed {}, expected {expected_socks}",
            fixture.requests()
        );
    }
    if expected_http > 0 {
        let fixture =
            http_forward.context("HTTP forward route was selected without an HTTP fixture")?;
        ensure!(
            fixture.requests() == expected_http,
            "HTTP forward fixture observed {}, expected {expected_http}",
            fixture.requests()
        );
    }
    Ok(())
}

fn reconcile_dns(
    scenario: &Scenario,
    dns: &DnsFixture,
    baseline_metrics: &str,
    metrics: &str,
) -> Result<()> {
    let cache_queries = metric_delta(
        baseline_metrics,
        metrics,
        "msgtausch_dns_cache_queries_total",
        &[],
    )?;
    reconcile_dns_queries(scenario, &dns.questions(), dns.queries(), cache_queries)
}

fn reconcile_dns_queries(
    scenario: &Scenario,
    questions: &[(String, u16)],
    wire_queries: u64,
    cache_queries: f64,
) -> Result<()> {
    let expected_lookups = scenario
        .operations
        .iter()
        .filter(|operation| {
            operation.route == ExpectedRoute::Direct
                && operation.outcome != ExpectedOutcome::Blocked
        })
        .count() as u64;
    let observed_names = questions
        .iter()
        .map(|(name, _)| name.as_str())
        .collect::<BTreeSet<_>>();
    ensure!(
        observed_names == BTreeSet::from(["policy.msgtausch.test"]),
        "DNS fixture observed unexpected names {observed_names:?}"
    );
    let a_queries = questions
        .iter()
        .filter(|(_, query_type)| *query_type == 1)
        .count() as u64;
    let aaaa_queries = questions
        .iter()
        .filter(|(_, query_type)| *query_type == 28)
        .count() as u64;
    ensure!(
        a_queries == aaaa_queries,
        "DNS fixture observed {a_queries} A queries and {aaaa_queries} AAAA queries"
    );
    ensure!(
        cache_queries >= 0.0 && cache_queries.fract() == 0.0,
        "DNS cache query metric changed by {cache_queries}, expected a non-negative integer"
    );
    let logical_queries = wire_queries + 2 * cache_queries as u64;
    ensure!(
        logical_queries == expected_lookups * 2,
        "DNS fixture observed {wire_queries} wire queries and the cache recorded {cache_queries} queries, totaling {logical_queries}, expected {}",
        expected_lookups * 2
    );
    Ok(())
}

fn read_headers(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut response = Vec::with_capacity(256);
    let mut byte = [0_u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        ensure!(response.len() < 32 * 1024, "response headers too large");
        stream.read_exact(&mut byte)?;
        response.push(byte[0]);
    }
    Ok(response)
}

fn scrape(address: SocketAddr) -> Result<String> {
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

fn scrape_when(
    address: SocketAddr,
    timeout: Duration,
    predicate: impl Fn(&str) -> bool,
) -> Result<String> {
    let deadline = Instant::now() + timeout;
    let mut last = String::new();
    while Instant::now() < deadline {
        last = scrape(address)?;
        if predicate(&last) {
            return Ok(last);
        }
        thread::sleep(Duration::from_millis(10));
    }
    bail!("metrics did not settle within {timeout:?}; last scrape:\n{last}")
}

fn metric_number(metrics: &str, name: &str, labels: &[(&str, &str)]) -> Result<f64> {
    metrics
        .lines()
        .find_map(|line| {
            let (metric, value) = line.rsplit_once(' ')?;
            (metric_name(metric) == name
                && labels
                    .iter()
                    .all(|(key, value)| metric.contains(&format!("{key}=\"{value}\""))))
            .then(|| value.parse().ok())
            .flatten()
        })
        .with_context(|| format!("metric {name} with labels {labels:?} is missing"))
}
fn metric_number_or_zero(metrics: &str, name: &str, labels: &[(&str, &str)]) -> Result<f64> {
    match metric_number(metrics, name, labels) {
        Ok(value) => Ok(value),
        Err(error) if error.to_string().contains("is missing") => Ok(0.0),
        Err(error) => Err(error),
    }
}
fn metric_name(metric: &str) -> &str {
    metric.split_once('{').map_or(metric, |(name, _)| name)
}

fn metric_delta(baseline: &str, current: &str, name: &str, labels: &[(&str, &str)]) -> Result<f64> {
    Ok(metric_number_or_zero(current, name, labels)?
        - metric_number_or_zero(baseline, name, labels)?)
}

fn compare_delta(
    comparisons: &mut Vec<MetricComparison>,
    baseline: &str,
    current: &str,
    name: &str,
    labels: &[(&str, &str)],
    expected: f64,
) -> Result<()> {
    let actual = metric_delta(baseline, current, name, labels)?;
    ensure!(
        actual == expected,
        "metric {name} with labels {labels:?} changed by {actual}, expected {expected}"
    );
    comparisons.push(MetricComparison {
        metric: name.into(),
        labels: format_labels(labels),
        expected,
        actual,
    });
    Ok(())
}

fn compare_absolute(
    comparisons: &mut Vec<MetricComparison>,
    current: &str,
    name: &str,
    labels: &[(&str, &str)],
    expected: f64,
) -> Result<()> {
    let actual = metric_number_or_zero(current, name, labels)?;
    ensure!(
        actual == expected,
        "metric {name} with labels {labels:?} is {actual}, expected {expected}"
    );
    comparisons.push(MetricComparison {
        metric: name.into(),
        labels: format_labels(labels),
        expected,
        actual,
    });
    Ok(())
}

fn compare_family_total(
    comparisons: &mut Vec<MetricComparison>,
    baseline: &str,
    current: &str,
    name: &str,
    expected: f64,
) -> Result<()> {
    let actual = metric_family_total(current, name)? - metric_family_total(baseline, name)?;
    ensure!(
        actual == expected,
        "metric family {name} changed by {actual}, expected {expected}"
    );
    comparisons.push(MetricComparison {
        metric: name.into(),
        labels: "*".into(),
        expected,
        actual,
    });
    Ok(())
}

fn metric_family_total(metrics: &str, name: &str) -> Result<f64> {
    metrics.lines().try_fold(0.0, |total, line| {
        let Some((sample, value)) = line.rsplit_once(' ') else {
            return Ok(total);
        };
        if metric_name(sample) == name {
            Ok(total
                + value
                    .parse::<f64>()
                    .with_context(|| format!("metric {name} has invalid sample value {value}"))?)
        } else {
            Ok(total)
        }
    })
}

fn format_labels(labels: &[(&str, &str)]) -> String {
    labels
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>()
        .join(",")
}

fn metrics_have_settled(baseline: &str, current: &str, scenario: &Scenario) -> bool {
    let expected_tunnels = scenario
        .operations
        .iter()
        .filter(|operation| {
            operation.protocol == Protocol::Connect && operation.outcome == ExpectedOutcome::Success
        })
        .count() as f64;
    metric_delta(
        baseline,
        current,
        "msgtausch_http_request_duration_seconds_count",
        &[],
    )
    .is_ok_and(|count| count == scenario.operations.len() as f64)
        && metric_delta(
            baseline,
            current,
            "msgtausch_tunnel_duration_seconds_count",
            &[],
        )
        .is_ok_and(|count| count == expected_tunnels)
        && metric_number_or_zero(current, "msgtausch_connections_active", &[])
            .is_ok_and(|active| active == 0.0)
}

fn validate_histogram_delta(
    baseline: &str,
    current: &str,
    name: &str,
    expected_count: f64,
) -> Result<()> {
    let count = metric_delta(baseline, current, &format!("{name}_count"), &[])?;
    ensure!(
        count == expected_count,
        "histogram {name} count is {count}, expected {expected_count}"
    );
    let sum = metric_delta(baseline, current, &format!("{name}_sum"), &[])?;
    ensure!(
        sum.is_finite() && sum >= 0.0,
        "histogram {name} has invalid sum {sum}"
    );
    let mut buckets = current
        .lines()
        .filter_map(|line| {
            let (sample, value) = line.rsplit_once(' ')?;
            if metric_name(sample) == format!("{name}_bucket") {
                Some((sample, value.parse::<f64>().ok()?))
            } else {
                None
            }
        })
        .collect::<Vec<_>>();
    ensure!(!buckets.is_empty(), "histogram {name} has no buckets");
    let mut previous = 0.0;
    let mut infinity = None;
    for (sample, current_value) in buckets.drain(..) {
        let baseline_value = baseline
            .lines()
            .find_map(|line| {
                let (base_sample, value) = line.rsplit_once(' ')?;
                (base_sample == sample)
                    .then(|| value.parse::<f64>().ok())
                    .flatten()
            })
            .unwrap_or(0.0);
        let value = current_value - baseline_value;
        ensure!(
            value >= previous,
            "histogram {name} buckets are not monotonic"
        );
        ensure!(
            value <= expected_count,
            "histogram {name} bucket exceeds its count"
        );
        previous = value;
        if sample.contains("le=\"+Inf\"") {
            infinity = Some(value);
        }
    }
    ensure!(
        infinity == Some(expected_count),
        "histogram {name} +Inf bucket does not match count"
    );
    Ok(())
}

fn bounded_method(method: &str) -> &str {
    match method {
        "GET" | "HEAD" | "POST" | "PUT" | "DELETE" | "CONNECT" | "OPTIONS" | "TRACE" | "PATCH" => {
            method
        }
        _ => "OTHER",
    }
}

struct ProxyProcess {
    child: Child,
    stderr: Arc<Mutex<String>>,
    stderr_thread: Option<thread::JoinHandle<()>>,
}
impl ProxyProcess {
    fn start(binary: &Path, config: &Path) -> Result<Self> {
        ensure!(
            binary.is_file(),
            "proxy binary {} does not exist",
            binary.display()
        );
        let mut child = Command::new(binary)
            .arg("--config")
            .arg(config)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("starting {}", binary.display()))?;
        let stderr = Arc::new(Mutex::new(String::new()));
        let collected = stderr.clone();
        let child_stderr = child.stderr.take().context("capturing proxy stderr")?;
        let stderr_thread = thread::spawn(move || {
            let mut reader = std::io::BufReader::new(child_stderr);
            let mut output = String::new();
            let _ = reader.read_to_string(&mut output);
            if let Ok(mut stored) = collected.lock() {
                *stored = output;
            }
        });
        Ok(Self {
            child,
            stderr,
            stderr_thread: Some(stderr_thread),
        })
    }
    fn exit_status(&mut self) -> Result<Option<ExitStatus>> {
        Ok(self.child.try_wait()?)
    }
    fn stderr(&self) -> String {
        self.stderr
            .lock()
            .map_or_else(|_| "<stderr lock poisoned>".into(), |value| value.clone())
    }
    fn stop(&mut self, timeout: Duration) -> Result<()> {
        if self.child.try_wait()?.is_none() {
            #[cfg(unix)]
            unsafe {
                if libc::kill(self.child.id() as libc::pid_t, libc::SIGTERM) != 0 {
                    return Err(std::io::Error::last_os_error())
                        .context("sending SIGTERM to proxy");
                }
            }
            #[cfg(not(unix))]
            self.child.kill().context("stopping proxy")?;
        }
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(status) = self.child.try_wait()? {
                self.join_stderr();
                ensure!(
                    status.success(),
                    "proxy did not exit cleanly after SIGTERM: {status}; proxy stderr:\n{}",
                    self.stderr()
                );
                return Ok(());
            }
            if Instant::now() >= deadline {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        let _ = self.child.kill();
        let status = self.child.wait()?;
        self.join_stderr();
        bail!(
            "proxy ignored SIGTERM for {timeout:?}; killed it with {status}; proxy stderr:\n{}",
            self.stderr()
        )
    }
    fn join_stderr(&mut self) {
        if let Some(thread) = self.stderr_thread.take() {
            let _ = thread.join();
        }
    }
}
impl Drop for ProxyProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        self.join_stderr();
    }
}

struct Origins {
    direct: Origin,
    socks: Origin,
    http_proxy: Origin,
}
impl Origins {
    fn start() -> Result<Self> {
        Ok(Self {
            direct: Origin::start()?,
            socks: Origin::start()?,
            http_proxy: Origin::start()?,
        })
    }
    fn address(&self, route: ExpectedRoute) -> SocketAddr {
        match route {
            ExpectedRoute::Direct => self.direct.address,
            ExpectedRoute::Socks5 => self.socks.address,
            ExpectedRoute::HttpProxy => self.http_proxy.address,
        }
    }
    fn authority(&self, operation: &Operation, use_dns: bool, failures: &FailureTargets) -> String {
        let address = match operation.outcome {
            ExpectedOutcome::RouteFailure => failures.address(operation.route),
            ExpectedOutcome::Success | ExpectedOutcome::Blocked => self.address(operation.route),
        };
        let host = match operation.outcome {
            ExpectedOutcome::Blocked => "blocked.msgtausch.test",
            ExpectedOutcome::Success | ExpectedOutcome::RouteFailure if use_dns => {
                "policy.msgtausch.test"
            }
            ExpectedOutcome::Success | ExpectedOutcome::RouteFailure => return address.to_string(),
        };
        format!("{host}:{}", address.port())
    }
    fn requests(&self, route: ExpectedRoute) -> u64 {
        match route {
            ExpectedRoute::Direct => self.direct.requests(),
            ExpectedRoute::Socks5 => self.socks.requests(),
            ExpectedRoute::HttpProxy => self.http_proxy.requests(),
        }
    }
    fn events(&self) -> Vec<Event> {
        [
            ("direct", &self.direct),
            ("socks5", &self.socks),
            ("http_proxy", &self.http_proxy),
        ]
        .into_iter()
        .map(|(route, origin)| Event {
            operation_id: None,
            component: "origin".into(),
            detail: format!("{route} origin handled {} requests", origin.requests()),
        })
        .collect()
    }
}

struct FailureTargets {
    direct: SocketAddr,
    socks: SocketAddr,
    http_proxy: SocketAddr,
    reservations: Option<[TcpListener; 3]>,
}

impl FailureTargets {
    fn reserve() -> Result<Self> {
        let reservations = [
            TcpListener::bind("127.0.0.1:0")?,
            TcpListener::bind("127.0.0.1:0")?,
            TcpListener::bind("127.0.0.1:0")?,
        ];
        let [direct, socks, http_proxy] = reservations
            .each_ref()
            .map(TcpListener::local_addr)
            .into_iter()
            .collect::<std::io::Result<Vec<_>>>()?
            .try_into()
            .map_err(|_| anyhow::anyhow!("reserved the wrong number of failure addresses"))?;
        Ok(Self {
            direct,
            socks,
            http_proxy,
            reservations: Some(reservations),
        })
    }

    fn release(&mut self) {
        self.reservations = None;
    }

    fn address(&self, route: ExpectedRoute) -> SocketAddr {
        match route {
            ExpectedRoute::Direct => self.direct,
            ExpectedRoute::Socks5 => self.socks,
            ExpectedRoute::HttpProxy => self.http_proxy,
        }
    }
}
struct Origin {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicU64>,
    thread: Option<thread::JoinHandle<()>>,
}
impl Origin {
    fn start() -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicU64::new(0));
        let thread_stop = stop.clone();
        let thread_requests = requests.clone();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let requests = thread_requests.clone();
                        thread::spawn(move || {
                            let _ = serve_origin(stream, &requests);
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
impl Drop for Origin {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_origin(mut stream: TcpStream, requests: &AtomicU64) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    let headers = String::from_utf8(read_headers(&mut stream)?)?;
    let mut lines = headers.lines();
    let request_line = lines.next().context("missing request line")?;
    let mut request_parts = request_line.split_whitespace();
    let method = request_parts.next().context("missing method")?;
    let path = request_parts.next().context("missing path")?;
    let mut id = None;
    let mut length = 0;
    for line in lines {
        if let Some(value) = line.strip_prefix("X-Sim-Id: ") {
            id = Some(value.to_owned());
        }
        if let Some(value) = line.strip_prefix("Content-Length: ") {
            length = value.parse()?;
        }
    }
    let mut body = vec![0; length];
    stream.read_exact(&mut body)?;
    let id = id.context("missing simulation request ID")?;
    let response_body = format!("{id}|{method}|{path}|{}", String::from_utf8_lossy(&body));
    requests.fetch_add(1, Ordering::Relaxed);
    if method == "HEAD" {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            response_body.len()
        )?;
    } else {
        write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            response_body.len(),
            response_body
        )?;
    }
    Ok(())
}

struct SocksFixture {
    address: SocketAddr,
    server: FixtureServer,
}
impl SocksFixture {
    fn start() -> Result<Self> {
        let server = FixtureServer::start("socks5", serve_socks)?;
        Ok(Self {
            address: server.address,
            server,
        })
    }
    fn requests(&self) -> u64 {
        self.server.requests()
    }
    fn events(&self) -> Vec<Event> {
        self.server.events()
    }
}
struct HttpConnectFixture {
    address: SocketAddr,
    server: FixtureServer,
}
impl HttpConnectFixture {
    fn start() -> Result<Self> {
        let server = FixtureServer::start("http_proxy", serve_http_connect)?;
        Ok(Self {
            address: server.address,
            server,
        })
    }
    fn requests(&self) -> u64 {
        self.server.requests()
    }
    fn events(&self) -> Vec<Event> {
        self.server.events()
    }
}
struct DomainListFixture {
    address: SocketAddr,
    server: FixtureServer,
}
impl DomainListFixture {
    fn start() -> Result<Self> {
        let server = FixtureServer::start("domains_url", serve_domain_list)?;
        Ok(Self {
            address: server.address,
            server,
        })
    }
    fn url(&self) -> String {
        format!("http://{}/domains.txt", self.address)
    }
    fn requests(&self) -> u64 {
        self.server.requests()
    }
    fn events(&self) -> Vec<Event> {
        self.server.events()
    }
}

struct DnsFixture {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    queries: Arc<AtomicU64>,
    questions: Arc<Mutex<Vec<(String, u16)>>>,
    events: Arc<Mutex<Vec<Event>>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl DnsFixture {
    fn start() -> Result<Self> {
        let socket = UdpSocket::bind("127.0.0.1:0")?;
        socket.set_nonblocking(true)?;
        let address = socket.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let queries = Arc::new(AtomicU64::new(0));
        let events = Arc::new(Mutex::new(Vec::new()));
        let questions = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = stop.clone();
        let thread_queries = queries.clone();
        let thread_events = events.clone();
        let thread_questions = questions.clone();
        let thread = thread::spawn(move || {
            let mut buffer = [0; 1500];
            while !thread_stop.load(Ordering::Relaxed) {
                match socket.recv_from(&mut buffer) {
                    Ok((length, peer)) => match dns_reply(&buffer[..length]) {
                        Ok((reply, name, query_type)) => {
                            thread_queries.fetch_add(1, Ordering::Relaxed);
                            if let Ok(mut questions) = thread_questions.lock() {
                                questions.push((name, query_type));
                            }
                            let _ = socket.send_to(&reply, peer);
                        }
                        Err(error) => {
                            if let Ok(mut events) = thread_events.lock() {
                                events.push(Event {
                                    operation_id: None,
                                    component: "dns".into(),
                                    detail: format!("invalid query: {error:#}"),
                                });
                            }
                        }
                    },
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
            queries,
            questions,
            events,
            thread: Some(thread),
        })
    }
    fn queries(&self) -> u64 {
        self.queries.load(Ordering::Relaxed)
    }
    fn questions(&self) -> Vec<(String, u16)> {
        self.questions
            .lock()
            .map_or_else(|_| Vec::new(), |questions| questions.clone())
    }
    fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .map_or_else(|_| Vec::new(), |events| events.clone())
    }
}
impl Drop for DnsFixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn dns_reply(query: &[u8]) -> Result<(Vec<u8>, String, u16)> {
    ensure!(query.len() >= 17, "DNS query is too short");
    ensure!(
        u16::from_be_bytes([query[4], query[5]]) == 1,
        "DNS query has no question"
    );
    let mut cursor = 12;
    let mut labels = Vec::new();
    while *query.get(cursor).context("truncated DNS query name")? != 0 {
        let length = query[cursor] as usize;
        ensure!(length <= 63, "invalid DNS label length");
        let label = query
            .get(cursor + 1..cursor + 1 + length)
            .context("truncated DNS label")?;
        labels.push(std::str::from_utf8(label)?.to_owned());
        cursor += length + 1;
    }
    let question_end = cursor + 5;
    ensure!(question_end <= query.len(), "truncated DNS question");
    let query_type = u16::from_be_bytes([query[cursor + 1], query[cursor + 2]]);
    let answer_count = u16::from(query_type == 1);
    let mut reply = Vec::with_capacity(question_end + 16);
    reply.extend_from_slice(&query[..2]);
    reply.extend_from_slice(&0x8180_u16.to_be_bytes());
    reply.extend_from_slice(&1_u16.to_be_bytes());
    reply.extend_from_slice(&answer_count.to_be_bytes());
    reply.extend_from_slice(&0_u16.to_be_bytes());
    reply.extend_from_slice(&0_u16.to_be_bytes());
    reply.extend_from_slice(&query[12..question_end]);
    if answer_count == 1 {
        reply.extend_from_slice(&0xc00c_u16.to_be_bytes());
        reply.extend_from_slice(&1_u16.to_be_bytes());
        reply.extend_from_slice(&1_u16.to_be_bytes());
        reply.extend_from_slice(&1_u32.to_be_bytes());
        reply.extend_from_slice(&4_u16.to_be_bytes());
        reply.extend_from_slice(&[127, 0, 0, 1]);
    }
    Ok((reply, labels.join("."), query_type))
}

fn serve_domain_list(
    mut stream: TcpStream,
    requests: &AtomicU64,
    events: &Mutex<Vec<Event>>,
) -> Result<()> {
    let request = String::from_utf8(read_headers(&mut stream)?)?;
    ensure!(
        request.starts_with("GET /domains.txt "),
        "unexpected domains-url request"
    );
    const BODY: &str = "# simulation policy list\nmsgtausch.test\n";
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{BODY}",
        BODY.len()
    )?;
    requests.fetch_add(1, Ordering::Relaxed);
    record_fixture(events, "domains_url", "served policy list".into());
    Ok(())
}

struct FixtureServer {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    requests: Arc<AtomicU64>,
    events: Arc<Mutex<Vec<Event>>>,
    thread: Option<thread::JoinHandle<()>>,
}
impl FixtureServer {
    fn start(
        kind: &'static str,
        handler: fn(TcpStream, &AtomicU64, &Mutex<Vec<Event>>) -> Result<()>,
    ) -> Result<Self> {
        let listener = TcpListener::bind("127.0.0.1:0")?;
        listener.set_nonblocking(true)?;
        let address = listener.local_addr()?;
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(AtomicU64::new(0));
        let events = Arc::new(Mutex::new(Vec::new()));
        let thread_stop = stop.clone();
        let thread_requests = requests.clone();
        let thread_events = events.clone();
        let thread = thread::spawn(move || {
            while !thread_stop.load(Ordering::Relaxed) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let requests = thread_requests.clone();
                        let events = thread_events.clone();
                        thread::spawn(move || {
                            if let Err(error) = handler(stream, &requests, &events)
                                && let Ok(mut events) = events.lock()
                            {
                                events.push(Event {
                                    operation_id: None,
                                    component: kind.into(),
                                    detail: format!("fixture error: {error:#}"),
                                });
                            }
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
            events,
            thread: Some(thread),
        })
    }
    fn requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }
    fn events(&self) -> Vec<Event> {
        self.events
            .lock()
            .map_or_else(|_| Vec::new(), |events| events.clone())
    }
}
impl Drop for FixtureServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn serve_socks(
    mut client: TcpStream,
    requests: &AtomicU64,
    events: &Mutex<Vec<Event>>,
) -> Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    let greeting = read_exact(&mut client, 2)?;
    ensure!(greeting[0] == 5, "SOCKS version is not 5");
    let methods = read_exact(&mut client, greeting[1] as usize)?;
    ensure!(methods.contains(&0), "client did not offer no-auth SOCKS");
    client.write_all(&[5, 0])?;
    let request = read_exact(&mut client, 4)?;
    ensure!(request[..3] == [5, 1, 0], "invalid SOCKS CONNECT request");
    let host = match request[3] {
        1 => std::net::Ipv4Addr::from(<[u8; 4]>::try_from(read_exact(&mut client, 4)?).unwrap())
            .to_string(),
        4 => std::net::Ipv6Addr::from(<[u8; 16]>::try_from(read_exact(&mut client, 16)?).unwrap())
            .to_string(),
        3 => {
            let length = read_exact(&mut client, 1)?[0] as usize;
            String::from_utf8(read_exact(&mut client, length)?)?
        }
        atyp => bail!("unsupported SOCKS address type {atyp}"),
    };
    let port = u16::from_be_bytes(<[u8; 2]>::try_from(read_exact(&mut client, 2)?).unwrap());
    let authority = format!("{host}:{port}");
    let upstream = TcpStream::connect(fixture_connect_address(&authority))
        .with_context(|| format!("SOCKS connecting {authority}"))?;
    client.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])?;
    requests.fetch_add(1, Ordering::Relaxed);
    record_fixture(events, "socks5", authority);
    relay(client, upstream)
}
fn serve_http_connect(
    mut client: TcpStream,
    requests: &AtomicU64,
    events: &Mutex<Vec<Event>>,
) -> Result<()> {
    client.set_read_timeout(Some(Duration::from_secs(5)))?;
    let headers = String::from_utf8(read_headers(&mut client)?)?;
    let authority = headers
        .lines()
        .next()
        .context("missing HTTP CONNECT request")?
        .split_whitespace()
        .nth(1)
        .context("missing HTTP CONNECT authority")?
        .to_owned();
    let upstream = TcpStream::connect(fixture_connect_address(&authority))
        .with_context(|| format!("HTTP forward connecting {authority}"))?;
    client.write_all(
        b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: msgtausch-simulation\r\n\r\n",
    )?;
    requests.fetch_add(1, Ordering::Relaxed);
    record_fixture(events, "http_proxy", authority);
    relay(client, upstream)
}
fn record_fixture(events: &Mutex<Vec<Event>>, component: &str, authority: String) {
    if let Ok(mut events) = events.lock() {
        events.push(Event {
            operation_id: None,
            component: component.into(),
            detail: format!("connected {authority}"),
        });
    }
}
fn fixture_connect_address(authority: &str) -> String {
    let Some((host, port)) = authority.rsplit_once(':') else {
        return authority.to_owned();
    };
    if host.trim_matches(['[', ']']).ends_with(".msgtausch.test") {
        format!("127.0.0.1:{port}")
    } else {
        authority.to_owned()
    }
}
fn relay(mut left: TcpStream, mut right: TcpStream) -> Result<()> {
    let mut left_reader = left.try_clone()?;
    let mut right_writer = right.try_clone()?;
    let one = thread::spawn(move || {
        let _ = std::io::copy(&mut left_reader, &mut right_writer);
        let _ = right_writer.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut right, &mut left);
    let _ = left.shutdown(Shutdown::Write);
    let _ = one.join();
    Ok(())
}
fn read_exact(stream: &mut TcpStream, len: usize) -> Result<Vec<u8>> {
    let mut bytes = vec![0; len];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}

struct StableRandom(u64);
impl StableRandom {
    fn next(&mut self) -> u64 {
        let mut value = self.0;
        value ^= value << 13;
        value ^= value >> 7;
        value ^= value << 17;
        self.0 = value;
        value
    }
    fn range(&mut self, upper: u64) -> u64 {
        self.next() % upper
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn generation_is_deterministic_and_materialized() {
        let mut first = generate(789);
        assert_eq!(first, generate(789));
        materialize_forward_routes(&mut first);
        assert!(
            first
                .operations
                .iter()
                .any(|operation| operation.protocol == Protocol::Connect)
        );
        let combinations = first
            .operations
            .iter()
            .map(|operation| (operation.protocol, operation.route))
            .collect::<BTreeSet<_>>();
        assert_eq!(combinations.len(), 6);
        assert!(
            first
                .operations
                .iter()
                .any(|operation| operation.body.len() == 16 * 1024)
        );
        assert!(first.operations.iter().any(|operation| {
            operation.outcome == ExpectedOutcome::Blocked
                || operation.outcome == ExpectedOutcome::RouteFailure
        }));
        assert!(
            first
                .operations
                .iter()
                .any(|operation| operation.method == "PATCH")
        );
    }
    #[test]
    fn forward_routes_are_stable_and_cover_every_fixture() {
        let mut scenario = generate(789);
        materialize_forward_routes(&mut scenario);
        assert_eq!(scenario.operations[0].route, ExpectedRoute::Direct);
        assert_eq!(scenario.operations[1].route, ExpectedRoute::Socks5);
        assert_eq!(scenario.operations[2].route, ExpectedRoute::HttpProxy);
    }

    #[test]
    fn reserved_fixture_addresses_are_distinct() {
        let addresses = reserve_addresses::<8>().unwrap();
        assert_eq!(addresses.into_iter().collect::<BTreeSet<_>>().len(), 8);
    }
    #[test]
    fn metric_parser_requires_exact_name_and_labels() {
        let metrics = "msgtausch_routes_total{route=\"socks5\"} 4\nmsgtausch_routes_total{route=\"direct\"} 2\n";
        assert_eq!(
            metric_number(metrics, "msgtausch_routes_total", &[("route", "socks5")]).unwrap(),
            4.0
        );
        assert!(
            metric_number(
                metrics,
                "msgtausch_routes_total",
                &[("route", "http_proxy")]
            )
            .is_err()
        );
    }

    #[test]
    fn metric_delta_parses_counters_gauges_and_floats() {
        let baseline = "msgtausch_connections_total 1\nmsgtausch_connections_active 0\n";
        let current = "msgtausch_connections_total 4\nmsgtausch_connections_active 0\nmsgtausch_http_request_duration_seconds_sum 0.0125\n";
        assert_eq!(
            metric_delta(baseline, current, "msgtausch_connections_total", &[]).unwrap(),
            3.0
        );
        assert_eq!(
            metric_number(current, "msgtausch_http_request_duration_seconds_sum", &[]).unwrap(),
            0.0125
        );
    }

    #[test]
    fn dns_reconciliation_combines_wire_and_cache_queries() {
        let operation = |id, outcome| Operation {
            id,
            protocol: Protocol::Http,
            method: "GET".into(),
            path: "/".into(),
            body: String::new(),
            route: ExpectedRoute::Direct,
            outcome,
        };
        let scenario = Scenario {
            schema_version: SCHEMA_VERSION,
            seed: 1,
            concurrency: 1,
            operations: vec![
                operation(1, ExpectedOutcome::Success),
                operation(2, ExpectedOutcome::RouteFailure),
                operation(3, ExpectedOutcome::Success),
                operation(4, ExpectedOutcome::Blocked),
            ],
        };
        let questions = vec![
            ("policy.msgtausch.test".into(), 1),
            ("policy.msgtausch.test".into(), 28),
            ("policy.msgtausch.test".into(), 1),
            ("policy.msgtausch.test".into(), 28),
        ];

        reconcile_dns_queries(&scenario, &questions, 4, 1.0).unwrap();
    }

    #[test]
    fn dns_reconciliation_requires_balanced_wire_query_types() {
        let scenario = Scenario {
            schema_version: SCHEMA_VERSION,
            seed: 1,
            concurrency: 1,
            operations: vec![Operation {
                id: 1,
                protocol: Protocol::Http,
                method: "GET".into(),
                path: "/".into(),
                body: String::new(),
                route: ExpectedRoute::Direct,
                outcome: ExpectedOutcome::Success,
            }],
        };
        let questions = vec![
            ("policy.msgtausch.test".into(), 1),
            ("policy.msgtausch.test".into(), 1),
        ];

        let error = reconcile_dns_queries(&scenario, &questions, 2, 0.0).unwrap_err();
        assert!(format!("{error:#}").contains("A queries and 0 AAAA queries"));
    }

    #[test]
    fn fixed_corpus_covers_methods_routes_failures_and_concurrency() {
        let directory = Path::new(env!("CARGO_MANIFEST_DIR")).join("corpus");
        let mut methods = BTreeSet::new();
        let mut combinations = BTreeSet::new();
        let mut outcomes = BTreeSet::new();
        let mut concurrent = false;
        for entry in fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            let scenario: Scenario = serde_json::from_slice(&fs::read(path).unwrap()).unwrap();
            concurrent |= scenario.concurrency > 1;
            for operation in scenario.operations {
                methods.insert(operation.method);
                combinations.insert((operation.protocol, operation.route));
                outcomes.insert(operation.outcome);
            }
        }
        for method in [
            "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "PURGE",
        ] {
            assert!(methods.contains(method), "fixed corpus missed {method}");
        }
        assert_eq!(combinations.len(), 6);
        assert_eq!(outcomes.len(), 3);
        assert!(concurrent);
    }
    #[test]
    fn artifact_round_trip_preserves_scenario() {
        let artifact = FailureArtifact {
            schema_version: SCHEMA_VERSION,
            seed: 42,
            scenario: generate(42),
            redacted_config: serde_json::json!({}),
            events: Vec::new(),
            metrics: String::new(),
            proxy_stderr: String::new(),
            error: "test".into(),
        };
        let encoded = serde_json::to_vec(&artifact).unwrap();
        let decoded: FailureArtifact = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded.scenario, artifact.scenario);
    }

    #[test]
    fn failed_run_reports_the_seed() {
        let artifact_dir = tempfile::tempdir().unwrap();
        let options = RunOptions {
            binary: PathBuf::from("/bin/false"),
            artifact_dir: artifact_dir.path().to_owned(),
            timeout: Duration::from_secs(1),
            shutdown_timeout: Duration::from_secs(1),
            enable_forwards: false,
            enable_policy_fixtures: false,
        };

        let error = run(generate(424_242), &options).unwrap_err();
        assert!(
            format!("{error:#}").contains("seed=424242"),
            "failure did not identify its seed: {error:#}"
        );
    }

    #[test]
    fn failure_ports_stay_reserved_until_fixtures_are_started() {
        let mut failures = FailureTargets::reserve().unwrap();

        assert!(TcpListener::bind(failures.http_proxy).is_err());
        failures.release();
        assert!(TcpListener::bind(failures.http_proxy).is_ok());
    }

    #[test]
    fn socks_fixture_relays_a_real_tunnel() {
        let origin = Origin::start().unwrap();
        let fixture = SocksFixture::start().unwrap();
        let mut stream = TcpStream::connect(fixture.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream.write_all(&[5, 1, 0]).unwrap();
        assert_eq!(read_exact(&mut stream, 2).unwrap(), [5, 0]);
        let ip = match origin.address.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            std::net::IpAddr::V6(_) => panic!("test origin must be IPv4"),
        };
        let mut request = vec![5, 1, 0, 1];
        request.extend(ip);
        request.extend(origin.address.port().to_be_bytes());
        stream.write_all(&request).unwrap();
        assert_eq!(read_exact(&mut stream, 10).unwrap()[..2], [5, 0]);
        request_in_tunnel(&mut stream, 81, "/fixture/socks");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        assert!(String::from_utf8_lossy(&response).contains("81|GET|/fixture/socks|"));
        assert_eq!(fixture.requests(), 1);
        assert_eq!(origin.requests(), 1);
    }

    #[test]
    fn http_connect_fixture_relays_a_real_tunnel() {
        let origin = Origin::start().unwrap();
        let fixture = HttpConnectFixture::start().unwrap();
        let mut stream = TcpStream::connect(fixture.address).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        write!(
            stream,
            "CONNECT {} HTTP/1.1\r\nHost: {}\r\n\r\n",
            origin.address, origin.address
        )
        .unwrap();
        assert!(
            read_headers(&mut stream)
                .unwrap()
                .starts_with(b"HTTP/1.1 200")
        );
        request_in_tunnel(&mut stream, 82, "/fixture/http-connect");
        let mut response = Vec::new();
        stream.read_to_end(&mut response).unwrap();
        assert!(String::from_utf8_lossy(&response).contains("82|GET|/fixture/http-connect|"));
        assert_eq!(fixture.requests(), 1);
        assert_eq!(origin.requests(), 1);
    }

    fn request_in_tunnel(stream: &mut TcpStream, id: u32, path: &str) {
        write!(
            stream,
            "GET {path} HTTP/1.1\r\nHost: fixture\r\nX-Sim-Id: {id}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
        )
        .unwrap();
    }
}
