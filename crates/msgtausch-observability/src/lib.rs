use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use anyhow::{Context, Result, bail};
use async_trait::async_trait;
use compio::{
    BufResult,
    io::{AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::TcpListener,
    runtime::{JoinHandle, spawn},
};
use hyper::{Method, StatusCode};
use opentelemetry::trace::TracerProvider as _;
use opentelemetry_http::{Bytes, HttpClient, HttpError, Request, Response};
use opentelemetry_otlp::{WithExportConfig, WithHttpConfig};
use opentelemetry_sdk::{Resource, trace::SdkTracerProvider};
use prometheus_client::{
    encoding::{EncodeLabelSet, text::encode},
    metrics::{
        counter::Counter,
        family::Family,
        gauge::Gauge,
        histogram::{Histogram, exponential_buckets},
    },
    registry::Registry,
};
use tracing_subscriber::{EnvFilter, layer::SubscriberExt, util::SubscriberInitExt};

use msgtausch_config::ObservabilityConfig;
use msgtausch_proxy::ProxyMetrics;

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RouteLabels {
    route: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct ErrorLabels {
    kind: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct AccessLabels {
    decision: &'static str,
}

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct RequestLabels {
    method: &'static str,
    status_class: &'static str,
}

pub struct Observability {
    registry: Mutex<Registry>,
    active_connections: Gauge,
    connections_total: Counter,
    access_total: Family<AccessLabels, Counter>,
    requests_total: Family<RequestLabels, Counter>,
    request_duration: Histogram,
    routes_total: Family<RouteLabels, Counter>,
    route_errors_total: Family<RouteLabels, Counter>,
    errors_total: Family<ErrorLabels, Counter>,
    bytes_sent: Counter,
    bytes_received: Counter,
    tunnel_duration: Histogram,
}

impl Observability {
    pub fn new() -> Arc<Self> {
        let active_connections = Gauge::default();
        let connections_total = Counter::default();
        let access_total = Family::default();
        let requests_total = Family::default();
        let request_duration = Histogram::new(exponential_buckets(0.001, 2.0, 18));
        let routes_total = Family::default();
        let route_errors_total = Family::default();
        let errors_total = Family::default();
        let bytes_sent = Counter::default();
        let bytes_received = Counter::default();
        let tunnel_duration = Histogram::new(exponential_buckets(0.001, 2.0, 18));

        let mut registry = Registry::with_prefix("msgtausch");
        registry.register(
            "connections_active",
            "Open downstream proxy connections.",
            active_connections.clone(),
        );
        registry.register(
            "connections",
            "Accepted downstream proxy connections.",
            connections_total.clone(),
        );
        registry.register(
            "access_decisions",
            "Allowlist and blocklist decisions.",
            access_total.clone(),
        );
        registry.register(
            "http_requests",
            "Completed HTTP proxy requests.",
            requests_total.clone(),
        );
        registry.register(
            "http_request_duration_seconds",
            "HTTP proxy request duration.",
            request_duration.clone(),
        );
        registry.register("routes", "Selected upstream routes.", routes_total.clone());
        registry.register(
            "route_errors",
            "Failed upstream route connections.",
            route_errors_total.clone(),
        );
        registry.register(
            "errors",
            "Proxy errors grouped by a bounded error kind.",
            errors_total.clone(),
        );
        registry.register(
            "tunnel_bytes_sent",
            "Bytes copied from clients to upstream tunnels.",
            bytes_sent.clone(),
        );
        registry.register(
            "tunnel_bytes_received",
            "Bytes copied from upstream tunnels to clients.",
            bytes_received.clone(),
        );
        registry.register(
            "tunnel_duration_seconds",
            "CONNECT and upgrade tunnel duration.",
            tunnel_duration.clone(),
        );

        Arc::new(Self {
            registry: Mutex::new(registry),
            active_connections,
            connections_total,
            access_total,
            requests_total,
            request_duration,
            routes_total,
            route_errors_total,
            errors_total,
            bytes_sent,
            bytes_received,
            tunnel_duration,
        })
    }

    fn encode(&self) -> Result<String> {
        let registry = self
            .registry
            .lock()
            .expect("metrics registry mutex poisoned");
        let mut body = String::new();
        encode(&mut body, &registry).context("encoding Prometheus metrics")?;
        Ok(body)
    }

    pub async fn serve(self: Arc<Self>, address: SocketAddr) -> Result<()> {
        let listener = TcpListener::bind(address)
            .await
            .with_context(|| format!("binding Prometheus listener {address}"))?;
        tracing::info!(%address, "Prometheus metrics listener started");
        loop {
            let (mut stream, _) = listener
                .accept()
                .await
                .context("accepting Prometheus connection")?;
            let metrics = self.clone();
            spawn(async move {
                let _ = serve_prometheus_connection(&mut stream, &metrics).await;
            })
            .detach();
        }
    }
}

async fn serve_prometheus_connection(
    stream: &mut compio::net::TcpStream,
    metrics: &Observability,
) -> Result<()> {
    read_prometheus_request(stream).await?;
    let body = metrics.encode().unwrap_or_else(|error| error.to_string());
    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/openmetrics-text; version=1.0.0; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(),
        body
    );
    let BufResult(result, _) = stream.write_all(response.into_bytes()).await;
    result.context("writing Prometheus response")?;
    stream
        .shutdown()
        .await
        .context("shutting down Prometheus connection")
}

async fn read_prometheus_request(stream: &mut compio::net::TcpStream) -> Result<()> {
    const MAX_HEADER_BYTES: usize = 32 * 1024;
    let mut headers = Vec::with_capacity(512);
    while !headers.ends_with(b"\r\n\r\n") {
        if headers.len() == MAX_HEADER_BYTES {
            bail!("Prometheus request headers exceed {MAX_HEADER_BYTES} bytes");
        }
        let BufResult(result, byte) = stream.read_exact(vec![0_u8]).await;
        result.context("reading Prometheus request headers")?;
        headers.push(byte[0]);
    }
    Ok(())
}

impl ProxyMetrics for Observability {
    fn connection_opened(&self) {
        self.active_connections.inc();
        self.connections_total.inc();
    }

    fn connection_closed(&self) {
        self.active_connections.dec();
    }

    fn access_decision(&self, allowed: bool) {
        self.access_total
            .get_or_create(&AccessLabels {
                decision: if allowed { "allow" } else { "block" },
            })
            .inc();
    }

    fn request_finished(&self, method: &Method, status: StatusCode, duration: Duration) {
        self.requests_total
            .get_or_create(&RequestLabels {
                method: bounded_method(method),
                status_class: status_class(status),
            })
            .inc();
        self.request_duration.observe(duration.as_secs_f64());
    }

    fn proxy_error(&self, kind: &'static str) {
        self.errors_total
            .get_or_create(&ErrorLabels {
                kind: bounded_error_kind(kind),
            })
            .inc();
    }

    fn route_selected(&self, route: &'static str) {
        self.routes_total
            .get_or_create(&RouteLabels {
                route: bounded_route(route),
            })
            .inc();
    }

    fn route_error(&self, route: &'static str) {
        self.route_errors_total
            .get_or_create(&RouteLabels {
                route: bounded_route(route),
            })
            .inc();
    }

    fn tunnel_finished(&self, sent: u64, received: u64, duration: Duration) {
        self.bytes_sent.inc_by(sent);
        self.bytes_received.inc_by(received);
        self.tunnel_duration.observe(duration.as_secs_f64());
    }
}

pub struct TelemetryGuard {
    provider: Option<SdkTracerProvider>,
}

#[derive(Debug, Default)]
struct BlockingHttpClient;

#[async_trait]
impl HttpClient for BlockingHttpClient {
    async fn send_bytes(
        &self,
        request: Request<Bytes>,
    ) -> std::result::Result<Response<Bytes>, HttpError> {
        let request = request.map(|body| body.to_vec());
        let response = ureq::run(request)?;
        let (parts, mut body) = response.into_parts();
        let body = body.read_to_vec()?;
        Ok(Response::from_parts(parts, Bytes::from(body)))
    }
}

impl Drop for TelemetryGuard {
    fn drop(&mut self) {
        if let Some(provider) = self.provider.take() {
            let _ = provider.shutdown();
        }
    }
}

pub fn init_tracing(
    config: &ObservabilityConfig,
    debug: bool,
    trace: bool,
) -> Result<TelemetryGuard> {
    let default_filter = if trace {
        "trace"
    } else if debug {
        "debug"
    } else {
        "info"
    };
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(default_filter));

    let provider = if let Some(endpoint) = &config.otlp_endpoint {
        let exporter = opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .with_http_client(BlockingHttpClient)
            .with_endpoint(endpoint)
            .build()
            .context("creating OTLP span exporter")?;
        let resource = Resource::builder()
            .with_service_name(
                config
                    .otlp_service_name
                    .clone()
                    .unwrap_or_else(|| "msgtausch".into()),
            )
            .build();
        let provider = SdkTracerProvider::builder()
            .with_resource(resource)
            .with_batch_exporter(exporter)
            .build();
        let tracer = provider.tracer("msgtausch");
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .with(tracing_opentelemetry::layer().with_tracer(tracer))
            .try_init()
            .context("installing tracing subscriber")?;
        Some(provider)
    } else {
        tracing_subscriber::registry()
            .with(filter)
            .with(tracing_subscriber::fmt::layer())
            .try_init()
            .context("installing tracing subscriber")?;
        None
    };
    Ok(TelemetryGuard { provider })
}

fn bounded_method(method: &Method) -> &'static str {
    match *method {
        Method::GET => "GET",
        Method::HEAD => "HEAD",
        Method::POST => "POST",
        Method::PUT => "PUT",
        Method::DELETE => "DELETE",
        Method::CONNECT => "CONNECT",
        Method::OPTIONS => "OPTIONS",
        Method::TRACE => "TRACE",
        Method::PATCH => "PATCH",
        _ => "OTHER",
    }
}

fn status_class(status: StatusCode) -> &'static str {
    match status.as_u16() / 100 {
        1 => "1xx",
        2 => "2xx",
        3 => "3xx",
        4 => "4xx",
        5 => "5xx",
        _ => "other",
    }
}

fn bounded_route(route: &'static str) -> &'static str {
    match route {
        "direct" | "socks5" | "http_proxy" => route,
        _ => "other",
    }
}

fn bounded_error_kind(kind: &'static str) -> &'static str {
    match kind {
        "invalid_target"
        | "blocked"
        | "classifier"
        | "http_forward"
        | "interception_classifier"
        | "connect"
        | "upgrade"
        | "tunnel_io"
        | "tunnel_timeout"
        | "downstream_tls"
        | "nested_connect"
        | "interception"
        | "upstream_tls"
        | "https_forward"
        | "h3_route"
        | "h3_forward" => kind,
        _ => "other",
    }
}

pub fn spawn_prometheus(
    metrics: Arc<Observability>,
    config: &ObservabilityConfig,
) -> Result<Option<JoinHandle<Result<()>>>> {
    config
        .prometheus_listen_address
        .as_ref()
        .map(|address| {
            let address = address
                .parse::<SocketAddr>()
                .with_context(|| format!("invalid Prometheus listen address {address}"))?;
            Ok(spawn(metrics.serve(address)))
        })
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[compio::test]
    async fn prometheus_waits_for_an_http_request() {
        use compio::io::AsyncReadExt as _;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let metrics = Observability::new();
        let server = spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            serve_prometheus_connection(&mut stream, &metrics).await
        });
        let mut client = compio::net::TcpStream::connect(address).await.unwrap();

        let early_response =
            compio::time::timeout(Duration::from_millis(50), client.read_exact(vec![0_u8])).await;
        assert!(
            early_response.is_err(),
            "Prometheus responded before receiving an HTTP request"
        );

        drop(client);
        let _ = server.await;
    }

    #[test]
    fn metric_output_uses_bounded_labels() {
        let metrics = Observability::new();
        metrics.connection_opened();
        metrics.connection_closed();
        metrics.access_decision(true);
        metrics.access_decision(false);
        metrics.request_finished(&Method::GET, StatusCode::OK, Duration::from_millis(5));
        metrics.request_finished(
            &Method::from_bytes(b"CUSTOM").unwrap(),
            StatusCode::BAD_GATEWAY,
            Duration::from_millis(7),
        );
        metrics.route_selected("direct");
        metrics.route_selected("unbounded-route");
        metrics.route_error("socks5");
        metrics.proxy_error("connect");
        metrics.proxy_error("unbounded-error");
        metrics.tunnel_finished(123, 456, Duration::from_millis(11));
        let output = metrics.encode().unwrap();

        assert!(output.contains("msgtausch_connections_active 0"));
        assert!(output.contains("msgtausch_connections_total 1"));
        assert!(output.contains("decision=\"allow\"} 1"));
        assert!(output.contains("decision=\"block\"} 1"));
        assert!(output.contains("msgtausch_http_requests_total"));
        assert!(output.contains("method=\"GET\""));
        assert!(output.contains("method=\"OTHER\""));
        assert!(output.contains("status_class=\"2xx\""));
        assert!(output.contains("status_class=\"5xx\""));
        assert!(output.contains("msgtausch_http_request_duration_seconds_count 2"));
        assert!(output.contains("route=\"direct\""));
        assert!(output.contains("route=\"other\""));
        assert!(output.contains("msgtausch_route_errors_total{route=\"socks5\"} 1"));
        assert!(output.contains("msgtausch_errors_total{kind=\"connect\"} 1"));
        assert!(output.contains("msgtausch_errors_total{kind=\"other\"} 1"));
        assert!(output.contains("msgtausch_tunnel_bytes_sent_total 123"));
        assert!(output.contains("msgtausch_tunnel_bytes_received_total 456"));
        assert!(output.contains("msgtausch_tunnel_duration_seconds_count 1"));
        assert!(!output.contains("unbounded-route"));
        assert!(!output.contains("unbounded-error"));
    }
}
