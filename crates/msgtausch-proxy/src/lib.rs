//! HTTP forward proxy runtime.

use std::{
    convert::Infallible,
    io,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::Arc,
    task::{Context as TaskContext, Poll},
    time::{Duration, Instant},
};

use anyhow::{Context, Result};
use bytes::Bytes;
use compio::{net::TcpStream, runtime, time::timeout};
use cyper_core::HyperStream;
use futures_util::io::{AsyncRead, AsyncWrite};
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::{
    Method, Request, Response, StatusCode, Uri,
    body::Incoming,
    header::{CONNECTION, HOST, PROXY_AUTHENTICATE, PROXY_AUTHORIZATION, UPGRADE},
    service::service_fn,
};

use msgtausch_config::{Config, ServerKind};
use msgtausch_interception::InterceptionRuntime;
use msgtausch_policy::{ClassifierEngine, Target};
use msgtausch_quic::{H3Connection, H3Request, H3Response, H3Upstream};
use msgtausch_routing::{RouteMetrics, RoutePlanner};

pub type ProxyBody = BoxBody<Bytes, hyper::Error>;

/// Request-path telemetry seam. Implementations must use bounded dimensions.
/// Hosts, paths, and client addresses belong in traces or logs, never metric
/// labels.
pub trait ProxyMetrics: Send + Sync + 'static {
    fn connection_opened(&self) {}
    fn connection_closed(&self) {}
    fn access_decision(&self, _allowed: bool) {}
    fn request_finished(&self, _method: &Method, _status: StatusCode, _duration: Duration) {}
    fn tunnel_finished(&self, _sent: u64, _received: u64, _duration: Duration) {}
    fn proxy_error(&self, _kind: &'static str) {}
    fn route_selected(&self, _route: &'static str) {}
    fn route_error(&self, _route: &'static str) {}
}

#[derive(Default)]
pub struct NoopProxyMetrics;
impl ProxyMetrics for NoopProxyMetrics {}

struct ProxyRouteMetrics(Arc<dyn ProxyMetrics>);
impl RouteMetrics for ProxyRouteMetrics {
    fn route_selected(&self, route: &'static str) {
        self.0.route_selected(route);
    }
    fn route_error(&self, route: &'static str) {
        self.0.route_error(route);
    }
}

/// The runtime can be shared by every listener. Its state is immutable, which
/// makes a reload an atomic listener/runtime swap instead of partial mutation.
#[derive(Clone)]
pub struct ProxyRuntime {
    router: RoutePlanner,
    metrics: Arc<dyn ProxyMetrics>,
    idle_timeout: Duration,
    interception: Option<InterceptionRuntime>,
    connect_interception_enabled: bool,
}

impl ProxyRuntime {
    pub fn from_config(config: &Config, metrics: Arc<dyn ProxyMetrics>) -> Result<Self> {
        let classifiers = ClassifierEngine::from_config(config)?;
        let dedicated_tls_listener = has_dedicated_tls_listener(config);
        let interception =
            InterceptionRuntime::from_config_for_dedicated_listener_with_classifiers(
                &config.interception,
                dedicated_tls_listener,
                &classifiers,
            )?;
        let timeout = config.timeout_seconds.max(1);
        Ok(Self {
            router: RoutePlanner::new(
                classifiers,
                timeout,
                Arc::new(ProxyRouteMetrics(metrics.clone())),
            )
            .with_dns(&config.dns),
            metrics,
            idle_timeout: Duration::from_secs(timeout),
            interception,
            connect_interception_enabled: config.interception.enabled && config.interception.https,
        })
    }

    pub fn with_noop_metrics(config: &Config) -> Result<Self> {
        Self::from_config(config, Arc::new(NoopProxyMetrics))
    }

    /// Share the compiled classifier engine with background refresh workers.
    pub fn classifiers_shared(&self) -> Arc<ClassifierEngine> {
        self.router.classifiers_shared()
    }

    /// Configuration for an intercepted HTTP/3 listener. A missing
    /// interception runtime is a configuration error, never a fallback to an
    /// unrelated certificate.
    pub fn quic_server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        Ok(self
            .interception
            .as_ref()
            .context("QUIC listener requires CA certificate state")?
            .quic_server_config())
    }

    /// Serve an already handshaken HTTP/3 connection. The certificate's SNI
    /// is carried by `H3Connection`; the request authority is checked there
    /// before this policy and routing path runs.
    pub async fn serve_h3_connection(self: Arc<Self>, connection: H3Connection) -> Result<()> {
        self.metrics.connection_opened();
        let runtime = self.clone();
        let result = connection
            .serve(move |context, request| {
                let runtime = runtime.clone();
                async move { runtime.forward_h3(context.peer, context.sni, request).await }
            })
            .await;
        self.metrics.connection_closed();
        result
    }

    async fn forward_h3(
        &self,
        peer: SocketAddr,
        sni: Option<String>,
        request: H3Request,
    ) -> Result<H3Response> {
        let started = Instant::now();
        let method = request.method.clone();
        let response: Result<H3Response> = async {
            let host = sni.context("HTTP/3 client did not supply SNI")?;
            let target = Target::new(host, 443, Some(peer.ip()));
            if !self.router.classifiers().allows(&target)? {
                self.metrics.access_decision(false);
                return Ok(h3_failure(StatusCode::FORBIDDEN, "Host not allowed"));
            }
            self.metrics.access_decision(true);
            let interception = self
                .interception
                .as_ref()
                .context("HTTP/3 listener requires CA certificate state")?;
            if !interception.should_intercept(&target, self.router.classifiers())? {
                return Ok(h3_failure(
                    StatusCode::FORBIDDEN,
                    "Host excluded from interception",
                ));
            }
            let remote = match self.router.resolve_direct(&target).await {
                Ok(remote) => remote,
                Err(error) => {
                    self.metrics.proxy_error("h3_route");
                    return Ok(h3_failure(StatusCode::BAD_GATEWAY, &error.to_string()));
                }
            };
            let upstream = H3Upstream {
                remote,
                authority: target
                    .authority()
                    .parse()
                    .context("building pinned HTTP/3 authority")?,
                tls: (*interception.upstream_tls_config()).clone(),
            };
            match msgtausch_quic::request(&upstream, request).await {
                Ok(response) => Ok(response),
                Err(error) => {
                    self.metrics.proxy_error("h3_forward");
                    Ok(h3_failure(StatusCode::BAD_GATEWAY, &error.to_string()))
                }
            }
        }
        .await;
        let response = response?;
        self.metrics
            .request_finished(&method, response.response.status(), started.elapsed());
        Ok(response)
    }

    /// Serve one accepted HTTP/1 connection, including CONNECT and HTTP/1
    /// upgrade support. Listener ownership and shutdown stay in `main`.
    pub async fn serve_connection(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> Result<()> {
        self.metrics.connection_opened();
        let runtime = self.clone();
        let result = hyper::server::conn::http1::Builder::new()
            .preserve_header_case(true)
            .serve_connection(
                HyperStream::new_plain(stream),
                service_fn(move |request| {
                    let runtime = runtime.clone();
                    async move { Ok::<_, Infallible>(runtime.handle(request, peer).await) }
                }),
            )
            .with_upgrades()
            .await
            .context("serving proxy connection");
        self.metrics.connection_closed();
        result
    }

    /// Serve a dedicated HTTPS listener. SNI determines both the leaf
    /// certificate and the only upstream authority allowed on this connection.
    /// A client without SNI is rejected because selecting an arbitrary
    /// certificate or target would be a silent downgrade in disguise.
    pub async fn serve_https_connection(
        self: Arc<Self>,
        stream: TcpStream,
        peer: SocketAddr,
    ) -> Result<()> {
        let interception = self
            .interception
            .as_ref()
            .context("HTTPS listener requires CA certificate state")?;
        let handshake =
            compio::tls::LazyConfigAcceptor::new(rustls::server::Acceptor::default(), stream)
                .await
                .context("reading HTTPS listener ClientHello")?;
        let host = handshake
            .client_hello()
            .server_name()
            .context("HTTPS listener client did not supply SNI")?
            .to_owned();
        let target = Target::new(host, 443, Some(peer.ip()));
        match self.router.classifiers().allows(&target) {
            Ok(true) => self.metrics.access_decision(true),
            Ok(false) => {
                self.metrics.access_decision(false);
                anyhow::bail!("HTTPS listener target is blocked by the access classifier");
            }
            Err(error) => {
                self.metrics.proxy_error("classifier");
                return Err(error).context("classifying HTTPS listener target");
            }
        }
        if !interception.should_intercept(&target, self.router.classifiers())? {
            anyhow::bail!("HTTPS listener target is excluded from interception");
        }
        let tls = handshake
            .into_stream(interception.downstream_config(&target.host)?)
            .await
            .context("accepting HTTPS listener TLS connection")?;
        self.metrics.connection_opened();
        let runtime = self.clone();
        let pinned_target = target.clone();
        let result =
            hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(
                    FuturesHyperIo(tls),
                    service_fn(move |request| {
                        let runtime = runtime.clone();
                        let target = pinned_target.clone();
                        async move {
                            Ok::<_, Infallible>(runtime.handle_intercepted(request, target).await)
                        }
                    }),
                )
                .await
                .context("serving HTTPS listener connection");
        self.metrics.connection_closed();
        result
    }

    async fn handle(
        self: Arc<Self>,
        request: Request<Incoming>,
        peer: SocketAddr,
    ) -> Response<ProxyBody> {
        let started = Instant::now();
        let method = request.method().clone();
        let response = match target_from_request(&request, peer.ip()) {
            Err(error) => self.failure(StatusCode::BAD_REQUEST, "invalid_target", error),
            Ok(target) => match self.router.classifiers().allows(&target) {
                Ok(false) => {
                    self.metrics.access_decision(false);
                    self.failure(StatusCode::FORBIDDEN, "blocked", "Host not allowed")
                }
                Err(error) => self.failure(StatusCode::INTERNAL_SERVER_ERROR, "classifier", error),
                Ok(true) => {
                    self.metrics.access_decision(true);
                    if method == Method::CONNECT {
                        self.clone().handle_connect(request, target).await
                    } else {
                        self.forward_http(request, target)
                            .await
                            .unwrap_or_else(|error| {
                                self.failure(StatusCode::BAD_GATEWAY, "http_forward", error)
                            })
                    }
                }
            },
        };
        self.metrics
            .request_finished(&method, response.status(), started.elapsed());
        response
    }

    async fn forward_http(
        &self,
        request: Request<Incoming>,
        target: Target,
    ) -> Result<Response<ProxyBody>> {
        let stream = HyperStream::new_plain(self.router.connect(&target).await?);
        self.forward_http_on_stream(request, target, stream).await
    }

    async fn forward_http_on_stream(
        &self,
        mut request: Request<Incoming>,
        target: Target,
        stream: HyperStream<TcpStream>,
    ) -> Result<Response<ProxyBody>> {
        let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
            .preserve_header_case(true)
            .handshake(stream)
            .await
            .context("starting upstream HTTP connection")?;
        runtime::spawn(async move {
            let _ = connection.with_upgrades().await;
        })
        .detach();

        let wants_upgrade = is_upgrade(&request);
        let client_upgrade = wants_upgrade.then(|| hyper::upgrade::on(&mut request));
        strip_proxy_headers(&mut request, wants_upgrade);
        rewrite_to_origin_form(&mut request, &target)?;
        let mut upstream = sender
            .send_request(request)
            .await
            .context("forwarding HTTP request")?;
        let status = upstream.status();
        let upstream_upgrade = (wants_upgrade && status == StatusCode::SWITCHING_PROTOCOLS)
            .then(|| hyper::upgrade::on(&mut upstream));
        let response = upstream.map(|body| body.boxed());
        if let (Some(client_upgrade), Some(upstream_upgrade)) = (client_upgrade, upstream_upgrade) {
            let idle = self.idle_timeout;
            let metrics = self.metrics.clone();
            runtime::spawn(async move {
                let (client, upstream) = match (client_upgrade.await, upstream_upgrade.await) {
                    (Ok(client), Ok(upstream)) => (client, upstream),
                    _ => {
                        metrics.proxy_error("upgrade");
                        return;
                    }
                };
                let started = Instant::now();
                match timeout(idle, tunnel(client, upstream)).await {
                    Ok(Ok((sent, received))) => {
                        metrics.tunnel_finished(sent, received, started.elapsed());
                    }
                    Ok(Err(_)) => metrics.proxy_error("tunnel_io"),
                    Err(_) => metrics.proxy_error("tunnel_timeout"),
                }
            })
            .detach();
        }
        Ok(response)
    }

    async fn handle_connect(
        self: Arc<Self>,
        mut request: Request<Incoming>,
        target: Target,
    ) -> Response<ProxyBody> {
        if self.connect_interception_enabled
            && let Some(interception) = self.interception.clone()
        {
            match interception.should_intercept(&target, self.router.classifiers()) {
                Ok(true) => {
                    return self
                        .handle_intercepted_connect(request, target, interception)
                        .await;
                }
                Ok(false) => {}
                Err(error) => {
                    return self.failure(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "interception_classifier",
                        error,
                    );
                }
            }
        }
        let stream = match self.router.connect(&target).await {
            Ok(stream) => stream,
            Err(error) => return self.failure(StatusCode::BAD_GATEWAY, "connect", error),
        };
        let client = hyper::upgrade::on(&mut request);
        let idle = self.idle_timeout;
        let metrics = self.metrics.clone();
        runtime::spawn(async move {
            let client = match client.await {
                Ok(client) => client,
                Err(_) => {
                    metrics.proxy_error("upgrade");
                    return;
                }
            };
            let started = Instant::now();
            match timeout(idle, tunnel(client, HyperStream::new_plain(stream))).await {
                Ok(Ok((sent, received))) => {
                    metrics.tunnel_finished(sent, received, started.elapsed());
                }
                Ok(Err(_)) => metrics.proxy_error("tunnel_io"),
                Err(_) => metrics.proxy_error("tunnel_timeout"),
            }
        })
        .detach();
        Response::builder()
            .status(StatusCode::OK)
            .body(empty_body())
            .expect("valid CONNECT response")
    }

    async fn handle_intercepted_connect(
        self: Arc<Self>,
        mut request: Request<Incoming>,
        target: Target,
        interception: InterceptionRuntime,
    ) -> Response<ProxyBody> {
        let client = hyper::upgrade::on(&mut request);
        let runtime = self.clone();
        runtime::spawn(async move {
            let client = match client.await {
                Ok(client) => client,
                Err(_) => {
                    runtime.metrics.proxy_error("upgrade");
                    return;
                }
            };
            let tls = match interception
                .accept_downstream(HyperIo(client), &target.host)
                .await
            {
                Ok(tls) => tls,
                Err(_) => {
                    runtime.metrics.proxy_error("downstream_tls");
                    return;
                }
            };
            let service_runtime = runtime.clone();
            let pinned_target = target.clone();
            let _ = hyper::server::conn::http1::Builder::new()
                .preserve_header_case(true)
                .serve_connection(
                    FuturesHyperIo(tls),
                    service_fn(move |request| {
                        let runtime = service_runtime.clone();
                        let target = pinned_target.clone();
                        async move {
                            Ok::<_, Infallible>(runtime.handle_intercepted(request, target).await)
                        }
                    }),
                )
                .with_upgrades()
                .await;
        })
        .detach();
        Response::builder()
            .status(StatusCode::OK)
            .body(empty_body())
            .expect("valid CONNECT response")
    }

    async fn handle_intercepted(
        self: Arc<Self>,
        mut request: Request<Incoming>,
        target: Target,
    ) -> Response<ProxyBody> {
        let started = Instant::now();
        let method = request.method().clone();
        let response = if method == Method::CONNECT {
            self.failure(
                StatusCode::METHOD_NOT_ALLOWED,
                "nested_connect",
                "CONNECT is not allowed inside an intercepted tunnel",
            )
        } else if self.interception.is_none() {
            self.failure(
                StatusCode::INTERNAL_SERVER_ERROR,
                "interception",
                "interception runtime is unavailable",
            )
        } else {
            let interception = self
                .interception
                .as_ref()
                .expect("interception runtime checked above");
            match self.router.connect(&target).await {
                Err(error) => self.failure(StatusCode::BAD_GATEWAY, "connect", error),
                Ok(stream) => match interception.connect_upstream(stream, &target.host).await {
                    Err(error) => self.failure(StatusCode::BAD_GATEWAY, "upstream_tls", error),
                    Ok(stream) => {
                        request.headers_mut().insert(
                            HOST,
                            target
                                .authority()
                                .parse()
                                .expect("target authority is a header value"),
                        );
                        self.forward_http_on_stream(request, target, HyperStream::new_tls(stream))
                            .await
                            .unwrap_or_else(|error| {
                                self.failure(StatusCode::BAD_GATEWAY, "https_forward", error)
                            })
                    }
                },
            }
        };
        self.metrics
            .request_finished(&method, response.status(), started.elapsed());
        response
    }

    fn failure(
        &self,
        status: StatusCode,
        kind: &'static str,
        error: impl std::fmt::Display,
    ) -> Response<ProxyBody> {
        self.metrics.proxy_error(kind);
        Response::builder()
            .status(status)
            .header("content-type", "text/plain; charset=utf-8")
            .body(
                Full::new(Bytes::from(error.to_string()))
                    .map_err(|never| match never {})
                    .boxed(),
            )
            .expect("valid error response")
    }
}

fn has_dedicated_tls_listener(config: &Config) -> bool {
    config
        .servers
        .iter()
        .any(|server| server.enabled && matches!(server.kind, ServerKind::Https | ServerKind::Quic))
}

fn h3_failure(status: StatusCode, message: &str) -> H3Response {
    let body = Bytes::copy_from_slice(message.as_bytes());
    H3Response {
        response: Response::builder()
            .status(status)
            .header(hyper::header::CONTENT_LENGTH, body.len())
            .body(())
            .expect("valid HTTP/3 failure response"),
        body,
        trailers: None,
    }
}

fn target_from_request<B>(request: &Request<B>, client_ip: IpAddr) -> Result<Target> {
    let uri = request.uri();
    let authority = if request.method() == Method::CONNECT {
        uri.authority().map(ToString::to_string).or_else(|| {
            let path = uri.path();
            (!path.is_empty() && path != "/").then(|| path.to_string())
        })
    } else {
        uri.authority().map(ToString::to_string).or_else(|| {
            request
                .headers()
                .get(HOST)
                .and_then(|value| value.to_str().ok())
                .map(str::to_owned)
        })
    }
    .context("request has no target authority")?;
    let parsed: hyper::http::uri::Authority =
        authority.parse().context("malformed target authority")?;
    let port = parsed.port_u16().unwrap_or_else(|| {
        if uri.scheme_str() == Some("https") || request.method() == Method::CONNECT {
            443
        } else {
            80
        }
    });
    Ok(Target::new(parsed.host(), port, Some(client_ip)))
}

fn rewrite_to_origin_form<B>(request: &mut Request<B>, target: &Target) -> Result<()> {
    let path = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    let uri: Uri = path.parse().context("invalid request path")?;
    *request.uri_mut() = uri;
    if !request.headers().contains_key(HOST) {
        request.headers_mut().insert(
            HOST,
            target
                .authority()
                .parse()
                .expect("target authority is a header value"),
        );
    }
    Ok(())
}

fn is_upgrade<B>(request: &Request<B>) -> bool {
    request.headers().get(UPGRADE).is_some()
        && request
            .headers()
            .get(CONNECTION)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|token| token.trim().eq_ignore_ascii_case("upgrade"))
            })
}

fn strip_proxy_headers<B>(request: &mut Request<B>, preserve_upgrade: bool) {
    let named_by_connection = request
        .headers()
        .get(CONNECTION)
        .and_then(|value| value.to_str().ok())
        .map(|value| {
            value
                .split(',')
                .map(|token| token.trim().to_owned())
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    request.headers_mut().remove(PROXY_AUTHORIZATION);
    request.headers_mut().remove(PROXY_AUTHENTICATE);
    request.headers_mut().remove("proxy-connection");
    if !preserve_upgrade {
        request.headers_mut().remove(CONNECTION);
        request.headers_mut().remove(UPGRADE);
        for name in named_by_connection {
            if let Ok(name) = hyper::http::header::HeaderName::from_bytes(name.as_bytes()) {
                request.headers_mut().remove(name);
            }
        }
    }
}

fn empty_body() -> ProxyBody {
    Full::new(Bytes::new())
        .map_err(|never| match never {})
        .boxed()
}

/// Adapts Hyper's upgrade stream to the futures I/O traits used by the tunnel
/// copier. This keeps the proxy entirely on Compio while preserving Hyper's
/// upgrade buffering and shutdown handling.
struct HyperIo<T>(T);

impl<T: hyper::rt::Read + Unpin> AsyncRead for HyperIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut read_buf = hyper::rt::ReadBuf::new(buf);
        match hyper::rt::Read::poll_read(Pin::new(&mut self.0), cx, read_buf.unfilled()) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read_buf.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: hyper::rt::Write + Unpin> AsyncWrite for HyperIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        hyper::rt::Write::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        hyper::rt::Write::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        hyper::rt::Write::poll_shutdown(Pin::new(&mut self.0), cx)
    }
}

/// Gives Hyper a futures-I/O TLS stream without introducing a second runtime.
/// The stream is produced after Hyper has handed CONNECT's upgraded bytes to
/// the Compio task, so no bytes are lost between the two protocol layers.
struct FuturesHyperIo<T>(T);

impl<T: futures_util::io::AsyncRead + Unpin> hyper::rt::Read for FuturesHyperIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        mut buf: hyper::rt::ReadBufCursor<'_>,
    ) -> Poll<io::Result<()>> {
        let unfilled = unsafe { buf.as_mut() };
        unfilled.fill(std::mem::MaybeUninit::new(0));
        let read = futures_util::io::AsyncRead::poll_read(Pin::new(&mut self.0), cx, unsafe {
            unfilled.assume_init_mut()
        });
        match read {
            Poll::Ready(Ok(count)) => {
                unsafe { buf.advance(count) };
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<T: futures_util::io::AsyncWrite + Unpin> hyper::rt::Write for FuturesHyperIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        futures_util::io::AsyncWrite::poll_write(Pin::new(&mut self.0), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        futures_util::io::AsyncWrite::poll_flush(Pin::new(&mut self.0), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
        futures_util::io::AsyncWrite::poll_close(Pin::new(&mut self.0), cx)
    }
}

async fn tunnel(
    client: hyper::upgrade::Upgraded,
    upstream: impl hyper::rt::Read + hyper::rt::Write + Unpin,
) -> io::Result<(u64, u64)> {
    let mut client = HyperIo(client);
    let mut upstream = HyperIo(upstream);
    let mut sent = CopyBuffer::new();
    let mut received = CopyBuffer::new();

    std::future::poll_fn(move |cx| {
        let sent_state = sent.poll(cx, &mut client, &mut upstream);
        let received_state = received.poll(cx, &mut upstream, &mut client);
        if let Poll::Ready(Err(error)) = sent_state {
            return Poll::Ready(Err(error));
        }
        if let Poll::Ready(Err(error)) = received_state {
            return Poll::Ready(Err(error));
        }
        if matches!(sent_state, Poll::Ready(Ok(())))
            && matches!(received_state, Poll::Ready(Ok(())))
        {
            Poll::Ready(Ok((sent.copied, received.copied)))
        } else {
            Poll::Pending
        }
    })
    .await
}

struct CopyBuffer {
    bytes: Box<[u8; 16 * 1024]>,
    position: usize,
    capacity: usize,
    read_done: bool,
    write_done: bool,
    copied: u64,
}

impl CopyBuffer {
    fn new() -> Self {
        Self {
            bytes: Box::new([0; 16 * 1024]),
            position: 0,
            capacity: 0,
            read_done: false,
            write_done: false,
            copied: 0,
        }
    }

    fn poll<R, W>(
        &mut self,
        cx: &mut TaskContext<'_>,
        reader: &mut R,
        writer: &mut W,
    ) -> Poll<io::Result<()>>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        loop {
            if self.position == self.capacity && self.capacity != 0 {
                match AsyncWrite::poll_flush(Pin::new(&mut *writer), cx) {
                    Poll::Ready(Ok(())) => {
                        self.position = 0;
                        self.capacity = 0;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if self.position == self.capacity && !self.read_done {
                match AsyncRead::poll_read(Pin::new(&mut *reader), cx, &mut *self.bytes) {
                    Poll::Ready(Ok(0)) => self.read_done = true,
                    Poll::Ready(Ok(count)) => {
                        self.position = 0;
                        self.capacity = count;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            while self.position < self.capacity {
                match AsyncWrite::poll_write(
                    Pin::new(&mut *writer),
                    cx,
                    &self.bytes[self.position..self.capacity],
                ) {
                    Poll::Ready(Ok(0)) => {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::WriteZero,
                            "tunnel write returned zero bytes",
                        )));
                    }
                    Poll::Ready(Ok(count)) => {
                        self.position += count;
                        self.copied += count as u64;
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }

            if self.read_done && !self.write_done {
                match AsyncWrite::poll_close(Pin::new(&mut *writer), cx) {
                    Poll::Ready(Ok(())) => self.write_done = true,
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => return Poll::Pending,
                }
            }
            if self.write_done {
                return Poll::Ready(Ok(()));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use msgtausch_config::{ServerConfig, ServerKind};

    fn request(method: Method, uri: &str) -> Request<()> {
        Request::builder()
            .method(method)
            .uri(uri)
            .body(())
            .expect("valid test request")
    }

    #[test]
    fn target_uses_uri_authority_scheme_defaults_and_client_ip() {
        let client_ip = "192.0.2.4".parse().unwrap();
        let http = target_from_request(
            &request(Method::GET, "http://example.com/resource"),
            client_ip,
        )
        .unwrap();
        let https = target_from_request(
            &request(Method::GET, "https://secure.example/resource"),
            client_ip,
        )
        .unwrap();
        let connect =
            target_from_request(&request(Method::CONNECT, "tunnel.example"), client_ip).unwrap();

        assert_eq!(http, Target::new("example.com", 80, Some(client_ip)));
        assert_eq!(https, Target::new("secure.example", 443, Some(client_ip)));
        assert_eq!(connect, Target::new("tunnel.example", 443, Some(client_ip)));
    }

    #[test]
    fn target_uses_host_header_and_explicit_port() {
        let request = Request::builder()
            .uri("/resource")
            .header(HOST, "Example.COM:8080")
            .body(())
            .unwrap();

        let target = target_from_request(&request, "2001:db8::1".parse().unwrap()).unwrap();

        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 8080);
    }

    #[test]
    fn target_rejects_missing_and_malformed_authorities() {
        let client_ip = "127.0.0.1".parse().unwrap();
        let missing = target_from_request(&request(Method::GET, "/"), client_ip).unwrap_err();
        let malformed = Request::builder()
            .uri("/")
            .header(HOST, "bad host")
            .body(())
            .unwrap();
        let malformed = target_from_request(&malformed, client_ip).unwrap_err();

        assert!(missing.to_string().contains("no target authority"));
        assert!(malformed.to_string().contains("malformed target authority"));
    }

    #[test]
    fn origin_form_rewrite_preserves_path_query_and_existing_host() {
        let target = Target::new("upstream.example", 8443, None);
        let mut without_host =
            request(Method::GET, "http://upstream.example:8443/a/path?key=value");
        rewrite_to_origin_form(&mut without_host, &target).unwrap();
        assert_eq!(without_host.uri(), "/a/path?key=value");
        assert_eq!(without_host.headers()[HOST], "upstream.example:8443");

        let mut with_host = Request::builder()
            .uri("http://upstream.example:8443/")
            .header(HOST, "original.example")
            .body(())
            .unwrap();
        rewrite_to_origin_form(&mut with_host, &target).unwrap();
        assert_eq!(with_host.headers()[HOST], "original.example");
    }

    #[test]
    fn upgrade_requires_both_headers_and_a_matching_connection_token() {
        let mut request = request(Method::GET, "/");
        request
            .headers_mut()
            .insert(UPGRADE, "websocket".parse().unwrap());
        assert!(!is_upgrade(&request));

        request
            .headers_mut()
            .insert(CONNECTION, "keep-alive, UpGrAdE".parse().unwrap());
        assert!(is_upgrade(&request));
    }

    #[test]
    fn proxy_headers_and_connection_named_headers_are_removed() {
        let mut request = Request::builder()
            .uri("/")
            .header(PROXY_AUTHORIZATION, "secret")
            .header(PROXY_AUTHENTICATE, "challenge")
            .header("proxy-connection", "keep-alive")
            .header(CONNECTION, "keep-alive, x-private")
            .header("x-private", "remove me")
            .header("x-public", "keep me")
            .body(())
            .unwrap();

        strip_proxy_headers(&mut request, false);

        assert!(!request.headers().contains_key(PROXY_AUTHORIZATION));
        assert!(!request.headers().contains_key(PROXY_AUTHENTICATE));
        assert!(!request.headers().contains_key("proxy-connection"));
        assert!(!request.headers().contains_key(CONNECTION));
        assert!(!request.headers().contains_key("x-private"));
        assert_eq!(request.headers()["x-public"], "keep me");
    }

    #[test]
    fn preserving_upgrade_keeps_upgrade_and_connection_headers() {
        let mut request = Request::builder()
            .uri("/")
            .header(PROXY_AUTHORIZATION, "secret")
            .header(CONNECTION, "upgrade, x-private")
            .header(UPGRADE, "websocket")
            .header("x-private", "needed by upgrade")
            .body(())
            .unwrap();

        strip_proxy_headers(&mut request, true);

        assert!(!request.headers().contains_key(PROXY_AUTHORIZATION));
        assert_eq!(request.headers()[CONNECTION], "upgrade, x-private");
        assert_eq!(request.headers()[UPGRADE], "websocket");
        assert_eq!(request.headers()["x-private"], "needed by upgrade");
    }

    #[test]
    fn standard_proxy_does_not_load_ca_when_interception_is_disabled() {
        let config = Config::default();
        assert!(!has_dedicated_tls_listener(&config));
        assert!(ProxyRuntime::with_noop_metrics(&config).is_ok());
    }

    #[test]
    fn dedicated_quic_loads_ca_even_when_connect_interception_is_disabled() {
        let config = Config {
            servers: vec![ServerConfig {
                kind: ServerKind::Quic,
                listen_address: "127.0.0.1:4433".into(),
                enabled: true,
                interceptor_name: None,
            }],
            ..Config::default()
        };
        assert!(has_dedicated_tls_listener(&config));
        let error = match ProxyRuntime::with_noop_metrics(&config) {
            Ok(_) => panic!("dedicated QUIC listener must load CA state"),
            Err(error) => error,
        };
        assert!(
            error
                .to_string()
                .contains("QUIC listener requires interception.ca-file")
        );
    }
}
