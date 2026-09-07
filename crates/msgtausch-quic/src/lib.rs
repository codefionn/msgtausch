//! QUIC and HTTP/3 transport primitives.
//!
//! This module deliberately owns the HTTP/3 boundary.  Callers hand it an
//! already-resolved UDP address and an authority.  The authority is used for
//! both TLS SNI and the HTTP/3 `:authority` pseudo-header, so a request cannot
//! accidentally be authenticated for one host and sent as another.

use std::{cell::Cell, future::Future, net::SocketAddr, pin::Pin, rc::Rc, sync::Arc};

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Buf, Bytes};
use compio_quic::{
    ClientConfig, Connection, Endpoint, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
};
use futures_util::{
    Stream, StreamExt,
    future::{Either, select},
    stream::{self, FuturesUnordered},
};
use hyper::http::{HeaderMap, Method, Response, Uri, header};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// ALPN token required by this HTTP/3 implementation.
pub const H3_ALPN: &str = "h3";

/// Certificate material used by an HTTP/3 listener.
///
/// `bind` consumes it because private keys are intentionally not cloneable.
pub struct TlsIdentity {
    pub certificate_chain: Vec<CertificateDer<'static>>,
    pub private_key: PrivateKeyDer<'static>,
}

/// The only upstream identity accepted for a direct HTTP/3 connection.
///
/// `authority` is pinned to TLS SNI. Do not derive it from an untrusted
/// request header.
#[derive(Clone, Debug)]
pub struct H3Upstream {
    pub remote: SocketAddr,
    pub authority: hyper::http::uri::Authority,
    pub tls: rustls::ClientConfig,
}

/// A reusable direct HTTP/3 connection to one pinned upstream.
///
/// Keep this object for the lifetime of a proxy upstream session. Cloning its
/// request sender lets several request streams make progress at once.
pub struct H3Client {
    endpoint: Endpoint,
    sender: compio_quic::h3::client::SendRequest<compio_quic::h3::OpenStreams, Bytes>,
    authority: hyper::http::uri::Authority,
    closed: Rc<Cell<bool>>,
}

impl H3Client {
    pub async fn connect(upstream: &H3Upstream) -> Result<Self> {
        let client = client_config(upstream.tls.clone())?;
        let bind: SocketAddr = match upstream.remote {
            SocketAddr::V4(_) => "0.0.0.0:0".parse().unwrap(),
            SocketAddr::V6(_) => "[::]:0".parse().unwrap(),
        };
        let endpoint = Endpoint::client(bind)
            .await
            .context("binding HTTP/3 client UDP socket")?;
        let connection = endpoint
            .connect(upstream.remote, upstream.authority.host(), Some(client))
            .context("starting QUIC connection")?
            .await
            .context("completing QUIC handshake")?;
        let (mut h3, sender) = compio_quic::h3::client::new(connection)
            .await
            .context("starting HTTP/3 client connection")?;
        // The connection driver owns HTTP/3 control-stream progress for every
        // cloned sender. It stops when the last sender is dropped.
        let closed = Rc::new(Cell::new(false));
        let driver_closed = closed.clone();
        compio::runtime::spawn(async move {
            let _ = h3.wait_idle().await;
            driver_closed.set(true);
        })
        .detach();
        Ok(Self {
            endpoint,
            sender,
            authority: upstream.authority.clone(),
            closed,
        })
    }

    pub fn is_closed(&self) -> bool {
        self.closed.get()
    }

    pub async fn request(&self, request: H3Request) -> Result<H3Response> {
        if self.is_closed() {
            bail!("HTTP/3 upstream connection is closed");
        }
        validate_content_length(&request.headers, request.body.len())?;
        let uri = pinned_uri(&self.authority, &request.uri)?;
        let headers = h3_headers(request.headers);
        let message = hyper::http::Request::builder()
            .method(request.method)
            .uri(uri)
            .body(())
            .context("building pinned HTTP/3 request")?;
        let (mut parts, ()) = message.into_parts();
        parts.headers = headers;
        let mut stream = self
            .sender
            .clone()
            .send_request(hyper::http::Request::from_parts(parts, ()))
            .await
            .context("sending HTTP/3 request headers")?;
        if !request.body.is_empty() {
            stream
                .send_data(request.body)
                .await
                .context("sending HTTP/3 request body")?;
        }
        if let Some(trailers) = request.trailers {
            stream
                .send_trailers(trailers)
                .await
                .context("sending HTTP/3 request trailers")?;
        } else {
            stream.finish().await.context("finishing HTTP/3 request")?;
        }
        let response = stream
            .recv_response()
            .await
            .context("reading HTTP/3 response headers")?;
        let keepalive = self.sender.clone();
        let endpoint = self.endpoint.clone();
        let body = stream::unfold(
            Some((Some(stream), keepalive, endpoint)),
            |state| async move {
                let (stream, keepalive, endpoint) = state?;
                let Some(mut stream) = stream else {
                    drop(keepalive);
                    return None;
                };
                match stream.recv_data().await {
                    Ok(Some(mut data)) => Some((
                        Ok(H3BodyFrame::Data(data.copy_to_bytes(data.remaining()))),
                        Some((Some(stream), keepalive, endpoint)),
                    )),
                    Ok(None) => match stream.recv_trailers().await {
                        Ok(Some(trailers)) => Some((
                            Ok(H3BodyFrame::Trailers(trailers)),
                            Some((None, keepalive, endpoint)),
                        )),
                        Ok(None) => None,
                        Err(error) => {
                            Some((Err(error).context("reading HTTP/3 response trailers"), None))
                        }
                    },
                    Err(error) => Some((Err(error).context("reading HTTP/3 response body"), None)),
                }
            },
        );
        Ok(H3Response {
            response,
            body: Box::pin(body),
        })
    }

    pub async fn shutdown(self) -> Result<()> {
        let Self {
            endpoint, sender, ..
        } = self;
        drop(sender);
        endpoint
            .shutdown()
            .await
            .context("shutting down HTTP/3 client endpoint")
    }
}

/// A complete HTTP/3 request. Requests are collected before forwarding.
#[derive(Clone, Debug)]
pub struct H3Request {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub trailers: Option<HeaderMap>,
}

pub struct H3Response {
    pub response: Response<()>,
    /// A flow-controlled sequence of body chunks followed by optional trailers.
    /// The producer is polled only while the downstream QUIC stream can accept
    /// data, so a slow client cannot make this layer accumulate a response.
    pub body: H3Body,
}

pub type H3Body = Pin<Box<dyn Stream<Item = Result<H3BodyFrame>> + 'static>>;

#[derive(Debug)]
pub enum H3BodyFrame {
    Data(Bytes),
    Trailers(HeaderMap),
}

impl H3Response {
    pub fn from_bytes(response: Response<()>, body: Bytes, trailers: Option<HeaderMap>) -> Self {
        let frames = (!body.is_empty())
            .then_some(H3BodyFrame::Data(body))
            .into_iter()
            .chain(trailers.map(H3BodyFrame::Trailers));
        Self {
            response,
            body: Box::pin(stream::iter(frames.map(Ok))),
        }
    }
}

/// Information available to an access policy or request classifier before it
/// chooses a response. The SNI check has already completed when this runs.
#[derive(Clone, Debug)]
pub struct H3RequestContext {
    pub peer: SocketAddr,
    pub sni: Option<String>,
}

/// A TLS-1.3-only HTTP/3 listener. It never accepts 0-RTT data.
#[derive(Clone, Debug)]
pub struct H3Listener {
    endpoint: Endpoint,
    expected_sni: Option<String>,
}

impl H3Listener {
    /// Bind an HTTP/3 listener with TLS 1.3 and 0-RTT disabled.
    pub async fn bind(
        bind: SocketAddr,
        identity: TlsIdentity,
        expected_sni: Option<String>,
    ) -> Result<Self> {
        let mut tls =
            rustls::ServerConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_no_client_auth()
                .with_single_cert(identity.certificate_chain, identity.private_key)
                .context("building HTTP/3 server certificate configuration")?;
        tls.alpn_protocols = vec![H3_ALPN.as_bytes().to_vec()];
        // compio-quic's convenience builder enables early data. Build the
        // rustls config ourselves so inbound requests always follow the full
        // handshake.
        tls.max_early_data_size = 0;
        Self::bind_with_tls_config(bind, Arc::new(tls), expected_sni).await
    }

    /// Bind with a caller-provided rustls configuration. This supports a
    /// ClientHello-driven certificate resolver for intercepted HTTP/3.
    pub async fn bind_with_tls_config(
        bind: SocketAddr,
        tls: Arc<rustls::ServerConfig>,
        expected_sni: Option<String>,
    ) -> Result<Self> {
        let config = ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from((*tls).clone()).context("converting TLS config for QUIC")?,
        ));
        let endpoint = Endpoint::server(bind, config)
            .await
            .context("binding HTTP/3 UDP socket")?;
        Ok(Self {
            endpoint,
            expected_sni,
        })
    }

    /// Accept a completed QUIC handshake. Request serving is intentionally a
    /// separate step so the lifecycle owner can supervise each connection.
    pub async fn accept(&self) -> Result<H3Connection> {
        let incoming = self
            .endpoint
            .wait_incoming()
            .await
            .ok_or_else(|| anyhow!("HTTP/3 listener is closed"))?;
        let peer = incoming.remote_address();
        let mut connection = incoming.await.context("completing QUIC handshake")?;
        let handshake = connection
            .handshake_data()
            .context("reading TLS handshake data")?;
        if handshake.protocol.as_deref() != Some(H3_ALPN.as_bytes()) {
            bail!("peer did not negotiate HTTP/3 ALPN");
        }
        if let Some(expected) = &self.expected_sni
            && handshake.server_name.as_deref() != Some(expected.as_str())
        {
            bail!("client SNI does not match the listener authority");
        }
        Ok(H3Connection {
            connection,
            context: H3RequestContext {
                peer,
                sni: handshake.server_name,
            },
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint
            .local_addr()
            .context("reading HTTP/3 listener address")
    }

    /// Accept and serve one QUIC connection.
    pub async fn serve_next<F, Fut>(&self, handler: F) -> Result<()>
    where
        F: Fn(H3RequestContext, H3Request) -> Fut + Clone + 'static,
        Fut: Future<Output = Result<H3Response>> + 'static,
    {
        self.accept().await?.serve(handler).await
    }

    pub fn close(&self) {
        self.endpoint.close(0u32.into(), b"shutdown");
    }

    pub async fn shutdown(self) -> Result<()> {
        self.endpoint
            .shutdown()
            .await
            .context("shutting down HTTP/3 listener")
    }
}

/// A handshaken connection, ready to be served by the proxy lifecycle.
pub struct H3Connection {
    connection: Connection,
    context: H3RequestContext,
}
impl H3Connection {
    pub async fn serve<F, Fut>(self, handler: F) -> Result<()>
    where
        F: Fn(H3RequestContext, H3Request) -> Fut + Clone + 'static,
        Fut: Future<Output = Result<H3Response>> + 'static,
    {
        let context = self.context;
        let mut h3 = compio_quic::h3::server::builder()
            .build::<_, Bytes>(self.connection)
            .await
            .context("starting HTTP/3 server connection")?;
        let mut requests = FuturesUnordered::<compio::runtime::JoinHandle<Result<()>>>::new();
        loop {
            let accepted = if requests.is_empty() {
                h3.accept().await
            } else {
                let accept = h3.accept();
                futures_util::pin_mut!(accept);
                match select(accept, requests.next()).await {
                    Either::Left((accepted, _)) => accepted,
                    Either::Right((completed, _)) => {
                        let _ = completed.expect("nonempty request task set");
                        continue;
                    }
                }
            };
            let resolver = match accepted {
                Ok(Some(resolver)) => resolver,
                // Drop the outstanding task set when the peer closes. Compio
                // cancels dropped join handles, so a stalled upstream handler
                // cannot keep this downstream connection alive.
                Ok(None) => return Ok(()),
                // h3 reports a peer's clean H3_NO_ERROR close as an error.
                Err(error) if error.is_h3_no_error() => return Ok(()),
                Err(error) => return Err(error).context("accepting HTTP/3 request"),
            };
            let context = context.clone();
            let handler = handler.clone();
            requests.push(compio::runtime::spawn(async move {
                let (request, mut stream) = resolver
                    .resolve_request()
                    .await
                    .context("reading HTTP/3 request headers")?;
                let expected_request_length = content_length(request.headers())?;
                let body = read_body(&mut stream, expected_request_length).await?;
                let trailers = stream
                    .recv_trailers()
                    .await
                    .context("reading HTTP/3 request trailers")?;
                validate_content_length(request.headers(), body.len())?;
                if let Some(sni) = context.sni.as_deref()
                    && request.uri().authority().map(|authority| authority.host()) != Some(sni)
                {
                    bail!("HTTP/3 request authority does not match ClientHello SNI");
                }
                let reply = handler(
                    context,
                    H3Request {
                        method: request.method().clone(),
                        uri: request.uri().clone(),
                        headers: request.headers().clone(),
                        body,
                        trailers,
                    },
                )
                .await?;
                let expected = response_body_length(
                    reply.response.headers(),
                    request.method(),
                    reply.response.status(),
                )?;
                let allows_body = response_allows_body(request.method(), reply.response.status());
                stream
                    .send_response(reply.response)
                    .await
                    .context("sending HTTP/3 response headers")?;
                if allows_body {
                    send_body(&mut stream, reply.body, expected).await
                } else {
                    stream.finish().await.context("finishing HTTP/3 response")
                }
            }));
        }
    }
}

/// Send one direct HTTP/3 request. Response headers are returned before its
/// body is read. Dropping the body cancels its client endpoint.
pub async fn request(upstream: &H3Upstream, request: H3Request) -> Result<H3Response> {
    H3Client::connect(upstream).await?.request(request).await
}

async fn send_body<S>(stream: &mut S, mut body: H3Body, expected: Option<usize>) -> Result<()>
where
    S: H3Writable,
{
    let mut length = 0usize;
    let mut trailers_sent = false;
    while let Some(frame) = body.next().await {
        match frame? {
            H3BodyFrame::Data(data) => {
                if trailers_sent {
                    bail!("HTTP/3 body data follows trailers");
                }
                length = length
                    .checked_add(data.len())
                    .context("HTTP/3 response body is too large")?;
                stream.send_data(data).await?;
            }
            H3BodyFrame::Trailers(trailers) => {
                if trailers_sent {
                    bail!("HTTP/3 response has multiple trailer blocks");
                }
                trailers_sent = true;
                stream.send_trailers(trailers).await?;
            }
        }
    }
    if let Some(expected) = expected
        && length != expected
    {
        bail!("content-length is {expected}, but body has {length} bytes");
    }
    if !trailers_sent {
        stream.finish().await?;
    }
    Ok(())
}

fn client_config(mut tls: rustls::ClientConfig) -> Result<ClientConfig> {
    tls.alpn_protocols = vec![H3_ALPN.as_bytes().to_vec()];
    tls.enable_early_data = false;
    Ok(ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls).context("converting TLS client config for QUIC")?,
    )))
}

fn pinned_uri(authority: &hyper::http::uri::Authority, original: &Uri) -> Result<Uri> {
    if let Some(actual) = original.authority()
        && actual != authority
    {
        bail!("request authority differs from pinned upstream authority");
    }
    let path = original
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or("/");
    Uri::builder()
        .scheme("https")
        .authority(authority.as_str())
        .path_and_query(path)
        .build()
        .context("building pinned request URI")
}

fn h3_headers(headers: HeaderMap) -> HeaderMap {
    let mut headers = headers;
    // HTTP/3 forbids connection-specific fields. Host is redundant because
    // h3 derives :authority from the pinned URI.
    for name in [
        header::CONNECTION,
        header::HOST,
        header::TRANSFER_ENCODING,
        header::UPGRADE,
        hyper::http::HeaderName::from_static("keep-alive"),
        header::PROXY_AUTHENTICATE,
        header::PROXY_AUTHORIZATION,
    ] {
        headers.remove(name);
    }
    headers
}

async fn read_body<S>(stream: &mut S, expected: Option<usize>) -> Result<Bytes>
where
    S: H3Readable,
{
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.next_data().await? {
        let length = body
            .len()
            .checked_add(chunk.remaining())
            .context("HTTP/3 request body is too large")?;
        if let Some(expected) = expected
            && length > expected
        {
            bail!("content-length is {expected}, but request body exceeds it");
        }
        body.extend_from_slice(&chunk.copy_to_bytes(chunk.remaining()));
    }
    Ok(Bytes::from(body))
}

/// The two h3 request stream types expose the same receive operation but do
/// not share a public trait. This small adapter keeps the protocol code above
/// independent of h3's internal stream names.
trait H3Readable {
    type Chunk: Buf;
    fn next_data(&mut self) -> impl Future<Output = Result<Option<Self::Chunk>>>;
}

trait H3Writable {
    fn send_data(&mut self, data: Bytes) -> impl Future<Output = Result<()>>;
    fn send_trailers(&mut self, trailers: HeaderMap) -> impl Future<Output = Result<()>>;
    fn finish(&mut self) -> impl Future<Output = Result<()>>;
}

impl<S> H3Writable for compio_quic::h3::server::RequestStream<S, Bytes>
where
    S: compio_quic::h3::quic::SendStream<Bytes>,
{
    async fn send_data(&mut self, data: Bytes) -> Result<()> {
        self.send_data(data)
            .await
            .context("sending HTTP/3 response body")
    }
    async fn send_trailers(&mut self, trailers: HeaderMap) -> Result<()> {
        self.send_trailers(trailers)
            .await
            .context("sending HTTP/3 response trailers")
    }
    async fn finish(&mut self) -> Result<()> {
        self.finish().await.context("finishing HTTP/3 response")
    }
}

impl<S> H3Readable for compio_quic::h3::client::RequestStream<S, Bytes>
where
    S: compio_quic::h3::quic::RecvStream,
{
    type Chunk = Bytes;
    async fn next_data(&mut self) -> Result<Option<Self::Chunk>> {
        self.recv_data()
            .await
            .map(|chunk| chunk.map(|mut value| value.copy_to_bytes(value.remaining())))
            .context("reading HTTP/3 response body")
    }
}

impl<S> H3Readable for compio_quic::h3::server::RequestStream<S, Bytes>
where
    S: compio_quic::h3::quic::RecvStream,
{
    type Chunk = Bytes;
    async fn next_data(&mut self) -> Result<Option<Self::Chunk>> {
        self.recv_data()
            .await
            .map(|chunk| chunk.map(|mut value| value.copy_to_bytes(value.remaining())))
            .context("reading HTTP/3 request body")
    }
}

fn validate_content_length(headers: &HeaderMap, actual: usize) -> Result<()> {
    let Some(expected) = content_length(headers)? else {
        return Ok(());
    };
    if expected != actual {
        bail!("content-length is {expected}, but body has {actual} bytes");
    }
    Ok(())
}

fn content_length(headers: &HeaderMap) -> Result<Option<usize>> {
    headers
        .get(header::CONTENT_LENGTH)
        .map(|value| {
            value
                .to_str()
                .context("invalid content-length header")?
                .parse::<usize>()
                .context("invalid content-length value")
        })
        .transpose()
}

fn response_body_length(
    headers: &HeaderMap,
    method: &Method,
    status: hyper::StatusCode,
) -> Result<Option<usize>> {
    if !response_allows_body(method, status) {
        return Ok(None);
    }
    content_length(headers)
}

fn response_allows_body(method: &Method, status: hyper::StatusCode) -> bool {
    method != Method::HEAD
        && status != hyper::StatusCode::NOT_MODIFIED
        && status != hyper::StatusCode::NO_CONTENT
}

#[cfg(test)]
mod tests {
    use super::*;
    use compio::runtime;
    use std::{
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::{Duration, Instant},
    };

    #[test]
    fn rejects_a_mismatched_pinned_authority() {
        let authority = "good.test".parse().unwrap();
        assert!(pinned_uri(&authority, &"https://bad.test/path".parse().unwrap()).is_err());
    }

    #[test]
    fn pinned_uri_adds_https_authority_and_preserves_origin_form_target() {
        let authority = "upstream.test:8443".parse().unwrap();
        let uri = pinned_uri(&authority, &"/search?q=rust".parse().unwrap()).unwrap();

        assert_eq!(
            uri,
            "https://upstream.test:8443/search?q=rust"
                .parse::<Uri>()
                .unwrap()
        );
    }

    #[test]
    fn pinned_uri_uses_root_path_when_original_has_no_path() {
        let authority = "upstream.test".parse().unwrap();
        let uri = pinned_uri(&authority, &"https://upstream.test".parse().unwrap()).unwrap();

        assert_eq!(uri, "https://upstream.test/".parse::<Uri>().unwrap());
    }

    #[test]
    fn pinned_uri_accepts_the_pinned_absolute_authority() {
        let authority = "upstream.test".parse().unwrap();
        let uri = pinned_uri(
            &authority,
            &"http://upstream.test/resource?version=2".parse().unwrap(),
        )
        .unwrap();

        assert_eq!(
            uri,
            "https://upstream.test/resource?version=2"
                .parse::<Uri>()
                .unwrap()
        );
    }

    #[test]
    fn h3_headers_removes_connection_specific_and_host_fields() {
        let mut headers = HeaderMap::new();
        for name in [
            header::CONNECTION,
            header::HOST,
            header::TRANSFER_ENCODING,
            header::UPGRADE,
            hyper::http::HeaderName::from_static("keep-alive"),
            header::PROXY_AUTHENTICATE,
            header::PROXY_AUTHORIZATION,
        ] {
            headers.insert(name, "remove-me".parse().unwrap());
        }
        headers.insert(
            header::CONTENT_TYPE,
            "application/octet-stream".parse().unwrap(),
        );
        headers.insert("x-request-id", "abc123".parse().unwrap());

        let filtered = h3_headers(headers);

        assert_eq!(filtered.len(), 2);
        assert_eq!(
            filtered.get(header::CONTENT_TYPE).unwrap(),
            "application/octet-stream"
        );
        assert_eq!(filtered.get("x-request-id").unwrap(), "abc123");
    }

    #[test]
    fn h3_headers_keeps_non_connection_headers() {
        let headers = [
            (header::ACCEPT, "application/json".parse().unwrap()),
            (header::CONTENT_LENGTH, "0".parse().unwrap()),
        ]
        .into_iter()
        .collect();

        assert_eq!(
            h3_headers(headers),
            [
                (header::ACCEPT, "application/json".parse().unwrap()),
                (header::CONTENT_LENGTH, "0".parse().unwrap()),
            ]
            .into_iter()
            .collect()
        );
    }

    #[test]
    fn accepts_matching_or_absent_content_length() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, "4".parse().unwrap());
        assert!(validate_content_length(&headers, 4).is_ok());
        assert!(validate_content_length(&HeaderMap::new(), 99).is_ok());
    }

    #[test]
    fn rejects_malformed_content_length() {
        let mut non_numeric = HeaderMap::new();
        non_numeric.insert(header::CONTENT_LENGTH, "four".parse().unwrap());
        assert!(validate_content_length(&non_numeric, 4).is_err());

        let mut non_text = HeaderMap::new();
        non_text.insert(
            header::CONTENT_LENGTH,
            hyper::http::HeaderValue::from_bytes(b"\xff").unwrap(),
        );
        assert!(validate_content_length(&non_text, 4).is_err());
    }

    #[test]
    fn detects_content_length_corruption() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, "4".parse().unwrap());
        assert!(validate_content_length(&headers, 3).is_err());
    }

    #[test]
    fn allows_content_length_metadata_on_head_and_not_modified_responses() {
        let mut headers = HeaderMap::new();
        headers.insert(header::CONTENT_LENGTH, "42".parse().unwrap());
        assert_eq!(
            response_body_length(&headers, &Method::HEAD, hyper::StatusCode::OK).unwrap(),
            None
        );
        assert_eq!(
            response_body_length(&headers, &Method::GET, hyper::StatusCode::NOT_MODIFIED).unwrap(),
            None
        );
        assert_eq!(
            response_body_length(&headers, &Method::GET, hyper::StatusCode::OK).unwrap(),
            Some(42)
        );
    }

    #[test]
    fn loopback_h3_preserves_request_and_response_bytes() {
        runtime::Runtime::new().unwrap().block_on(async {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert_der = cert.der().clone();
            let identity = TlsIdentity {
                certificate_chain: vec![cert_der.clone()],
                private_key: signing_key.serialize_der().try_into().unwrap(),
            };
            let listener = H3Listener::bind(
                "127.0.0.1:0".parse().unwrap(),
                identity,
                Some("localhost".into()),
            )
            .await
            .unwrap();
            let address = listener.local_addr().unwrap();
            let server = runtime::spawn(async move {
                listener
                    .serve_next(|context, request| async move {
                        assert_eq!(context.sni.as_deref(), Some("localhost"));
                        assert_eq!(request.method, Method::POST);
                        assert_eq!(request.body, Bytes::from_static(b"ping"));
                        Ok(H3Response::from_bytes(
                            Response::builder()
                                .status(201)
                                .header(header::CONTENT_LENGTH, "4")
                                .body(())
                                .unwrap(),
                            Bytes::from_static(b"pong"),
                            None,
                        ))
                    })
                    .await
            });
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert_der).unwrap();
            let tls =
                rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .with_root_certificates(roots)
                    .with_no_client_auth();
            let response = request(
                &H3Upstream {
                    remote: address,
                    authority: "localhost".parse().unwrap(),
                    tls,
                },
                H3Request {
                    method: Method::POST,
                    uri: "/echo".parse().unwrap(),
                    headers: [(header::CONTENT_LENGTH, "4".parse().unwrap())]
                        .into_iter()
                        .collect(),
                    body: Bytes::from_static(b"ping"),
                    trailers: None,
                },
            )
            .await
            .unwrap();
            assert_eq!(response.response.status(), 201);
            let body = response.body.collect::<Vec<_>>().await;
            assert!(
                matches!(body.as_slice(), [Ok(H3BodyFrame::Data(data))] if data.as_ref() == b"pong")
            );
            server.await.unwrap().unwrap();
        });
    }

    #[test]
    fn loopback_h3_returns_headers_before_a_delayed_body() {
        runtime::Runtime::new().unwrap().block_on(async {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert_der = cert.der().clone();
            let listener = H3Listener::bind(
                "127.0.0.1:0".parse().unwrap(),
                TlsIdentity { certificate_chain: vec![cert_der.clone()], private_key: signing_key.serialize_der().try_into().unwrap() },
                Some("localhost".into()),
            ).await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = runtime::spawn(async move {
                listener.serve_next(|_, _| async {
                    let delayed = stream::once(async {
                        compio::time::sleep(Duration::from_millis(100)).await;
                        Ok(H3BodyFrame::Data(Bytes::from_static(b"body")))
                    });
                    Ok(H3Response {
                        response: Response::builder().status(200).header(header::CONTENT_LENGTH, "4").body(()).unwrap(),
                        body: Box::pin(delayed),
                    })
                }).await
            });
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert_der).unwrap();
            let tls = rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                .with_root_certificates(roots).with_no_client_auth();
            let started = Instant::now();
            let response = request(&H3Upstream { remote: address, authority: "localhost".parse().unwrap(), tls }, H3Request {
                method: Method::GET, uri: "/slow".parse().unwrap(), headers: HeaderMap::new(), body: Bytes::new(), trailers: None,
            }).await.unwrap();
            assert_eq!(response.response.status(), 200);
            assert!(started.elapsed() < Duration::from_millis(80), "response headers waited for the body");
            let frames = response.body.collect::<Vec<_>>().await;
            assert!(matches!(frames.as_slice(), [Ok(H3BodyFrame::Data(data))] if data.as_ref() == b"body"));
            assert!(started.elapsed() >= Duration::from_millis(100));
            server.await.unwrap().unwrap();
        });
    }

    #[test]
    fn reusable_client_sends_multiple_requests_on_one_connection() {
        runtime::Runtime::new().unwrap().block_on(async {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert_der = cert.der().clone();
            let listener = H3Listener::bind(
                "127.0.0.1:0".parse().unwrap(),
                TlsIdentity {
                    certificate_chain: vec![cert_der.clone()],
                    private_key: signing_key.serialize_der().try_into().unwrap(),
                },
                Some("localhost".into()),
            )
            .await
            .unwrap();
            let address = listener.local_addr().unwrap();
            let requests = Arc::new(AtomicUsize::new(0));
            let server_requests = requests.clone();
            let server = runtime::spawn(async move {
                listener
                    .serve_next(move |_, _| {
                        let requests = server_requests.clone();
                        async move {
                            requests.fetch_add(1, Ordering::Relaxed);
                            Ok(H3Response::from_bytes(
                                Response::builder()
                                    .status(200)
                                    .header(header::CONTENT_LENGTH, "2")
                                    .body(())
                                    .unwrap(),
                                Bytes::from_static(b"ok"),
                                None,
                            ))
                        }
                    })
                    .await
            });
            let mut roots = rustls::RootCertStore::empty();
            roots.add(cert_der).unwrap();
            let upstream = H3Upstream {
                remote: address,
                authority: "localhost".parse().unwrap(),
                tls: rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13])
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            };
            let client = H3Client::connect(&upstream).await.unwrap();
            for path in ["/one", "/two"] {
                let response = client
                    .request(H3Request {
                        method: Method::GET,
                        uri: path.parse().unwrap(),
                        headers: HeaderMap::new(),
                        body: Bytes::new(),
                        trailers: None,
                    })
                    .await
                    .unwrap();
                assert!(matches!(response.body.collect::<Vec<_>>().await.as_slice(), [Ok(H3BodyFrame::Data(body))] if body.as_ref() == b"ok"));
            }
            client.shutdown().await.unwrap();
            server.await.unwrap().unwrap();
            assert_eq!(requests.load(Ordering::Relaxed), 2);
        });
    }

    #[test]
    fn same_connection_fast_request_is_not_blocked_by_a_slow_handler() {
        runtime::Runtime::new().unwrap().block_on(async {
            let rcgen::CertifiedKey { cert, signing_key } =
                rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert_der = cert.der().clone();
            let listener = H3Listener::bind(
                "127.0.0.1:0".parse().unwrap(),
                TlsIdentity { certificate_chain: vec![cert_der.clone()], private_key: signing_key.serialize_der().try_into().unwrap() },
                Some("localhost".into()),
            ).await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = runtime::spawn(async move {
                listener.serve_next(|_, request| async move {
                    if request.uri.path() == "/slow" { compio::time::sleep(Duration::from_millis(150)).await; }
                    Ok(H3Response::from_bytes(Response::builder().status(200).header(header::CONTENT_LENGTH, "2").body(()).unwrap(), Bytes::from_static(b"ok"), None))
                }).await
            });
            let mut roots = rustls::RootCertStore::empty(); roots.add(cert_der).unwrap();
            let upstream = H3Upstream { remote: address, authority: "localhost".parse().unwrap(), tls: rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]).with_root_certificates(roots).with_no_client_auth() };
            let client = H3Client::connect(&upstream).await.unwrap();
            let request = |path: &str| H3Request { method: Method::GET, uri: path.parse().unwrap(), headers: HeaderMap::new(), body: Bytes::new(), trailers: None };
            let started = Instant::now();
            let fast = Box::pin(client.request(request("/fast")));
            let slow = Box::pin(client.request(request("/slow")));
            let (fast, slow) = match select(fast, slow).await {
                Either::Left((fast, slow)) => (fast.unwrap(), slow),
                Either::Right(_) => panic!("slow request completed before the fast request"),
            };
            assert!(started.elapsed() < Duration::from_millis(100), "fast request waited for slow handler");
            assert!(matches!(fast.body.collect::<Vec<_>>().await.as_slice(), [Ok(H3BodyFrame::Data(body))] if body.as_ref() == b"ok"));
            let slow = slow.await.unwrap();
            assert!(matches!(slow.body.collect::<Vec<_>>().await.as_slice(), [Ok(H3BodyFrame::Data(body))] if body.as_ref() == b"ok"));
            client.shutdown().await.unwrap();
            server.await.unwrap().unwrap();
        });
    }

    #[test]
    fn resetting_one_response_stream_does_not_abort_another() {
        runtime::Runtime::new().unwrap().block_on(async {
            let rcgen::CertifiedKey { cert, signing_key } = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
            let cert_der = cert.der().clone();
            let listener = H3Listener::bind("127.0.0.1:0".parse().unwrap(), TlsIdentity { certificate_chain: vec![cert_der.clone()], private_key: signing_key.serialize_der().try_into().unwrap() }, Some("localhost".into())).await.unwrap();
            let address = listener.local_addr().unwrap();
            let server = runtime::spawn(async move {
                listener.serve_next(|_, request| async move {
                    if request.uri.path() == "/cancel" {
                        return Ok(H3Response { response: Response::builder().status(200).header(header::CONTENT_LENGTH, "4").body(()).unwrap(), body: Box::pin(stream::once(async { compio::time::sleep(Duration::from_millis(80)).await; Ok(H3BodyFrame::Data(Bytes::from_static(b"late"))) })) });
                    }
                    Ok(H3Response::from_bytes(Response::builder().status(200).header(header::CONTENT_LENGTH, "2").body(()).unwrap(), Bytes::from_static(b"ok"), None))
                }).await
            });
            let mut roots = rustls::RootCertStore::empty(); roots.add(cert_der).unwrap();
            let upstream = H3Upstream { remote: address, authority: "localhost".parse().unwrap(), tls: rustls::ClientConfig::builder_with_protocol_versions(&[&rustls::version::TLS13]).with_root_certificates(roots).with_no_client_auth() };
            let client = H3Client::connect(&upstream).await.unwrap();
            let cancelled = client.request(H3Request { method: Method::GET, uri: "/cancel".parse().unwrap(), headers: HeaderMap::new(), body: Bytes::new(), trailers: None }).await.unwrap();
            drop(cancelled);
            compio::time::sleep(Duration::from_millis(120)).await;
            let response = client.request(H3Request { method: Method::GET, uri: "/ok".parse().unwrap(), headers: HeaderMap::new(), body: Bytes::new(), trailers: None }).await.unwrap();
            assert!(matches!(response.body.collect::<Vec<_>>().await.as_slice(), [Ok(H3BodyFrame::Data(body))] if body.as_ref() == b"ok"));
            client.shutdown().await.unwrap();
            server.await.unwrap().unwrap();
        });
    }
}
