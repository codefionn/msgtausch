//! QUIC and HTTP/3 transport primitives.
//!
//! This module deliberately owns the HTTP/3 boundary.  Callers hand it an
//! already-resolved UDP address and an authority.  The authority is used for
//! both TLS SNI and the HTTP/3 `:authority` pseudo-header, so a request cannot
//! accidentally be authenticated for one host and sent as another.

use std::{future::Future, net::SocketAddr, sync::Arc};

use anyhow::{Context, Result, anyhow, bail};
use bytes::{Buf, Bytes};
use compio_quic::{
    ClientConfig, Connection, Endpoint, ServerConfig,
    crypto::rustls::{QuicClientConfig, QuicServerConfig},
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

/// A complete HTTP message. HTTP/3 has no chunk framing, so preserving the
/// body as bytes makes the content-length check unambiguous at this boundary.
#[derive(Clone, Debug)]
pub struct H3Request {
    pub method: Method,
    pub uri: Uri,
    pub headers: HeaderMap,
    pub body: Bytes,
    pub trailers: Option<HeaderMap>,
}

#[derive(Clone, Debug)]
pub struct H3Response {
    pub response: Response<()>,
    pub body: Bytes,
    pub trailers: Option<HeaderMap>,
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

    /// Accept and serve one QUIC connection. Requests on the connection are
    /// handled in order, which gives callers one simple classifier seam.
    pub async fn serve_next<F, Fut>(&self, handler: F) -> Result<()>
    where
        F: Fn(H3RequestContext, H3Request) -> Fut,
        Fut: Future<Output = Result<H3Response>>,
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
        F: Fn(H3RequestContext, H3Request) -> Fut,
        Fut: Future<Output = Result<H3Response>>,
    {
        let context = self.context;
        let mut h3 = compio_quic::h3::server::builder()
            .build::<_, Bytes>(self.connection)
            .await
            .context("starting HTTP/3 server connection")?;
        loop {
            let resolver = match h3.accept().await {
                Ok(Some(resolver)) => resolver,
                Ok(None) => break,
                // h3 reports a peer's clean H3_NO_ERROR close as an error.
                Err(error) if error.is_h3_no_error() => break,
                Err(error) => return Err(error).context("accepting HTTP/3 request"),
            };
            let (request, mut stream) = resolver
                .resolve_request()
                .await
                .context("reading HTTP/3 request headers")?;
            let body = read_body(&mut stream).await?;
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
                context.clone(),
                H3Request {
                    method: request.method().clone(),
                    uri: request.uri().clone(),
                    headers: request.headers().clone(),
                    body,
                    trailers,
                },
            )
            .await?;
            validate_content_length(reply.response.headers(), reply.body.len())?;
            stream
                .send_response(reply.response)
                .await
                .context("sending HTTP/3 response headers")?;
            if !reply.body.is_empty() {
                stream
                    .send_data(reply.body)
                    .await
                    .context("sending HTTP/3 response body")?;
            }
            if let Some(trailers) = reply.trailers {
                stream
                    .send_trailers(trailers)
                    .await
                    .context("sending HTTP/3 response trailers")?;
            } else {
                stream.finish().await.context("finishing HTTP/3 response")?;
            }
        }
        Ok(())
    }
}

/// Send one direct HTTP/3 request. The endpoint is shut down after the
/// response is fully read, avoiding a hidden connection pool at this layer.
pub async fn request(upstream: &H3Upstream, request: H3Request) -> Result<H3Response> {
    validate_content_length(&request.headers, request.body.len())?;
    let uri = pinned_uri(&upstream.authority, &request.uri)?;
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
    let response = request_on_connection(connection, uri, request).await;
    endpoint
        .shutdown()
        .await
        .context("shutting down HTTP/3 client endpoint")?;
    response
}

async fn request_on_connection(
    connection: Connection,
    uri: Uri,
    request: H3Request,
) -> Result<H3Response> {
    let (mut h3, mut sender) = compio_quic::h3::client::new(connection)
        .await
        .context("starting HTTP/3 client connection")?;
    // h3 keeps its control streams and response processing on this driver.
    // The request stream alone cannot make progress without it.
    let driver = compio::runtime::spawn(async move { h3.wait_idle().await });
    let headers = h3_headers(request.headers);
    let message = hyper::http::Request::builder()
        .method(request.method)
        .uri(uri)
        .body(())
        .context("building pinned HTTP/3 request")?;
    let (mut parts, ()) = message.into_parts();
    parts.headers = headers;
    let mut stream = sender
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
    let body = read_body(&mut stream).await?;
    let trailers = stream
        .recv_trailers()
        .await
        .context("reading HTTP/3 response trailers")?;
    validate_content_length(response.headers(), body.len())?;
    drop(stream);
    drop(sender);
    let _ = driver
        .await
        .map_err(|error| anyhow!("joining HTTP/3 client driver failed: {error:?}"))?;
    Ok(H3Response {
        response,
        body,
        trailers,
    })
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

async fn read_body<S>(stream: &mut S) -> Result<Bytes>
where
    S: H3Readable,
{
    let mut body = Vec::new();
    while let Some(mut chunk) = stream.next_data().await? {
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
    let Some(value) = headers.get(header::CONTENT_LENGTH) else {
        return Ok(());
    };
    let expected = value
        .to_str()
        .context("invalid content-length header")?
        .parse::<usize>()
        .context("invalid content-length value")?;
    if expected != actual {
        bail!("content-length is {expected}, but body has {actual} bytes");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use compio::runtime;

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
                        Ok(H3Response {
                            response: Response::builder()
                                .status(201)
                                .header(header::CONTENT_LENGTH, "4")
                                .body(())
                                .unwrap(),
                            body: Bytes::from_static(b"pong"),
                            trailers: None,
                        })
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
            assert_eq!(response.body, Bytes::from_static(b"pong"));
            server.await.unwrap().unwrap();
        });
    }
}
