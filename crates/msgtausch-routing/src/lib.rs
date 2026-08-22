//! Target connection setup for direct and chained proxy routes.

use std::{net::SocketAddr, sync::Arc, time::Duration};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use compio::{
    BufResult,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrsAsync},
    time::timeout,
};

use msgtausch_config::{DnsConfig, Forward, ForwardKind};
use msgtausch_policy::{ClassifierEngine, Target};
use msgtausch_resolver::Resolver;

/// The narrow route telemetry seam. Observability can attach bounded route
/// labels without pulling a metrics dependency into the connection code.
pub trait RouteMetrics: Send + Sync + 'static {
    fn route_selected(&self, route: &'static str);
    fn route_error(&self, route: &'static str);
}

#[derive(Default)]
pub struct NoopRouteMetrics;

impl RouteMetrics for NoopRouteMetrics {
    fn route_selected(&self, _: &'static str) {}
    fn route_error(&self, _: &'static str) {}
}

/// A first-match route selector and bounded connector.
#[derive(Clone)]
pub struct RoutePlanner {
    classifiers: Arc<ClassifierEngine>,
    connect_timeout: Duration,
    metrics: Arc<dyn RouteMetrics>,
    resolver: Option<Arc<Resolver>>,
}

impl RoutePlanner {
    pub fn new(
        classifiers: ClassifierEngine,
        timeout_seconds: u64,
        metrics: Arc<dyn RouteMetrics>,
    ) -> Self {
        Self {
            classifiers: Arc::new(classifiers),
            connect_timeout: Duration::from_secs(timeout_seconds.max(1)),
            metrics,
            resolver: None,
        }
    }

    /// Select explicit DNS servers for route connections. Existing callers can
    /// keep using `new` and therefore retain system resolution.
    pub fn with_dns(mut self, config: &DnsConfig) -> Self {
        self.resolver = Resolver::new(config).map(Arc::new);
        self
    }

    pub fn classifiers(&self) -> &ClassifierEngine {
        &self.classifiers
    }

    pub fn classifiers_shared(&self) -> Arc<ClassifierEngine> {
        self.classifiers.clone()
    }

    pub async fn connect(&self, target: &Target) -> Result<TcpStream> {
        let forward = self.classifiers.select_forward(target)?;
        log_forward(forward, target);
        let (route, outcome) = match forward {
            None => ("direct", self.connect_direct(target, false).await),
            Some(Forward {
                kind: ForwardKind::Direct,
                force_ipv4,
                ..
            }) => ("direct", self.connect_direct(target, *force_ipv4).await),
            Some(Forward {
                kind:
                    ForwardKind::Socks5 {
                        address,
                        username,
                        password,
                    },
                force_ipv4,
                ..
            }) => (
                "socks5",
                self.connect_socks5(
                    target,
                    address,
                    username.as_deref(),
                    password.as_deref(),
                    *force_ipv4,
                )
                .await,
            ),
            Some(Forward {
                kind:
                    ForwardKind::HttpProxy {
                        address,
                        username,
                        password,
                    },
                force_ipv4,
                ..
            }) => (
                "http_proxy",
                self.connect_http_proxy(
                    target,
                    address,
                    username.as_deref(),
                    password.as_deref(),
                    *force_ipv4,
                )
                .await,
            ),
        };
        self.metrics.route_selected(route);
        if outcome.is_err() {
            self.metrics.route_error(route);
        }
        outcome
    }

    /// Resolve a UDP/QUIC destination directly through the configured DNS
    /// servers. Chained TCP forwards are deliberately excluded: they cannot
    /// carry native QUIC datagrams without a separate tunnel transport.
    pub async fn resolve_direct(&self, target: &Target) -> Result<SocketAddr> {
        let forward = self.classifiers.select_forward(target)?;
        log_forward(forward, target);
        let (route, result) = match forward {
            None => (
                "direct",
                self.resolve_direct_address(&target.authority(), false)
                    .await,
            ),
            Some(Forward {
                kind: ForwardKind::Direct,
                force_ipv4,
                ..
            }) => (
                "direct",
                self.resolve_direct_address(&target.authority(), *force_ipv4)
                    .await,
            ),
            Some(Forward {
                kind: ForwardKind::Socks5 { .. },
                ..
            }) => (
                "socks5",
                Err(anyhow::anyhow!(
                    "QUIC does not support SOCKS5 forward routes"
                )),
            ),
            Some(Forward {
                kind: ForwardKind::HttpProxy { .. },
                ..
            }) => (
                "http_proxy",
                Err(anyhow::anyhow!(
                    "QUIC does not support HTTP proxy forward routes"
                )),
            ),
        };
        self.metrics.route_selected(route);
        if result.is_err() {
            self.metrics.route_error(route);
        }
        result
    }

    async fn resolve_direct_address(&self, address: &str, force_ipv4: bool) -> Result<SocketAddr> {
        let (host, port) = split_authority(address)?;
        if let Ok(ip) = host.parse() {
            return Ok(SocketAddr::new(ip, port));
        }
        if let Some(resolver) = &self.resolver {
            return resolver
                .lookup(host)
                .await?
                .into_iter()
                .find(|ip| !force_ipv4 || ip.is_ipv4())
                .map(|ip| SocketAddr::new(ip, port))
                .context("DNS returned no usable address");
        }
        address
            .to_socket_addrs_async()
            .await?
            .find(|address| !force_ipv4 || address.is_ipv4())
            .context("system DNS returned no usable address")
    }

    async fn connect_direct(&self, target: &Target, force_ipv4: bool) -> Result<TcpStream> {
        self.connect_address(&target.authority(), force_ipv4).await
    }

    async fn connect_socks5(
        &self,
        target: &Target,
        proxy: &str,
        username: Option<&str>,
        password: Option<&str>,
        force_ipv4: bool,
    ) -> Result<TcpStream> {
        // SOCKS permits the proxy to resolve the target. For an IPv4-only
        // rule we resolve it here and send the literal IPv4 address instead.
        let target_address = if force_ipv4 {
            self.resolve_ipv4(&target.authority()).await?.to_string()
        } else {
            target.authority()
        };
        let proxy_address = if force_ipv4 {
            self.resolve_ipv4(proxy).await?.to_string()
        } else {
            proxy.to_owned()
        };
        if username.is_some() != password.is_some() {
            bail!("SOCKS5 credentials require both username and password");
        }
        timeout(self.connect_timeout, async {
            let mut stream = TcpStream::connect(proxy_address).await?;
            socks5_connect(&mut stream, &target_address, username.zip(password)).await?;
            Ok::<_, anyhow::Error>(stream)
        })
        .await
        .context("SOCKS5 connection timed out")?
    }

    async fn connect_http_proxy(
        &self,
        target: &Target,
        proxy: &str,
        username: Option<&str>,
        password: Option<&str>,
        force_ipv4: bool,
    ) -> Result<TcpStream> {
        if username.is_some() != password.is_some() {
            bail!("HTTP proxy credentials require both username and password");
        }
        let mut stream = self.connect_address(proxy, force_ipv4).await?;
        let authority = target.authority();
        let mut request = format!(
            "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: keep-alive\r\n"
        );
        if let (Some(username), Some(password)) = (username, password) {
            request.push_str("Proxy-Authorization: Basic ");
            request.push_str(&STANDARD.encode(format!("{username}:{password}")));
            request.push_str("\r\n");
        }
        request.push_str("\r\n");
        let BufResult(result, _) = timeout(self.connect_timeout, stream.write_all(request))
            .await
            .context("HTTP proxy CONNECT write timed out")?;
        result.context("writing HTTP proxy CONNECT request")?;
        let response = self.read_http_headers(&mut stream).await?;
        let status = response.split_whitespace().nth(1).unwrap_or_default();
        if status != "200" {
            bail!(
                "HTTP proxy refused CONNECT to {} with status {}",
                authority,
                status
            );
        }
        Ok(stream)
    }

    async fn connect_address(&self, address: &str, force_ipv4: bool) -> Result<TcpStream> {
        if let Some(resolver) = &self.resolver {
            let (host, port) = split_authority(address)?;
            if host.parse::<std::net::IpAddr>().is_err() {
                let addresses = resolver.lookup(host).await?;
                let mut last_error: Option<anyhow::Error> = None;
                for ip in addresses {
                    if force_ipv4 && !ip.is_ipv4() {
                        continue;
                    }
                    let resolved = std::net::SocketAddr::new(ip, port).to_string();
                    match timeout(self.connect_timeout, TcpStream::connect(resolved)).await {
                        Ok(Ok(stream)) => return Ok(stream),
                        Ok(Err(error)) => last_error = Some(error.into()),
                        Err(error) => last_error = Some(anyhow::Error::from(error)),
                    }
                }
                return Err(last_error.unwrap_or_else(|| {
                    anyhow::anyhow!("DNS returned no usable address for {host}")
                }))
                .with_context(|| format!("connecting {address}"));
            }
        }
        let address = if force_ipv4 {
            self.resolve_ipv4(address).await?.to_string()
        } else {
            address.to_owned()
        };
        let stream = timeout(self.connect_timeout, TcpStream::connect(address))
            .await
            .context("TCP connection timed out")??;
        Ok(stream)
    }

    async fn resolve_ipv4(&self, address: &str) -> Result<SocketAddr> {
        if let Some(resolver) = &self.resolver {
            let (host, port) = split_authority(address)?;
            if let Ok(ip) = host.parse() {
                return match ip {
                    std::net::IpAddr::V4(ip) => Ok(SocketAddr::new(ip.into(), port)),
                    std::net::IpAddr::V6(_) => bail!("{address} has no IPv4 address"),
                };
            }
            return resolver
                .lookup(host)
                .await?
                .into_iter()
                .find(std::net::IpAddr::is_ipv4)
                .map(|ip| SocketAddr::new(ip, port))
                .with_context(|| format!("{address} has no IPv4 address"));
        }
        address
            .to_socket_addrs_async()
            .await
            .with_context(|| format!("resolving {address}"))?
            .find(SocketAddr::is_ipv4)
            .with_context(|| format!("{address} has no IPv4 address"))
    }

    async fn read_http_headers(&self, stream: &mut TcpStream) -> Result<String> {
        const MAX_HEADERS: usize = 32 * 1024;
        let response = timeout(self.connect_timeout, async {
            let mut response = Vec::with_capacity(512);
            loop {
                if response.len() == MAX_HEADERS {
                    bail!("HTTP proxy response headers exceed {MAX_HEADERS} bytes");
                }
                let BufResult(result, byte) = stream.read_exact(vec![0_u8]).await;
                result?;
                response.push(byte[0]);
                if response.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            String::from_utf8(response).context("HTTP proxy sent invalid response headers")
        })
        .await
        .context("HTTP proxy CONNECT response timed out")??;
        Ok(response)
    }
}

fn log_forward(forward: Option<&Forward>, target: &Target) {
    let Some(forward) = forward.filter(|forward| forward.log) else {
        return;
    };
    match &forward.kind {
        ForwardKind::Direct => {
            tracing::info!(route = "direct", target = %target.authority(), "route selected")
        }
        ForwardKind::Socks5 { address, .. } => {
            tracing::info!(route = "socks5", target = %target.authority(), proxy = %address, "route selected")
        }
        ForwardKind::HttpProxy { address, .. } => {
            tracing::info!(route = "http_proxy", target = %target.authority(), proxy = %address, "route selected")
        }
    }
}

async fn socks5_connect(
    stream: &mut TcpStream,
    target: &str,
    credentials: Option<(&str, &str)>,
) -> Result<()> {
    let methods = if credentials.is_some() {
        vec![0x05, 0x02, 0x00, 0x02]
    } else {
        vec![0x05, 0x01, 0x00]
    };
    write_all(stream, methods).await?;
    let greeting = read_exact(stream, 2).await?;
    if greeting[0] != 0x05 {
        bail!("SOCKS5 proxy sent an invalid greeting version");
    }
    match greeting[1] {
        0x00 if credentials.is_none() => {}
        0x02 if credentials.is_some() => {
            let (username, password) = credentials.expect("credentials checked above");
            let username = username.as_bytes();
            let password = password.as_bytes();
            if username.len() > u8::MAX as usize || password.len() > u8::MAX as usize {
                bail!("SOCKS5 credentials cannot exceed 255 bytes");
            }
            let mut auth = Vec::with_capacity(username.len() + password.len() + 3);
            auth.extend_from_slice(&[0x01, username.len() as u8]);
            auth.extend_from_slice(username);
            auth.push(password.len() as u8);
            auth.extend_from_slice(password);
            write_all(stream, auth).await?;
            let auth_response = read_exact(stream, 2).await?;
            if auth_response != [0x01, 0x00] {
                bail!("SOCKS5 proxy rejected authentication");
            }
        }
        0xff => bail!("SOCKS5 proxy has no acceptable authentication method"),
        _ => bail!("SOCKS5 proxy selected an unsupported authentication method"),
    }

    let (host, port) = split_authority(target)?;
    let mut request = vec![0x05, 0x01, 0x00];
    if let Ok(address) = host.parse::<std::net::Ipv4Addr>() {
        request.push(0x01);
        request.extend_from_slice(&address.octets());
    } else if let Ok(address) = host.parse::<std::net::Ipv6Addr>() {
        request.push(0x04);
        request.extend_from_slice(&address.octets());
    } else {
        if host.len() > u8::MAX as usize {
            bail!("SOCKS5 target host cannot exceed 255 bytes");
        }
        request.extend_from_slice(&[0x03, host.len() as u8]);
        request.extend_from_slice(host.as_bytes());
    }
    request.extend_from_slice(&port.to_be_bytes());
    write_all(stream, request).await?;

    let response = read_exact(stream, 4).await?;
    if response[0] != 0x05 {
        bail!("SOCKS5 proxy sent an invalid response version");
    }
    if response[1] != 0x00 {
        bail!(
            "SOCKS5 proxy refused CONNECT with reply code {}",
            response[1]
        );
    }
    let remaining = match response[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => usize::from(read_exact(stream, 1).await?[0]) + 2,
        _ => bail!("SOCKS5 proxy sent an invalid response address type"),
    };
    read_exact(stream, remaining).await?;
    Ok(())
}

async fn write_all(stream: &mut TcpStream, bytes: Vec<u8>) -> Result<()> {
    let BufResult(result, _) = stream.write_all(bytes).await;
    result.context("writing SOCKS5 message")?;
    Ok(())
}

async fn read_exact(stream: &mut TcpStream, length: usize) -> Result<Vec<u8>> {
    let BufResult(result, bytes) = stream.read_exact(vec![0_u8; length]).await;
    result.context("reading SOCKS5 message")?;
    Ok(bytes)
}

fn split_authority(authority: &str) -> Result<(&str, u16)> {
    if let Some(host) = authority.strip_prefix('[') {
        let (host, port) = host
            .split_once("]:")
            .context("invalid IPv6 SOCKS5 target authority")?;
        return Ok((host, port.parse().context("invalid SOCKS5 target port")?));
    }
    let (host, port) = authority
        .rsplit_once(':')
        .context("invalid SOCKS5 target authority")?;
    Ok((host, port.parse().context("invalid SOCKS5 target port")?))
}

#[cfg(test)]
mod tests {
    use compio::{net::TcpListener, runtime};
    use msgtausch_config::{Classifier, Config};

    use super::*;

    #[test]
    fn socks5_password_handshake_uses_domain_target() {
        runtime::Runtime::new()
            .expect("creating Compio runtime")
            .block_on(async {
                let listener = TcpListener::bind("127.0.0.1:0")
                    .await
                    .expect("binding SOCKS5 test server");
                let address = listener.local_addr().expect("reading test server address");
                let server = runtime::spawn(async move {
                    let (mut stream, _) =
                        listener.accept().await.context("accepting test client")?;
                    assert_eq!(read_exact(&mut stream, 4).await?, [0x05, 0x02, 0x00, 0x02]);
                    write_all(&mut stream, vec![0x05, 0x02]).await?;
                    assert_eq!(
                        read_exact(&mut stream, 14).await?,
                        b"\x01\x05alice\x06secret"
                    );
                    write_all(&mut stream, vec![0x01, 0x00]).await?;

                    let mut expected = vec![0x05, 0x01, 0x00, 0x03, 12];
                    expected.extend_from_slice(b"example.test");
                    expected.extend_from_slice(&8443_u16.to_be_bytes());
                    assert_eq!(read_exact(&mut stream, expected.len()).await?, expected);
                    write_all(&mut stream, vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await?;
                    Ok::<_, anyhow::Error>(())
                });

                let mut client = TcpStream::connect(address)
                    .await
                    .expect("connecting SOCKS5 test client");
                socks5_connect(&mut client, "example.test:8443", Some(("alice", "secret")))
                    .await
                    .expect("completing SOCKS5 handshake");
                server
                    .await
                    .expect("SOCKS5 test task did not complete")
                    .expect("SOCKS5 test server failed");
            });
    }

    #[test]
    fn split_authority_handles_ipv6() {
        assert_eq!(
            split_authority("[2001:db8::1]:443").expect("splitting IPv6 authority"),
            ("2001:db8::1", 443)
        );
    }

    #[test]
    fn quic_rejects_the_first_matching_tcp_forward() {
        runtime::Runtime::new().unwrap().block_on(async {
            let config = Config {
                forwards: vec![
                    Forward {
                        kind: ForwardKind::Socks5 {
                            address: "127.0.0.1:1".into(),
                            username: None,
                            password: None,
                        },
                        classifier: Classifier::True,
                        force_ipv4: false,
                        log: false,
                    },
                    Forward {
                        kind: ForwardKind::Direct,
                        classifier: Classifier::True,
                        force_ipv4: false,
                        log: false,
                    },
                ],
                ..Config::default()
            };
            let planner = RoutePlanner::new(
                ClassifierEngine::from_config(&config).unwrap(),
                1,
                Arc::new(NoopRouteMetrics),
            );
            let error = planner
                .resolve_direct(&Target::new("example.test", 443, None))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("SOCKS5"));
        });
    }
}
