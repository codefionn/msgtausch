//! Target connection setup for direct and chained proxy routes.

use std::{
    borrow::Cow,
    net::{IpAddr, SocketAddr},
    num::NonZeroUsize,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use compio::{
    BufResult,
    buf::{IntoInner, IoBuf},
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, ToSocketAddrsAsync},
    time::timeout,
};
use futures_util::{
    StreamExt,
    future::{Either, select},
    stream::FuturesUnordered,
};
use lru::LruCache;

use msgtausch_config::{DnsConfig, Forward, ForwardKind};
use msgtausch_policy::{ClassifierEngine, Target};
use msgtausch_resolver::Resolver;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AddressHintKey {
    host: String,
    port: u16,
}

#[derive(Clone, Debug)]
struct AddressHint {
    address: SocketAddr,
    expires_at: Instant,
    answer_set: Vec<IpAddr>,
}

struct AddressHints {
    entries: Option<LruCache<AddressHintKey, AddressHint>>,
}

impl AddressHints {
    fn new(capacity: usize) -> Self {
        Self {
            entries: NonZeroUsize::new(capacity).map(LruCache::new),
        }
    }

    fn preferred(
        &mut self,
        key: &AddressHintKey,
        expires_at: Instant,
        answer_set: &[IpAddr],
        addresses: &[SocketAddr],
        now: Instant,
    ) -> Option<SocketAddr> {
        let hint = self.entries.as_mut()?.get(key)?;
        if hint.expires_at > now
            && hint.expires_at == expires_at
            && hint.answer_set == answer_set
            && addresses.contains(&hint.address)
        {
            Some(hint.address)
        } else {
            self.entries.as_mut()?.pop(key);
            None
        }
    }

    fn insert(&mut self, key: AddressHintKey, hint: AddressHint, now: Instant) {
        if hint.expires_at <= now {
            return;
        }
        if let Some(entries) = &mut self.entries {
            entries.put(key, hint);
        }
    }
}

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
    happy_eyeballs_delay: Duration,
    address_hints: Arc<Mutex<AddressHints>>,
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
            happy_eyeballs_delay: Duration::from_millis(250),
            address_hints: Arc::new(Mutex::new(AddressHints::new(4096))),
        }
    }

    /// Select explicit DNS servers for route connections. Existing callers can
    /// keep using `new` and therefore retain system resolution.
    pub fn with_dns(mut self, config: &DnsConfig) -> Self {
        self.resolver = Resolver::new(config).map(Arc::new);
        self.happy_eyeballs_delay = Duration::from_millis(config.happy_eyeballs_delay_millis);
        self.address_hints = Arc::new(Mutex::new(AddressHints::new(config.cache_capacity)));
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
        if let Ok(ip) = host.parse::<IpAddr>() {
            if force_ipv4 && !ip.is_ipv4() {
                bail!("{address} has no IPv4 address");
            }
            return Ok(SocketAddr::new(ip, port));
        }
        if let Some(resolver) = &self.resolver {
            return resolver
                .lookup_with_expiry(host)
                .await?
                .addresses
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
        self.connect_address(Cow::Owned(target.authority()), force_ipv4)
            .await
    }

    async fn connect_socks5(
        &self,
        target: &Target,
        proxy: &str,
        username: Option<&str>,
        password: Option<&str>,
        force_ipv4: bool,
    ) -> Result<TcpStream> {
        if username.is_some() != password.is_some() {
            bail!("SOCKS5 credentials require both username and password");
        }
        timeout(self.connect_timeout, async {
            // SOCKS permits the proxy to resolve the target. For an IPv4-only
            // rule we resolve it here and send the literal IPv4 address instead.
            let target_address = if force_ipv4 {
                self.resolve_ipv4(&target.authority()).await?.to_string()
            } else {
                target.authority()
            };
            let mut stream = self
                .connect_address_within_timeout(Cow::Borrowed(proxy), force_ipv4)
                .await?;
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
        let mut stream = self
            .connect_address(Cow::Borrowed(proxy), force_ipv4)
            .await?;
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
        let response = read_http_headers(&mut stream, self.connect_timeout).await?;
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

    async fn connect_address(&self, address: Cow<'_, str>, force_ipv4: bool) -> Result<TcpStream> {
        timeout(
            self.connect_timeout,
            self.connect_address_within_timeout(address, force_ipv4),
        )
        .await
        .context("TCP connection timed out")?
    }

    async fn connect_address_within_timeout(
        &self,
        address: Cow<'_, str>,
        force_ipv4: bool,
    ) -> Result<TcpStream> {
        let (host, port) = split_authority(&address)?;
        if let Ok(ip) = host.parse::<IpAddr>() {
            if force_ipv4 && !ip.is_ipv4() {
                bail!("{address} has no IPv4 address");
            }
            return Ok(TcpStream::connect(SocketAddr::new(ip, port)).await?);
        }

        let (addresses, expiry) = if let Some(resolver) = &self.resolver {
            let answer = resolver.lookup_with_expiry(host).await?;
            (answer.addresses, Some(answer.expires_at))
        } else {
            (
                address
                    .to_socket_addrs_async()
                    .await
                    .with_context(|| format!("resolving {address}"))?
                    .map(|address| address.ip())
                    .collect(),
                None,
            )
        };
        self.connect_resolved(host, port, addresses, expiry, force_ipv4)
            .await
            .with_context(|| format!("connecting {address}"))
    }

    async fn connect_resolved(
        &self,
        host: &str,
        port: u16,
        addresses: Vec<IpAddr>,
        expires_at: Option<Instant>,
        force_ipv4: bool,
    ) -> Result<TcpStream> {
        let addresses = socket_candidates(addresses, port, force_ipv4);
        if addresses.is_empty() {
            bail!("DNS returned no usable address for {host}");
        }

        let key = AddressHintKey {
            host: normalize_host(host),
            port,
        };
        let answer_set = canonical_answer_set(&addresses);
        let preferred = expires_at.and_then(|expires_at| {
            self.address_hints
                .lock()
                .expect("address hint lock poisoned")
                .preferred(&key, expires_at, &answer_set, &addresses, Instant::now())
        });

        let candidates = staggered_candidates(addresses, preferred);
        let result = self.connect_staggered(candidates).await;
        match result {
            Ok((address, stream)) => {
                if let Some(expires_at) =
                    expires_at.filter(|expires_at| *expires_at > Instant::now())
                {
                    self.address_hints
                        .lock()
                        .expect("address hint lock poisoned")
                        .insert(
                            key,
                            AddressHint {
                                address,
                                expires_at,
                                answer_set,
                            },
                            Instant::now(),
                        );
                }
                Ok(stream)
            }
            Err(error) => {
                self.address_hints
                    .lock()
                    .expect("address hint lock poisoned")
                    .entries
                    .as_mut()
                    .and_then(|entries| entries.pop(&key));
                Err(error)
            }
        }
    }

    async fn connect_staggered(
        &self,
        candidates: Vec<SocketAddr>,
    ) -> Result<(SocketAddr, TcpStream)> {
        let first_is_ipv4 = candidates.first().is_some_and(SocketAddr::is_ipv4);
        let (first, second): (Vec<_>, Vec<_>) = candidates
            .into_iter()
            .partition(|address| address.is_ipv4() == first_is_ipv4);
        let first_attempt = compio::runtime::spawn(connect_family(first, Duration::ZERO));
        if second.is_empty() {
            return first_attempt
                .await
                .map_err(|error| anyhow::anyhow!("connection task failed: {error}"))?;
        }
        let timer = Box::pin(compio::time::sleep(self.happy_eyeballs_delay));
        let first_attempt = Box::pin(first_attempt);
        let first_attempt = match select(first_attempt, timer).await {
            Either::Left((result, _)) => match result {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(_)) | Err(_) => {
                    return compio::runtime::spawn(connect_family(second, Duration::ZERO))
                        .await
                        .map_err(|error| anyhow::anyhow!("connection task failed: {error}"))?;
                }
            },
            Either::Right((_, first_attempt)) => first_attempt,
        };
        let mut attempts = FuturesUnordered::new();
        attempts.push(first_attempt);
        attempts.push(Box::pin(compio::runtime::spawn(connect_family(
            second,
            Duration::ZERO,
        ))));
        let mut last_error = None;
        while let Some(attempt) = attempts.next().await {
            match attempt {
                Ok(Ok(result)) => return Ok(result),
                Ok(Err(error)) => last_error = Some(error),
                Err(error) => last_error = Some(anyhow::anyhow!("connection task failed: {error}")),
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("all connection attempts failed")))
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
}

async fn read_http_headers(stream: &mut TcpStream, connect_timeout: Duration) -> Result<String> {
    const MAX_HEADERS: usize = 32 * 1024;
    const READ_CHUNK: usize = 4 * 1024;

    timeout(connect_timeout, async {
        let mut response = Vec::with_capacity(READ_CHUNK);
        let mut chunk = vec![0_u8; READ_CHUNK];
        loop {
            if response.len() == MAX_HEADERS {
                bail!("HTTP proxy response headers exceed {MAX_HEADERS} bytes");
            }

            let available = (MAX_HEADERS - response.len()).min(READ_CHUNK);
            chunk.resize(available, 0);
            let BufResult(result, returned_chunk) = stream.peek(chunk.slice(..available)).await;
            let read = result.context("reading HTTP proxy CONNECT response")?;
            if read == 0 {
                bail!("HTTP proxy closed before completing CONNECT response headers");
            }
            chunk = returned_chunk.into_inner();
            chunk.truncate(read);

            let response_len = response.len();
            response.extend_from_slice(&chunk[..read]);
            if let Some(header_len) = http_header_end(&response) {
                response.truncate(header_len);
                let BufResult(result, _) = stream
                    .read_exact(chunk.slice(..header_len - response_len))
                    .await;
                result.context("reading HTTP proxy CONNECT response")?;
                return String::from_utf8(response)
                    .context("HTTP proxy sent invalid response headers");
            }

            let BufResult(result, returned_chunk) = stream.read_exact(chunk.slice(..read)).await;
            result.context("reading HTTP proxy CONNECT response")?;
            chunk = returned_chunk.into_inner();
        }
    })
    .await
    .context("HTTP proxy CONNECT response timed out")?
}

fn http_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(b"\r\n\r\n".len())
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + b"\r\n\r\n".len())
}

async fn connect_family(
    addresses: Vec<SocketAddr>,
    delay: Duration,
) -> Result<(SocketAddr, TcpStream)> {
    if !delay.is_zero() {
        compio::time::sleep(delay).await;
    }
    let mut last_error = None;
    for address in addresses {
        match TcpStream::connect(address).await {
            Ok(stream) => return Ok((address, stream)),
            Err(error) => last_error = Some(anyhow::Error::from(error)),
        }
    }
    Err(last_error.unwrap_or_else(|| anyhow::anyhow!("no addresses to connect")))
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

fn normalize_host(host: &str) -> String {
    host.trim_end_matches('.').to_ascii_lowercase()
}

fn canonical_answer_set(addresses: &[SocketAddr]) -> Vec<IpAddr> {
    let mut answer_set: Vec<_> = addresses.iter().map(SocketAddr::ip).collect();
    answer_set.sort_unstable();
    answer_set.dedup();
    answer_set
}

fn socket_candidates(addresses: Vec<IpAddr>, port: u16, force_ipv4: bool) -> Vec<SocketAddr> {
    addresses
        .into_iter()
        .filter(|ip| !force_ipv4 || ip.is_ipv4())
        .map(|ip| SocketAddr::new(ip, port))
        .collect()
}

fn staggered_candidates(
    mut addresses: Vec<SocketAddr>,
    preferred: Option<SocketAddr>,
) -> Vec<SocketAddr> {
    if let Some(preferred) = preferred
        && let Some(index) = addresses.iter().position(|address| *address == preferred)
    {
        let preferred = addresses.remove(index);
        addresses.insert(0, preferred);
    }
    let first_is_ipv4 = addresses.first().is_none_or(SocketAddr::is_ipv4);
    let (mut first, mut second): (Vec<_>, Vec<_>) = addresses
        .into_iter()
        .partition(|address| address.is_ipv4() == first_is_ipv4);
    let mut candidates = Vec::with_capacity(first.len() + second.len());
    while !first.is_empty() || !second.is_empty() {
        if !first.is_empty() {
            candidates.push(first.remove(0));
        }
        if !second.is_empty() {
            candidates.push(second.remove(0));
        }
    }
    candidates
}

#[cfg(test)]
mod tests {
    use compio::{
        net::{TcpListener, UdpSocket},
        runtime,
    };
    use msgtausch_config::{Classifier, Config, DnsConfig, DnsServerConfig, DnsServerKind};

    use super::*;

    fn http_response(length: usize) -> Vec<u8> {
        let prefix = b"HTTP/1.1 200 OK\r\nX-Fill: ";
        let suffix = b"\r\n\r\n";
        assert!(length >= prefix.len() + suffix.len());

        let mut response = Vec::with_capacity(length);
        response.extend_from_slice(prefix);
        response.extend(std::iter::repeat_n(
            b'a',
            length - prefix.len() - suffix.len(),
        ));
        response.extend_from_slice(suffix);
        response
    }

    async fn read_proxy_response(response: Vec<u8>) -> Result<(Result<String>, TcpStream)> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .context("binding HTTP proxy test server")?;
        let address = listener
            .local_addr()
            .context("reading HTTP proxy test server address")?;
        let server = runtime::spawn(async move {
            let (mut stream, _) = listener
                .accept()
                .await
                .context("accepting HTTP proxy test client")?;
            write_all(&mut stream, response).await
        });

        let mut client = TcpStream::connect(address)
            .await
            .context("connecting HTTP proxy test client")?;
        let headers = read_http_headers(&mut client, Duration::from_secs(1)).await;
        server
            .await
            .map_err(|error| anyhow::anyhow!("HTTP proxy test task did not complete: {error}"))??;
        Ok((headers, client))
    }

    #[test]
    fn http_proxy_headers_read_a_200_byte_response() {
        runtime::Runtime::new().unwrap().block_on(async {
            let (headers, _) = read_proxy_response(http_response(200)).await.unwrap();
            assert_eq!(headers.unwrap().len(), 200);
        });
    }

    #[test]
    fn http_proxy_headers_read_a_four_kib_response() {
        runtime::Runtime::new().unwrap().block_on(async {
            let (headers, _) = read_proxy_response(http_response(4 * 1024)).await.unwrap();
            assert_eq!(headers.unwrap().len(), 4 * 1024);
        });
    }

    #[test]
    fn http_proxy_headers_read_a_near_limit_response() {
        runtime::Runtime::new().unwrap().block_on(async {
            let length = 32 * 1024 - 1;
            let (headers, _) = read_proxy_response(http_response(length)).await.unwrap();
            assert_eq!(headers.unwrap().len(), length);
        });
    }

    #[test]
    fn http_proxy_headers_reject_a_response_over_the_limit() {
        runtime::Runtime::new().unwrap().block_on(async {
            let (headers, _) = read_proxy_response(http_response(32 * 1024 + 1))
                .await
                .unwrap();
            let error = headers.expect_err("headers over 32 KiB must fail");
            assert!(error.to_string().contains("exceed 32768 bytes"));
        });
    }

    #[test]
    fn http_proxy_headers_find_a_terminator_split_between_chunks() {
        let mut response = b"HTTP/1.1 200 OK\r\n\r\n".to_vec();
        let split_at = response.len() - 1;
        let trailing = response.split_off(split_at);

        assert_eq!(http_header_end(&response), None);
        response.extend_from_slice(&trailing);
        assert_eq!(http_header_end(&response), Some(response.len()));
    }

    #[test]
    fn http_proxy_headers_leave_same_read_payload_for_the_tunnel() {
        runtime::Runtime::new().unwrap().block_on(async {
            let payload = b"first bytes of the tunnel";
            let mut response = http_response(200);
            response.extend_from_slice(payload);
            let (headers, mut client) = read_proxy_response(response).await.unwrap();

            assert_eq!(headers.unwrap().len(), 200);
            let BufResult(result, payload_after_headers) =
                client.read_exact(vec![0_u8; payload.len()]).await;
            result.unwrap();
            assert_eq!(payload_after_headers, payload);
        });
    }

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
    fn happy_eyeballs_alternates_families_after_a_preferred_address() {
        let v4_one = SocketAddr::from(([192, 0, 2, 1], 443));
        let v4_two = SocketAddr::from(([192, 0, 2, 2], 443));
        let v6_one = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443));
        let v6_two = SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 2], 443));

        assert_eq!(
            staggered_candidates(vec![v6_one, v6_two, v4_one, v4_two], Some(v4_two)),
            vec![v4_two, v6_one, v4_one, v6_two]
        );
    }

    #[test]
    fn force_ipv4_filters_ipv6_before_attempts_are_scheduled() {
        let candidates = socket_candidates(
            vec!["2001:db8::1".parse().unwrap(), "192.0.2.1".parse().unwrap()],
            443,
            true,
        );
        assert_eq!(candidates, vec![SocketAddr::from(([192, 0, 2, 1], 443))]);
    }

    #[test]
    fn force_ipv4_rejects_a_literal_ipv6_quic_target() {
        runtime::Runtime::new().unwrap().block_on(async {
            let config = Config {
                forwards: vec![Forward {
                    kind: ForwardKind::Direct,
                    classifier: Classifier::True,
                    force_ipv4: true,
                    log: false,
                }],
                ..Config::default()
            };
            let planner = RoutePlanner::new(
                ClassifierEngine::from_config(&config).unwrap(),
                1,
                Arc::new(NoopRouteMetrics),
            );
            let error = planner
                .resolve_direct(&Target::new("2001:db8::1", 443, None))
                .await
                .unwrap_err();
            assert!(error.to_string().contains("no IPv4 address"));
        });
    }

    #[test]
    fn address_hints_ignore_expired_values_and_bound_their_size() {
        let now = Instant::now();
        let first = AddressHintKey {
            host: "first.test".into(),
            port: 443,
        };
        let second = AddressHintKey {
            host: "second.test".into(),
            port: 443,
        };
        let hint = |address| AddressHint {
            address,
            expires_at: now + Duration::from_secs(5),
            answer_set: vec![address.ip()],
        };
        let mut hints = AddressHints::new(1);
        hints.insert(
            first.clone(),
            hint(SocketAddr::from(([192, 0, 2, 1], 443))),
            now,
        );
        hints.insert(
            second.clone(),
            hint(SocketAddr::from(([192, 0, 2, 2], 443))),
            now,
        );
        assert!(!hints.entries.as_ref().unwrap().contains(&first));
        assert!(hints.entries.as_ref().unwrap().contains(&second));

        let expired = AddressHint {
            address: SocketAddr::from(([192, 0, 2, 3], 443)),
            expires_at: now,
            answer_set: vec!["192.0.2.3".parse().unwrap()],
        };
        hints.insert(first.clone(), expired, now - Duration::from_secs(1));
        assert!(
            hints
                .preferred(
                    &first,
                    now,
                    &["192.0.2.3".parse().unwrap()],
                    &[SocketAddr::from(([192, 0, 2, 3], 443))],
                    now,
                )
                .is_none()
        );
    }

    #[test]
    fn connect_timeout_includes_configured_dns_lookup() {
        runtime::Runtime::new().unwrap().block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let config = Config {
                dns: DnsConfig {
                    enabled: true,
                    servers: vec![DnsServerConfig {
                        address: server.local_addr().unwrap().to_string(),
                        kind: DnsServerKind::Udp,
                        timeout_seconds: 5,
                        tls_host: None,
                    }],
                    ..DnsConfig::default()
                },
                ..Config::default()
            };
            let planner = RoutePlanner::new(
                ClassifierEngine::from_config(&config).unwrap(),
                1,
                Arc::new(NoopRouteMetrics),
            )
            .with_dns(&config.dns);
            let started = Instant::now();
            let error = planner
                .connect(&Target::new("slow-dns.test", 443, None))
                .await
                .unwrap_err();
            assert!(started.elapsed() < Duration::from_secs(2));
            assert!(error.to_string().contains("TCP connection timed out"));
        });
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
