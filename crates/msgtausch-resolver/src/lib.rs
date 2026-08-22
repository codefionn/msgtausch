//! A small DNS client used when the configuration selects explicit resolvers.
//!
//! It deliberately speaks only the part of DNS needed for proxy connection
//! setup: validated A and AAAA replies.  One resolver is selected first in
//! round-robin order. A query never spills over into the next server.

use std::{
    error::Error,
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroUsize,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};

use anyhow::{Context, Result, bail};
use compio::{
    BufResult,
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::timeout,
};
use compio_tls::{TlsConnector, rustls};
use futures_util::future::join;
use lru::LruCache;

use msgtausch_config::{DnsConfig, DnsServerConfig, DnsServerKind};

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// DNS answers together with the point at which their DNS TTL expires.
#[derive(Clone, Debug)]
pub struct ResolvedAddresses {
    pub addresses: Vec<IpAddr>,
    pub expires_at: Instant,
}

#[derive(Debug)]
struct NoRecords;

impl fmt::Display for NoRecords {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DNS reply contains no requested records")
    }
}

impl Error for NoRecords {}

#[derive(Clone)]
enum CacheEntry {
    Positive(ResolvedAddresses),
    Negative { expires_at: Instant },
}

struct DnsCache {
    entries: Option<LruCache<String, CacheEntry>>,
}

impl DnsCache {
    fn new(capacity: usize) -> Self {
        Self {
            entries: NonZeroUsize::new(capacity).map(LruCache::new),
        }
    }

    fn get(&mut self, host: &str, now: Instant) -> Option<CacheEntry> {
        let entry = self.entries.as_mut()?.get(host)?.clone();
        let expires_at = match &entry {
            CacheEntry::Positive(answer) => answer.expires_at,
            CacheEntry::Negative { expires_at } => *expires_at,
        };
        if expires_at <= now {
            self.entries.as_mut()?.pop(host);
            return None;
        }
        Some(entry)
    }

    fn insert(&mut self, host: String, entry: CacheEntry, now: Instant) {
        let expires_at = match &entry {
            CacheEntry::Positive(answer) => answer.expires_at,
            CacheEntry::Negative { expires_at } => *expires_at,
        };
        if expires_at <= now {
            return;
        }
        if let Some(entries) = &mut self.entries {
            entries.put(host, entry);
        }
    }
}

#[derive(Debug)]
struct Records {
    addresses: Vec<IpAddr>,
    min_ttl: Duration,
}

/// DNS resolver with per-query round-robin server selection.
pub struct Resolver {
    servers: Vec<DnsServerConfig>,
    next_server: AtomicUsize,
    next_id: AtomicUsize,
    cache: Mutex<DnsCache>,
    cache_enabled: bool,
    cache_max_ttl: Duration,
    negative_cache_ttl: Duration,
    cache_query: Arc<dyn Fn() + Send + Sync>,
}

impl Resolver {
    pub fn new(config: &DnsConfig) -> Option<Self> {
        (config.enabled && !config.servers.is_empty()).then(|| Self {
            servers: config.servers.clone(),
            next_server: AtomicUsize::new(0),
            next_id: AtomicUsize::new(1),
            cache: Mutex::new(DnsCache::new(config.cache_capacity)),
            cache_enabled: config.cache_enabled && config.cache_capacity > 0,
            cache_max_ttl: Duration::from_secs(config.cache_max_ttl_seconds),
            negative_cache_ttl: Duration::from_secs(config.negative_cache_ttl_seconds),
            cache_query: Arc::new(|| {}),
        })
    }

    /// Record a logical lookup served by the DNS cache. The callback is
    /// invoked once for either a positive or negative cache hit.
    pub fn with_cache_query_callback(mut self, callback: Arc<dyn Fn() + Send + Sync>) -> Self {
        self.cache_query = callback;
        self
    }

    pub async fn lookup(&self, host: &str) -> Result<Vec<IpAddr>> {
        Ok(self.lookup_with_expiry(host).await?.addresses)
    }

    pub async fn lookup_with_expiry(&self, host: &str) -> Result<ResolvedAddresses> {
        let host = normalize_host(host);
        if let Ok(ip) = host.parse() {
            return Ok(ResolvedAddresses {
                addresses: vec![ip],
                expires_at: Instant::now(),
            });
        }
        if host.is_empty() {
            bail!("DNS name is empty");
        }
        let now = Instant::now();
        if self.cache_enabled {
            let cached = self
                .cache
                .lock()
                .expect("DNS cache lock poisoned")
                .get(&host, now);
            match cached {
                Some(CacheEntry::Positive(answer)) => {
                    (self.cache_query)();
                    return Ok(answer);
                }
                Some(CacheEntry::Negative { .. }) => {
                    (self.cache_query)();
                    return Err(NoRecords.into());
                }
                None => {}
            }
        }
        let index = self.next_server.fetch_add(1, Ordering::Relaxed) % self.servers.len();
        match self.lookup_server(&self.servers[index], &host).await {
            Ok(records) => {
                let ttl = records.min_ttl.min(self.cache_max_ttl);
                let answer = ResolvedAddresses {
                    addresses: records.addresses,
                    expires_at: Instant::now() + ttl,
                };
                if self.cache_enabled && !ttl.is_zero() {
                    self.cache.lock().expect("DNS cache lock poisoned").insert(
                        host.clone(),
                        CacheEntry::Positive(answer.clone()),
                        Instant::now(),
                    );
                }
                Ok(answer)
            }
            Err(error) if is_no_records(&error) => {
                if self.cache_enabled && !self.negative_cache_ttl.is_zero() {
                    self.cache.lock().expect("DNS cache lock poisoned").insert(
                        host,
                        CacheEntry::Negative {
                            expires_at: Instant::now() + self.negative_cache_ttl,
                        },
                        Instant::now(),
                    );
                }
                Err(error)
            }
            Err(error) => Err(error),
        }
    }

    async fn lookup_server(&self, server: &DnsServerConfig, host: &str) -> Result<Records> {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed) as u16;
        let (a, aaaa) = join(
            self.query(server, host, TYPE_A, id),
            self.query(server, host, TYPE_AAAA, id.wrapping_add(1)),
        )
        .await;
        combine_records([a, aaaa])
    }

    async fn query(
        &self,
        server: &DnsServerConfig,
        host: &str,
        qtype: u16,
        id: u16,
    ) -> Result<Records> {
        let packet = build_query(host, qtype, id)?;
        let duration = Duration::from_secs(server.timeout_seconds.max(1));
        let response = match server.kind {
            DnsServerKind::Udp => timeout(duration, udp_exchange(&server.address, packet))
                .await
                .context("DNS UDP query timed out")??,
            DnsServerKind::Tcp => timeout(duration, tcp_exchange(&server.address, packet))
                .await
                .context("DNS TCP query timed out")??,
            DnsServerKind::Dot => timeout(duration, dot_exchange(server, packet))
                .await
                .context("DNS-over-TLS query timed out")??,
        };
        parse_records(&response, host, qtype, id)
    }
}

fn combine_records(results: [Result<Records>; 2]) -> Result<Records> {
    let mut addresses = Vec::new();
    let mut min_ttl = None;
    let mut first_error = None;
    for result in results {
        match result {
            Ok(records) => {
                min_ttl =
                    Some(min_ttl.map_or(records.min_ttl, |ttl: Duration| ttl.min(records.min_ttl)));
                addresses.extend(records.addresses);
            }
            Err(error) if is_no_records(&error) => {}
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    if addresses.is_empty() {
        return Err(first_error.unwrap_or_else(|| NoRecords.into()));
    }
    Ok(Records {
        addresses,
        min_ttl: min_ttl.expect("records had a TTL"),
    })
}

async fn udp_exchange(address: &str, packet: Vec<u8>) -> Result<Vec<u8>> {
    let bind = if address.contains('[')
        || address
            .rsplit_once(':')
            .is_some_and(|(host, _)| host.contains(':'))
    {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };
    let socket = UdpSocket::bind(bind)
        .await
        .context("binding DNS UDP socket")?;
    let BufResult(sent, _) = socket.send_to(packet.clone(), address).await;
    sent.context("sending DNS UDP query")?;
    let BufResult(received, buffer) = socket.recv_from(Vec::with_capacity(4096)).await;
    let (length, _) = received.context("receiving DNS UDP reply")?;
    if length == buffer.len() {
        Ok(buffer)
    } else {
        Ok(buffer[..length].to_vec())
    }
}

async fn tcp_exchange(address: &str, packet: Vec<u8>) -> Result<Vec<u8>> {
    let mut stream = TcpStream::connect(address)
        .await
        .context("connecting DNS TCP server")?;
    framed_exchange(&mut stream, packet).await
}

async fn dot_exchange(server: &DnsServerConfig, packet: Vec<u8>) -> Result<Vec<u8>> {
    let tcp = TcpStream::connect(&server.address)
        .await
        .context("connecting DNS-over-TLS server")?;
    let native = rustls_native_certs::load_native_certs();
    if native.certs.is_empty() {
        bail!("no native CA certificates were available for DNS-over-TLS");
    }
    let mut roots = rustls::RootCertStore::empty();
    roots.add_parsable_certificates(native.certs);
    let mut tls = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    tls.alpn_protocols = vec![b"dot".to_vec()];
    let connector = TlsConnector::from(std::sync::Arc::new(tls));
    let hostname = server
        .tls_host
        .as_deref()
        .unwrap_or_else(|| dns_server_name(&server.address));
    let mut stream = connector
        .connect(hostname, tcp)
        .await
        .context("DNS-over-TLS handshake failed")?;
    framed_exchange(&mut stream, packet).await
}

fn dns_server_name(address: &str) -> &str {
    if let Some(rest) = address.strip_prefix('[') {
        return rest.split_once(']').map_or(rest, |(host, _)| host);
    }
    address.rsplit_once(':').map_or(address, |(host, _)| host)
}

async fn framed_exchange<S>(stream: &mut S, packet: Vec<u8>) -> Result<Vec<u8>>
where
    S: compio::io::AsyncRead + compio::io::AsyncWrite + Unpin,
{
    let length = u16::try_from(packet.len()).context("DNS query is too large")?;
    let mut framed = length.to_be_bytes().to_vec();
    framed.extend(packet);
    let BufResult(result, _) = stream.write_all(framed).await;
    result.context("writing DNS TCP query")?;
    let BufResult(result, prefix) = stream.read_exact(vec![0; 2]).await;
    result.context("reading DNS TCP reply length")?;
    let length = u16::from_be_bytes([prefix[0], prefix[1]]) as usize;
    let BufResult(result, reply) = stream.read_exact(vec![0; length]).await;
    result.context("reading DNS TCP reply")?;
    Ok(reply)
}

fn build_query(host: &str, qtype: u16, id: u16) -> Result<Vec<u8>> {
    let mut packet = Vec::with_capacity(512);
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(&0x0100_u16.to_be_bytes()); // recursion desired
    packet.extend_from_slice(&1_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    packet.extend_from_slice(&0_u16.to_be_bytes());
    write_name(&mut packet, host)?;
    packet.extend_from_slice(&qtype.to_be_bytes());
    packet.extend_from_slice(&CLASS_IN.to_be_bytes());
    Ok(packet)
}

#[cfg(test)]
fn parse_response(packet: &[u8], host: &str, qtype: u16, id: u16) -> Result<Vec<IpAddr>> {
    Ok(parse_records(packet, host, qtype, id)?.addresses)
}

fn parse_records(packet: &[u8], host: &str, qtype: u16, id: u16) -> Result<Records> {
    if packet.len() < 12 {
        bail!("DNS reply is shorter than its header");
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != id {
        bail!("DNS reply transaction ID does not match");
    }
    let flags = u16::from_be_bytes([packet[2], packet[3]]);
    if flags & 0x8000 == 0 {
        bail!("DNS reply is not a response");
    }
    if flags & 0x000f == 3 {
        return Err(NoRecords.into());
    }
    if flags & 0x000f != 0 {
        bail!("DNS server returned rcode {}", flags & 0x000f);
    }
    let questions = u16::from_be_bytes([packet[4], packet[5]]) as usize;
    let answers = u16::from_be_bytes([packet[6], packet[7]]) as usize;
    if questions != 1 {
        bail!("DNS reply has {questions} questions, expected one");
    }
    let mut cursor = 12;
    let question = read_name(packet, &mut cursor)?;
    let reply_type = read_u16(packet, &mut cursor)?;
    let reply_class = read_u16(packet, &mut cursor)?;
    if !names_equal(&question, host) || reply_type != qtype || reply_class != CLASS_IN {
        bail!("DNS reply question does not match request");
    }
    let mut addresses = Vec::new();
    let mut min_ttl = None;
    for _ in 0..answers {
        let _name = read_name(packet, &mut cursor)?;
        let typ = read_u16(packet, &mut cursor)?;
        let class = read_u16(packet, &mut cursor)?;
        let ttl = read_u32(packet, &mut cursor)?;
        let length = read_u16(packet, &mut cursor)? as usize;
        let data = packet
            .get(cursor..cursor + length)
            .context("truncated DNS resource record")?;
        cursor += length;
        if class != CLASS_IN || typ != qtype {
            continue;
        }
        match (typ, data) {
            (TYPE_A, [a, b, c, d]) => {
                addresses.push(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)));
                min_ttl = Some(min_ttl.map_or(ttl, |current: u32| current.min(ttl)));
            }
            (TYPE_AAAA, bytes) if bytes.len() == 16 => {
                let mut octets = [0; 16];
                octets.copy_from_slice(bytes);
                addresses.push(IpAddr::V6(Ipv6Addr::from(octets)));
                min_ttl = Some(min_ttl.map_or(ttl, |current: u32| current.min(ttl)));
            }
            _ => bail!("DNS reply has an invalid address record length"),
        }
    }
    if addresses.is_empty() {
        return Err(NoRecords.into());
    }
    Ok(Records {
        addresses,
        min_ttl: Duration::from_secs(u64::from(min_ttl.expect("addresses had a TTL"))),
    })
}

fn write_name(packet: &mut Vec<u8>, host: &str) -> Result<()> {
    for label in host.split('.') {
        if label.is_empty() || label.len() > 63 {
            bail!("invalid DNS label in '{host}'");
        }
        packet.push(label.len() as u8);
        packet.extend_from_slice(label.as_bytes());
    }
    packet.push(0);
    Ok(())
}

fn read_name(packet: &[u8], cursor: &mut usize) -> Result<String> {
    let mut labels = Vec::new();
    let mut pos = *cursor;
    let mut jumped = false;
    let mut hops = 0;
    loop {
        let byte = *packet.get(pos).context("truncated DNS name")?;
        if byte & 0xc0 == 0xc0 {
            let second = *packet.get(pos + 1).context("truncated DNS pointer")?;
            let pointer = (((byte & 0x3f) as usize) << 8) | second as usize;
            if pointer >= packet.len() || hops >= packet.len() {
                bail!("invalid DNS compression pointer");
            }
            if !jumped {
                *cursor = pos + 2;
                jumped = true;
            }
            pos = pointer;
            hops += 1;
            continue;
        }
        if byte & 0xc0 != 0 {
            bail!("invalid DNS name label");
        }
        pos += 1;
        if byte == 0 {
            if !jumped {
                *cursor = pos;
            }
            break;
        }
        let end = pos + byte as usize;
        let label = packet.get(pos..end).context("truncated DNS label")?;
        labels.push(
            std::str::from_utf8(label)
                .context("DNS label is not UTF-8")?
                .to_ascii_lowercase(),
        );
        pos = end;
    }
    Ok(labels.join("."))
}

fn read_u16(p: &[u8], c: &mut usize) -> Result<u16> {
    let b = p.get(*c..*c + 2).context("truncated DNS field")?;
    *c += 2;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}
fn read_u32(p: &[u8], c: &mut usize) -> Result<u32> {
    let b = p.get(*c..*c + 4).context("truncated DNS field")?;
    *c += 4;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}
fn names_equal(left: &str, right: &str) -> bool {
    left.trim_end_matches('.')
        .eq_ignore_ascii_case(right.trim_end_matches('.'))
}
fn is_no_records(error: &anyhow::Error) -> bool {
    error.downcast_ref::<NoRecords>().is_some()
}

fn normalize_host(host: &str) -> String {
    host.trim().trim_end_matches('.').to_ascii_lowercase()
}

#[cfg(test)]
mod tests {
    use super::*;
    use compio::runtime;

    fn reply_for(host: &str, qtype: u16, id: u16) -> Vec<u8> {
        let query = build_query(host, qtype, id).unwrap();
        let mut reply = query[..12].to_vec();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply.extend_from_slice(&query[12..]);
        reply
    }

    fn append_answer(reply: &mut Vec<u8>, qtype: u16, data: &[u8]) {
        append_answer_with_ttl(reply, qtype, 60, data);
    }

    fn append_answer_with_ttl(reply: &mut Vec<u8>, qtype: u16, ttl: u32, data: &[u8]) {
        let answer_count = u16::from_be_bytes([reply[6], reply[7]]) + 1;
        reply[6..8].copy_from_slice(&answer_count.to_be_bytes());
        reply.extend_from_slice(&[0xc0, 0x0c]);
        reply.extend_from_slice(&qtype.to_be_bytes());
        reply.extend_from_slice(&CLASS_IN.to_be_bytes());
        reply.extend_from_slice(&ttl.to_be_bytes());
        reply.extend_from_slice(&(data.len() as u16).to_be_bytes());
        reply.extend_from_slice(data);
    }

    #[test]
    fn parses_valid_compressed_a_reply() {
        let query = build_query("example.test", TYPE_A, 7).unwrap();
        let mut reply = query[..12].to_vec();
        reply[2] = 0x81;
        reply[3] = 0x80;
        reply[6..8].copy_from_slice(&1_u16.to_be_bytes());
        reply.extend_from_slice(&query[12..]);
        reply.extend_from_slice(&[0xc0, 0x0c]);
        reply.extend_from_slice(&TYPE_A.to_be_bytes());
        reply.extend_from_slice(&CLASS_IN.to_be_bytes());
        reply.extend_from_slice(&60_u32.to_be_bytes());
        reply.extend_from_slice(&4_u16.to_be_bytes());
        reply.extend_from_slice(&[127, 0, 0, 1]);
        assert_eq!(
            parse_response(&reply, "example.test", TYPE_A, 7).unwrap(),
            vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
        );
    }

    #[test]
    fn parser_uses_the_smallest_usable_record_ttl() {
        let mut reply = reply_for("example.test", TYPE_A, 7);
        append_answer_with_ttl(&mut reply, TYPE_A, 30, &[192, 0, 2, 1]);
        append_answer_with_ttl(&mut reply, TYPE_A, 4, &[192, 0, 2, 2]);

        let records = parse_records(&reply, "example.test", TYPE_A, 7).unwrap();
        assert_eq!(records.min_ttl, Duration::from_secs(4));
        assert_eq!(records.addresses.len(), 2);
    }

    #[test]
    fn cache_returns_hits_evicts_expired_entries_and_bounds_capacity() {
        let now = Instant::now();
        let answer = ResolvedAddresses {
            addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
            expires_at: now + Duration::from_secs(1),
        };
        let mut cache = DnsCache::new(1);
        cache.insert(
            "first.test".into(),
            CacheEntry::Positive(answer.clone()),
            now,
        );
        assert!(matches!(
            cache.get("first.test", now),
            Some(CacheEntry::Positive(_))
        ));
        assert!(
            cache
                .get("first.test", now + Duration::from_secs(1))
                .is_none()
        );

        cache.insert(
            "first.test".into(),
            CacheEntry::Positive(answer.clone()),
            now,
        );
        cache.insert(
            "second.test".into(),
            CacheEntry::Positive(answer.clone()),
            now,
        );
        assert!(cache.get("first.test", now).is_none());
        assert!(cache.get("second.test", now).is_some());

        let mut disabled = DnsCache::new(0);
        disabled.insert("disabled.test".into(), CacheEntry::Positive(answer), now);
        assert!(disabled.get("disabled.test", now).is_none());
    }

    #[test]
    fn cache_keeps_negative_answers_only_until_their_expiry() {
        let now = Instant::now();
        let mut cache = DnsCache::new(1);
        cache.insert(
            "missing.test".into(),
            CacheEntry::Negative {
                expires_at: now + Duration::from_secs(5),
            },
            now,
        );
        assert!(matches!(
            cache.get("missing.test", now),
            Some(CacheEntry::Negative { .. })
        ));
        assert!(
            cache
                .get("missing.test", now + Duration::from_secs(5))
                .is_none()
        );
    }

    #[test]
    fn normalizes_cache_keys_without_changing_dns_name_semantics() {
        assert_eq!(normalize_host(" Api.Example.Test. "), "api.example.test");
    }

    #[test]
    fn keeps_a_usable_family_when_the_other_query_fails() {
        let records = combine_records([
            Ok(Records {
                addresses: vec![IpAddr::V4(Ipv4Addr::LOCALHOST)],
                min_ttl: Duration::from_secs(30),
            }),
            Err(anyhow::anyhow!("DNS UDP query timed out")),
        ])
        .unwrap();
        assert_eq!(records.addresses, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
        assert_eq!(records.min_ttl, Duration::from_secs(30));
    }
    #[test]
    fn rejects_wrong_question() {
        let mut reply = build_query("other.test", TYPE_A, 7).unwrap();
        reply[2] = 0x81;
        reply[3] = 0x80;
        assert!(parse_response(&reply, "example.test", TYPE_A, 7).is_err());
    }

    #[test]
    fn builds_aaaa_query_with_expected_header_and_name() {
        let query = build_query("Api.Example.Test", TYPE_AAAA, 0x1234).unwrap();

        assert_eq!(
            &query[..12],
            &[0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]
        );
        assert_eq!(
            &query[12..],
            &[
                3, b'A', b'p', b'i', 7, b'E', b'x', b'a', b'm', b'p', b'l', b'e', 4, b'T', b'e',
                b's', b't', 0, 0, 28, 0, 1
            ]
        );
    }

    #[test]
    fn rejects_invalid_query_labels() {
        assert!(build_query("", TYPE_A, 1).is_err());
        assert!(build_query("example.", TYPE_A, 1).is_err());
        assert!(build_query(&format!("{}.test", "a".repeat(64)), TYPE_A, 1).is_err());
    }

    #[test]
    fn parses_valid_compressed_aaaa_reply() {
        let mut reply = reply_for("example.test", TYPE_AAAA, 7);
        let address = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 42);
        append_answer(&mut reply, TYPE_AAAA, &address.octets());

        assert_eq!(
            parse_response(&reply, "EXAMPLE.TEST.", TYPE_AAAA, 7).unwrap(),
            vec![IpAddr::V6(address)]
        );
    }

    #[test]
    fn rejects_malformed_response_headers() {
        assert!(parse_response(&[], "example.test", TYPE_A, 7).is_err());

        let mut wrong_id = reply_for("example.test", TYPE_A, 7);
        wrong_id[1] = 8;
        assert!(parse_response(&wrong_id, "example.test", TYPE_A, 7).is_err());

        let mut query_not_response = reply_for("example.test", TYPE_A, 7);
        query_not_response[2] = 0x01;
        assert!(parse_response(&query_not_response, "example.test", TYPE_A, 7).is_err());

        let mut missing_question = reply_for("example.test", TYPE_A, 7);
        missing_question[4..6].copy_from_slice(&0_u16.to_be_bytes());
        assert!(parse_response(&missing_question, "example.test", TYPE_A, 7).is_err());
    }

    #[test]
    fn rejects_truncated_and_invalid_answer_records() {
        let mut truncated = reply_for("example.test", TYPE_A, 7);
        append_answer(&mut truncated, TYPE_A, &[127, 0, 0, 1]);
        truncated.pop();
        assert!(parse_response(&truncated, "example.test", TYPE_A, 7).is_err());

        let mut invalid_a_length = reply_for("example.test", TYPE_A, 7);
        append_answer(&mut invalid_a_length, TYPE_A, &[127, 0, 0]);
        assert!(parse_response(&invalid_a_length, "example.test", TYPE_A, 7).is_err());

        let mut invalid_aaaa_length = reply_for("example.test", TYPE_AAAA, 7);
        append_answer(&mut invalid_aaaa_length, TYPE_AAAA, &[0; 15]);
        assert!(parse_response(&invalid_aaaa_length, "example.test", TYPE_AAAA, 7).is_err());
    }

    #[test]
    fn rejects_invalid_compression_names() {
        let mut cursor = 0;
        assert!(read_name(&[0xc0], &mut cursor).is_err());

        let mut cursor = 0;
        assert!(read_name(&[0xc0, 0x00], &mut cursor).is_err());

        let mut cursor = 0;
        assert!(read_name(&[0x40, 0x00], &mut cursor).is_err());

        let mut cursor = 0;
        assert!(read_name(&[3, b'a', b'b'], &mut cursor).is_err());
    }

    #[test]
    fn derives_dns_server_names_from_socket_addresses() {
        assert_eq!(dns_server_name("resolver.example:853"), "resolver.example");
        assert_eq!(dns_server_name("[2001:db8::53]:853"), "2001:db8::53");
        assert_eq!(dns_server_name("resolver.example"), "resolver.example");
    }

    #[test]
    fn udp_lookup_uses_loopback_server_and_validates_its_reply() {
        runtime::Runtime::new().unwrap().block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = server.local_addr().unwrap();
            let task = runtime::spawn(async move {
                for answer in [true, false] {
                    let BufResult(result, query) = server.recv_from(Vec::with_capacity(512)).await;
                    let (_, peer) = result.unwrap();
                    let mut reply = query[..12].to_vec();
                    reply[2] = 0x81;
                    reply[3] = 0x80;
                    reply[6..8].copy_from_slice(&(answer as u16).to_be_bytes());
                    reply.extend_from_slice(&query[12..]);
                    if answer {
                        reply.extend_from_slice(&[0xc0, 0x0c]);
                        reply.extend_from_slice(&TYPE_A.to_be_bytes());
                        reply.extend_from_slice(&CLASS_IN.to_be_bytes());
                        reply.extend_from_slice(&60_u32.to_be_bytes());
                        reply.extend_from_slice(&4_u16.to_be_bytes());
                        reply.extend_from_slice(&[127, 0, 0, 1]);
                    }
                    let BufResult(result, _) = server.send_to(reply, peer).await;
                    result.unwrap();
                }
            });
            let resolver = Resolver {
                servers: vec![DnsServerConfig {
                    address: address.to_string(),
                    kind: DnsServerKind::Udp,
                    timeout_seconds: 1,
                    tls_host: None,
                }],
                next_server: AtomicUsize::new(0),
                next_id: AtomicUsize::new(20),
                cache: Mutex::new(DnsCache::new(0)),
                cache_enabled: false,
                cache_max_ttl: Duration::from_secs(60),
                negative_cache_ttl: Duration::from_secs(5),
                cache_query: Arc::new(|| {}),
            };
            assert_eq!(
                resolver.lookup("example.test").await.unwrap(),
                vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]
            );
            task.await.unwrap();
        });
    }

    #[test]
    fn warm_udp_lookup_reuses_the_original_query_pair_and_counts_one_cache_query() {
        runtime::Runtime::new().unwrap().block_on(async {
            let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let address = server.local_addr().unwrap();
            let task = runtime::spawn(async move {
                for _ in 0..2 {
                    let BufResult(result, query) = server.recv_from(Vec::with_capacity(512)).await;
                    let (_, peer) = result.unwrap();
                    let qtype =
                        u16::from_be_bytes([query[query.len() - 4], query[query.len() - 3]]);
                    let mut reply = query[..12].to_vec();
                    reply[2] = 0x81;
                    reply[3] = 0x80;
                    reply[6..8].copy_from_slice(&1_u16.to_be_bytes());
                    reply.extend_from_slice(&query[12..]);
                    reply.extend_from_slice(&[0xc0, 0x0c]);
                    reply.extend_from_slice(&qtype.to_be_bytes());
                    reply.extend_from_slice(&CLASS_IN.to_be_bytes());
                    reply.extend_from_slice(&30_u32.to_be_bytes());
                    match qtype {
                        TYPE_A => {
                            reply.extend_from_slice(&4_u16.to_be_bytes());
                            reply.extend_from_slice(&[127, 0, 0, 1]);
                        }
                        TYPE_AAAA => {
                            reply.extend_from_slice(&16_u16.to_be_bytes());
                            reply.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
                        }
                        _ => unreachable!("unexpected DNS query type"),
                    }
                    let BufResult(result, _) = server.send_to(reply, peer).await;
                    result.unwrap();
                }
            });
            let cache_queries = Arc::new(AtomicUsize::new(0));
            let resolver = Resolver {
                servers: vec![DnsServerConfig {
                    address: address.to_string(),
                    kind: DnsServerKind::Udp,
                    timeout_seconds: 1,
                    tls_host: None,
                }],
                next_server: AtomicUsize::new(0),
                next_id: AtomicUsize::new(40),
                cache: Mutex::new(DnsCache::new(4)),
                cache_enabled: true,
                cache_max_ttl: Duration::from_secs(60),
                negative_cache_ttl: Duration::from_secs(5),
                cache_query: {
                    let cache_queries = cache_queries.clone();
                    Arc::new(move || {
                        cache_queries.fetch_add(1, Ordering::Relaxed);
                    })
                },
            };
            let first = resolver.lookup("cache.test").await.unwrap();
            assert_eq!(cache_queries.load(Ordering::Relaxed), 0);
            let second = resolver.lookup("CACHE.TEST.").await.unwrap();
            assert_eq!(first, second);
            assert_eq!(cache_queries.load(Ordering::Relaxed), 1);
            task.await.unwrap();
        });
    }
}
