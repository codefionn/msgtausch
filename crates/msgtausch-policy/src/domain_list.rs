//! Downloaded domain lists and their immutable, synchronous matchers.

use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex, OnceLock, RwLock, Weak},
    thread,
    time::{Duration, Instant},
};

use anyhow::{Context, Result, anyhow, bail};

use msgtausch_config::{CacheConfig, DomainsUrlFormat};

const ERROR_TTL: Duration = Duration::from_secs(5 * 60);

/// An immutable domain set. A match includes a listed domain and its children.
#[derive(Clone, Debug, Default)]
pub struct DomainMatcher {
    domains: HashSet<String>,
}

impl DomainMatcher {
    pub fn new(domains: impl IntoIterator<Item = String>) -> Self {
        let domains = domains
            .into_iter()
            .filter_map(|domain| normalize_domain(&domain))
            .collect();
        Self { domains }
    }

    /// Build a matcher from tokens already normalized by the legacy local
    /// domains-file reader. Unlike remote list entries, local tokens may be
    /// single labels, IP-like values, or otherwise non-DNS strings.
    pub fn from_local_tokens(domains: impl IntoIterator<Item = String>) -> Self {
        Self {
            domains: domains.into_iter().collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.domains.len()
    }

    pub fn is_empty(&self) -> bool {
        self.domains.is_empty()
    }

    /// This only reads an immutable hash set. Callers which already normalize
    /// hosts avoid an allocation; other callers pay for one lowercase copy.
    pub fn matches(&self, host: &str) -> bool {
        let host = host.trim_matches('.');
        if host.is_empty() {
            return false;
        }
        if host.bytes().any(|byte| byte.is_ascii_uppercase()) {
            return self.matches_normalized(&host.to_ascii_lowercase());
        }
        self.matches_normalized(host)
    }

    fn matches_normalized(&self, mut host: &str) -> bool {
        loop {
            if self.domains.contains(host) {
                return true;
            }
            let Some((_, parent)) = host.split_once('.') else {
                return false;
            };
            host = parent;
        }
    }
}

#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct CacheKey {
    primary: String,
    mirrors: Vec<String>,
    format: u8,
}

impl CacheKey {
    fn new(primary: String, mirrors: Vec<String>, format: DomainsUrlFormat) -> Self {
        let format = match format {
            DomainsUrlFormat::Rpz => 0,
            DomainsUrlFormat::Wildcard => 1,
            DomainsUrlFormat::Adblock => 2,
            DomainsUrlFormat::Plain => 3,
        };
        Self {
            primary,
            mirrors,
            format,
        }
    }
}

#[derive(Debug)]
enum CachedResult {
    Success {
        matcher: Arc<DomainMatcher>,
        expires_at: Instant,
    },
    Failure {
        message: String,
        expires_at: Instant,
    },
}

impl CachedResult {
    fn is_fresh(&self) -> bool {
        match self {
            Self::Success { expires_at, .. } | Self::Failure { expires_at, .. } => {
                Instant::now() < *expires_at
            }
        }
    }
}

#[derive(Debug, Default)]
struct SharedCacheEntry {
    value: RwLock<Option<CachedResult>>,
    fetch_lock: Mutex<()>,
}

fn cache() -> &'static Mutex<HashMap<CacheKey, Weak<SharedCacheEntry>>> {
    static CACHE: OnceLock<Mutex<HashMap<CacheKey, Weak<SharedCacheEntry>>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn shared_entry(key: &CacheKey) -> Arc<SharedCacheEntry> {
    let mut cache = cache().lock().expect("domain-list cache lock poisoned");
    cache.retain(|_, entry| entry.strong_count() != 0);
    if let Some(entry) = cache.get(key).and_then(Weak::upgrade) {
        return entry;
    }
    let entry = Arc::new(SharedCacheEntry::default());
    cache.insert(key.clone(), Arc::downgrade(&entry));
    entry
}

/// A remotely fetched list. `matches` never performs I/O. Lifecycle code can
/// call `refresh` periodically to replace its matcher after the configured TTL.
#[derive(Debug)]
pub struct RemoteDomainList {
    key: CacheKey,
    format: DomainsUrlFormat,
    request_timeout: Duration,
    ttl: Duration,
    max_retries: usize,
    retry_delay: Duration,
    entry: Arc<SharedCacheEntry>,
}

impl RemoteDomainList {
    pub fn new(
        url: String,
        mirrors: Vec<String>,
        format: DomainsUrlFormat,
        timeout_seconds: u64,
        cache_config: &CacheConfig,
    ) -> Result<Self> {
        if url.trim().is_empty() {
            bail!("domains-url primary URL must not be empty");
        }
        let key = CacheKey::new(url, mirrors, format);
        let list = Self {
            entry: shared_entry(&key),
            key,
            format,
            request_timeout: Duration::from_secs(timeout_seconds.max(1)),
            ttl: Duration::from_secs(cache_config.default_ttl_seconds.max(1)),
            max_retries: cache_config.max_retries,
            retry_delay: Duration::from_secs(cache_config.retry_delay_seconds),
        };
        // A failed source is a cached false matcher, not a startup failure.
        // The next lifecycle refresh can replace it when a primary or mirror
        // comes back.
        let _ = list.load(false);
        Ok(list)
    }

    pub fn matches(&self, host: &str) -> bool {
        let value = self
            .entry
            .value
            .read()
            .expect("domain-list cache lock poisoned");
        match value.as_ref() {
            Some(CachedResult::Success { matcher, .. }) => matcher.matches(host),
            Some(CachedResult::Failure { .. }) | None => false,
        }
    }

    /// Download a replacement. This keeps the prior immutable matcher
    /// available to concurrent matchers until the replacement is ready.
    pub fn refresh(&self) -> Result<()> {
        self.load(true)
    }

    /// Force a download even if the current entry has not reached its TTL.
    pub fn refresh_now(&self) -> Result<()> {
        self.load(true)
    }

    pub fn domain_count(&self) -> usize {
        let value = self
            .entry
            .value
            .read()
            .expect("domain-list cache lock poisoned");
        match value.as_ref() {
            Some(CachedResult::Success { matcher, .. }) => matcher.len(),
            Some(CachedResult::Failure { .. }) | None => 0,
        }
    }

    fn load(&self, force: bool) -> Result<()> {
        if !force && let Some(result) = self.cached_result() {
            return result;
        }

        // This second check under the lock makes constructor and refresh calls
        // for an identical URL set coalesce into a single download.
        let _fetch = self
            .entry
            .fetch_lock
            .lock()
            .expect("domain-list fetch lock poisoned");
        if !force && let Some(result) = self.cached_result() {
            return result;
        }

        let result = self.fetch_with_fallback();
        let cached = match &result {
            Ok(matcher) => CachedResult::Success {
                matcher: Arc::clone(matcher),
                expires_at: Instant::now() + self.ttl,
            },
            Err(error) => CachedResult::Failure {
                message: error.to_string(),
                expires_at: Instant::now() + ERROR_TTL,
            },
        };
        *self
            .entry
            .value
            .write()
            .expect("domain-list cache lock poisoned") = Some(cached);
        result.map(|_| ())
    }

    fn cached_result(&self) -> Option<Result<()>> {
        let value = self
            .entry
            .value
            .read()
            .expect("domain-list cache lock poisoned");
        let value = value.as_ref()?;
        if !value.is_fresh() {
            return None;
        }
        Some(match value {
            CachedResult::Success { .. } => Ok(()),
            CachedResult::Failure { message, .. } => Err(anyhow!(message.clone())),
        })
    }

    fn fetch_with_fallback(&self) -> Result<Arc<DomainMatcher>> {
        let mut last_error = None;
        for url in std::iter::once(&self.key.primary).chain(self.key.mirrors.iter()) {
            for attempt in 0..=self.max_retries {
                if attempt != 0 && !self.retry_delay.is_zero() {
                    thread::sleep(self.retry_delay);
                }
                match fetch_domains(url, self.format, self.request_timeout) {
                    Ok(domains) => return Ok(Arc::new(DomainMatcher::new(domains))),
                    Err(error) => last_error = Some(error),
                }
            }
        }
        Err(last_error.unwrap_or_else(|| anyhow!("no domains-url endpoints configured")))
            .with_context(|| {
                format!(
                    "failed to fetch domain list from {} and its mirrors",
                    self.key.primary
                )
            })
    }
}

fn fetch_domains(url: &str, format: DomainsUrlFormat, timeout: Duration) -> Result<Vec<String>> {
    let agent = ureq::Agent::config_builder()
        .timeout_global(Some(timeout))
        .build()
        .new_agent();
    let response = agent
        .get(url)
        .header("User-Agent", "msgtausch/0.1")
        .call()
        .with_context(|| format!("GET {url} failed"))?;
    if !response.status().is_success() {
        bail!("GET {url} returned HTTP {}", response.status());
    }
    let body = response
        .into_body()
        .read_to_string()
        .with_context(|| format!("could not read response body from {url}"))?;
    Ok(parse_domains(&body, format))
}

fn parse_domains(content: &str, format: DomainsUrlFormat) -> Vec<String> {
    content
        .lines()
        .filter_map(|line| parse_line(line, format))
        .collect()
}

fn parse_line(line: &str, format: DomainsUrlFormat) -> Option<String> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }
    let domain = match format {
        DomainsUrlFormat::Plain => {
            if line.starts_with('#') {
                return None;
            }
            line
        }
        DomainsUrlFormat::Wildcard => {
            if line.starts_with('#') {
                return None;
            }
            line.strip_prefix("*.")?
        }
        DomainsUrlFormat::Adblock => {
            if line.starts_with('!') {
                return None;
            }
            line.strip_prefix("||")?.strip_suffix('^')?
        }
        DomainsUrlFormat::Rpz => {
            if line.starts_with(';') || line.starts_with('$') || line == "NS  localhost." {
                return None;
            }
            let mut fields = line.split_ascii_whitespace();
            let domain = fields.next()?;
            (fields.next()?.eq_ignore_ascii_case("CNAME")
                && fields.next()? == "."
                && fields.next().is_none())
            .then_some(domain)?
        }
    };
    normalize_domain(domain)
}

fn normalize_domain(domain: &str) -> Option<String> {
    let domain = domain
        .trim()
        .trim_start_matches("*.")
        .trim_matches('.')
        .to_ascii_lowercase();
    if domain == "localhost" || domain == "0.0.0.0" || !domain.contains('.') {
        return None;
    }
    if domain
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'.' || byte == b'-')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
    {
        Some(domain)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_all_configured_formats() {
        let cases = [
            (
                DomainsUrlFormat::Plain,
                "# comment\nExample.COM\n",
                "example.com",
            ),
            (DomainsUrlFormat::Wildcard, "*.example.com\n", "example.com"),
            (
                DomainsUrlFormat::Adblock,
                "! comment\n||example.com^\n",
                "example.com",
            ),
            (
                DomainsUrlFormat::Rpz,
                "; comment\nexample.com CNAME .\n",
                "example.com",
            ),
        ];
        for (format, content, expected) in cases {
            assert_eq!(parse_domains(content, format), vec![expected.to_owned()]);
        }
    }

    #[test]
    fn ignores_non_rules_and_normalizes_domains() {
        assert!(parse_domains("example.com # inline\n", DomainsUrlFormat::Plain).is_empty());
        assert!(parse_domains("||example.com/path^\n", DomainsUrlFormat::Adblock).is_empty());
        assert!(parse_domains("example.com A 127.0.0.1\n", DomainsUrlFormat::Rpz).is_empty());
    }

    #[test]
    fn matcher_matches_a_domain_and_its_children() {
        let matcher = DomainMatcher::new(["example.com".to_owned()]);
        assert!(matcher.matches("EXAMPLE.COM."));
        assert!(matcher.matches("api.example.com"));
        assert!(!matcher.matches("notexample.com"));
    }
}
