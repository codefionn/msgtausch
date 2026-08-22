use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    net::IpAddr,
    path::{Path, PathBuf},
    str::FromStr,
};

use serde_json::{Map, Value};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("failed to read configuration: {0}")]
    Read(#[from] std::io::Error),
    #[error("failed to parse configuration: {0}")]
    Parse(String),
    #[error("unsupported config file format: {0}")]
    UnsupportedFormat(String),
    #[error("invalid configuration: {0}")]
    Invalid(String),
}

pub type Result<T> = std::result::Result<T, ConfigError>;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Config {
    pub servers: Vec<ServerConfig>,
    pub timeout_seconds: u64,
    pub max_idle_conns: usize,
    pub max_idle_conns_per_host: usize,
    pub classifiers: BTreeMap<String, Classifier>,
    pub forwards: Vec<Forward>,
    pub allowlist: Option<Classifier>,
    pub blocklist: Option<Classifier>,
    pub interception: InterceptionConfig,
    pub cache: CacheConfig,
    pub dns: DnsConfig,
    pub observability: ObservabilityConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            servers: vec![ServerConfig::default()],
            timeout_seconds: 30,
            max_idle_conns: 2048,
            max_idle_conns_per_host: 256,
            classifiers: BTreeMap::new(),
            forwards: Vec::new(),
            allowlist: None,
            blocklist: None,
            interception: InterceptionConfig::default(),
            cache: CacheConfig::default(),
            dns: DnsConfig::default(),
            observability: ObservabilityConfig::default(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerConfig {
    pub kind: ServerKind,
    pub listen_address: String,
    pub enabled: bool,
    pub interceptor_name: Option<String>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            kind: ServerKind::Standard,
            listen_address: "127.0.0.1:8080".into(),
            enabled: true,
            interceptor_name: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ServerKind {
    #[default]
    Standard,
    Http,
    Https,
    Quic,
}

impl FromStr for ServerKind {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "standard" => Ok(Self::Standard),
            "http" => Ok(Self::Http),
            "https" => Ok(Self::Https),
            "quic" => Ok(Self::Quic),
            _ => Err(ConfigError::Invalid(format!(
                "unsupported server type `{value}`"
            ))),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct InterceptionConfig {
    pub enabled: bool,
    pub http: bool,
    pub https: bool,
    pub https_classifier: Option<Classifier>,
    pub exclude_classifier: Option<Classifier>,
    pub ca_file: Option<PathBuf>,
    pub ca_key_file: Option<PathBuf>,
    pub ca_key_passwd: Option<String>,
    pub insecure_skip_verify: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CacheConfig {
    pub enabled: bool,
    pub default_ttl_seconds: u64,
    pub refresh_interval_seconds: u64,
    pub http_timeout_seconds: u64,
    pub max_retries: usize,
    pub retry_delay_seconds: u64,
    pub chunked_ac_enabled: bool,
    pub chunk_size: usize,
    pub chunk_threshold: usize,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            default_ttl_seconds: 3600,
            refresh_interval_seconds: 300,
            http_timeout_seconds: 30,
            max_retries: 3,
            retry_delay_seconds: 5,
            chunked_ac_enabled: true,
            chunk_size: 2048,
            chunk_threshold: 2048,
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DnsConfig {
    pub enabled: bool,
    pub servers: Vec<DnsServerConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DnsServerConfig {
    pub address: String,
    pub kind: DnsServerKind,
    pub timeout_seconds: u64,
    pub tls_host: Option<String>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DnsServerKind {
    #[default]
    Udp,
    Tcp,
    Dot,
}

impl FromStr for DnsServerKind {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "udp" => Ok(Self::Udp),
            "tcp" => Ok(Self::Tcp),
            "dot" => Ok(Self::Dot),
            _ => Err(ConfigError::Invalid(format!(
                "unsupported DNS server type `{value}`"
            ))),
        }
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservabilityConfig {
    pub prometheus_listen_address: Option<String>,
    pub otlp_endpoint: Option<String>,
    pub otlp_service_name: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Forward {
    pub kind: ForwardKind,
    pub classifier: Classifier,
    pub force_ipv4: bool,
    pub log: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForwardKind {
    Direct,
    Socks5 {
        address: String,
        username: Option<String>,
        password: Option<String>,
    },
    HttpProxy {
        address: String,
        username: Option<String>,
        password: Option<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Classifier {
    True,
    False,
    And(Vec<Classifier>),
    Or(Vec<Classifier>),
    Not(Box<Classifier>),
    Domain {
        op: DomainOp,
        domain: String,
    },
    Ref(String),
    Ip(String),
    Network(String),
    Port(u16),
    DomainsFile(PathBuf),
    DomainsUrl {
        url: String,
        mirrors: Vec<String>,
        format: DomainsUrlFormat,
        timeout_seconds: u64,
    },
    /// Retained for config compatibility. The Rust service never records bodies.
    Record(Box<Classifier>),
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum DomainOp {
    #[default]
    Equal,
    NotEqual,
    Contains,
    NotContains,
    Is,
}

impl FromStr for DomainOp {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "equal" => Ok(Self::Equal),
            "not-equal" => Ok(Self::NotEqual),
            "contains" => Ok(Self::Contains),
            "not-contains" => Ok(Self::NotContains),
            "is" => Ok(Self::Is),
            _ => Err(ConfigError::Invalid(format!(
                "unsupported domain operator `{value}`"
            ))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DomainsUrlFormat {
    Rpz,
    Wildcard,
    Adblock,
    Plain,
}

impl FromStr for DomainsUrlFormat {
    type Err = ConfigError;

    fn from_str(value: &str) -> Result<Self> {
        match value {
            "rpz" => Ok(Self::Rpz),
            "wildcard" => Ok(Self::Wildcard),
            "adblock" => Ok(Self::Adblock),
            "plain" => Ok(Self::Plain),
            _ => Err(ConfigError::Invalid(format!(
                "unsupported domains-url format `{value}`"
            ))),
        }
    }
}

/// A connection target used by classifier and forwarding code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Target {
    pub host: String,
    pub port: u16,
    pub ip: Option<IpAddr>,
}

impl Config {
    /// Loads one file from defaults, then applies the supplied environment.
    pub fn load_file(
        path: impl AsRef<Path>,
        environment: &BTreeMap<String, String>,
    ) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path)?;
        let extension = path
            .extension()
            .and_then(|extension| extension.to_str())
            .unwrap_or_default()
            .to_ascii_lowercase();
        let value = match extension.as_str() {
            "json" => serde_json::from_str(&text)
                .map_err(|error| ConfigError::Parse(format!("JSON: {error}")))?,
            "hcl" => {
                hcl::from_str(&text).map_err(|error| ConfigError::Parse(format!("HCL: {error}")))?
            }
            _ => return Err(ConfigError::UnsupportedFormat(extension)),
        };
        let mut config = Self::from_value(value, environment)?;
        config.apply_environment(environment)?;
        config.validate()?;
        Ok(config)
    }

    /// Loads each path independently. Later successful paths replace prior ones.
    /// A failed first path falls back to an environment-only configuration.
    pub fn load_paths(paths: &[PathBuf], environment: &BTreeMap<String, String>) -> Result<Self> {
        let paths = if paths.is_empty() {
            vec![PathBuf::from("config.json")]
        } else {
            paths.to_vec()
        };
        let mut selected = None;
        let mut first_error = None;
        for (index, path) in paths.iter().enumerate() {
            match Self::load_file(path, environment) {
                Ok(config) => selected = Some(config),
                Err(error) if index == 0 => {
                    first_error = Some(error);
                    if let Ok(config) = Self::from_environment(environment) {
                        selected = Some(config);
                    }
                }
                Err(_) => {}
            }
        }
        selected.ok_or_else(|| {
            first_error
                .unwrap_or_else(|| ConfigError::Invalid("no configuration could be loaded".into()))
        })
    }

    pub fn from_environment(environment: &BTreeMap<String, String>) -> Result<Self> {
        let mut config = Self::default();
        config.apply_environment(environment)?;
        config.validate()?;
        Ok(config)
    }

    /// Environment inherited by the service, with a dotenv file taking precedence.
    pub fn current_environment(envfile: Option<&Path>) -> Result<BTreeMap<String, String>> {
        let mut values = env::vars().collect::<BTreeMap<_, _>>();
        if let Some(path) = envfile {
            values.extend(read_dotenv(path)?);
        }
        Ok(values)
    }

    pub fn select_forward<'a>(&'a self, target: &Target) -> Option<&'a Forward> {
        self.forwards.iter().find(|forward| {
            self.matches_classifier(&forward.classifier, target, &mut BTreeSet::new())
        })
    }

    pub fn allows(&self, target: &Target) -> bool {
        let mut seen = BTreeSet::new();
        let allowed = self
            .allowlist
            .as_ref()
            .is_none_or(|classifier| self.matches_classifier(classifier, target, &mut seen));
        allowed
            && self.blocklist.as_ref().is_none_or(|classifier| {
                !self.matches_classifier(classifier, target, &mut BTreeSet::new())
            })
    }

    pub fn validate(&self) -> Result<()> {
        for server in self.servers.iter().filter(|server| server.enabled) {
            validate_address(&server.listen_address, "server listen-address")?;
        }
        for forward in &self.forwards {
            match &forward.kind {
                ForwardKind::Direct => {}
                ForwardKind::Socks5 { address, .. } | ForwardKind::HttpProxy { address, .. } => {
                    validate_address(address, "forward address")?;
                }
            }
            validate_classifier(&forward.classifier, &self.classifiers)?;
        }
        for classifier in self.classifiers.values() {
            validate_classifier(classifier, &self.classifiers)?;
        }
        for classifier in [&self.allowlist, &self.blocklist].into_iter().flatten() {
            validate_classifier(classifier, &self.classifiers)?;
        }
        for server in &self.dns.servers {
            validate_address(&server.address, "DNS server address")?;
            if server.timeout_seconds == 0 {
                return Err(ConfigError::Invalid(
                    "DNS server timeout-seconds must be greater than zero".into(),
                ));
            }
        }
        if let Some(address) = &self.observability.prometheus_listen_address {
            validate_address(address, "prometheus-listen-address")?;
        }
        Ok(())
    }

    fn matches_classifier(
        &self,
        classifier: &Classifier,
        target: &Target,
        resolving: &mut BTreeSet<String>,
    ) -> bool {
        match classifier {
            Classifier::True => true,
            Classifier::False => false,
            Classifier::And(items) => items
                .iter()
                .all(|item| self.matches_classifier(item, target, resolving)),
            Classifier::Or(items) => items
                .iter()
                .any(|item| self.matches_classifier(item, target, resolving)),
            Classifier::Not(item) => !self.matches_classifier(item, target, resolving),
            Classifier::Domain { op, domain } => match op {
                DomainOp::Equal => target.host == *domain,
                DomainOp::NotEqual => target.host != *domain,
                DomainOp::Contains => target.host.contains(domain),
                DomainOp::NotContains => !target.host.contains(domain),
                DomainOp::Is => {
                    target.host == *domain || target.host.ends_with(&format!(".{domain}"))
                }
            },
            Classifier::Ref(name) => {
                if !resolving.insert(name.clone()) {
                    return false;
                }
                let matched = self
                    .classifiers
                    .get(name)
                    .is_some_and(|item| self.matches_classifier(item, target, resolving));
                resolving.remove(name);
                matched
            }
            Classifier::Ip(value) => target.ip.is_some_and(|ip| ip.to_string() == *value),
            Classifier::Network(cidr) => target.ip.is_some_and(|ip| {
                cidr.parse::<ipnet::IpNet>()
                    .is_ok_and(|network| network.contains(&ip))
            }),
            Classifier::Port(port) => target.port == *port,
            // Loading domain data belongs to the proxy cache. These classifiers are intentionally not
            // evaluated before that cache is attached to a runtime.
            Classifier::DomainsFile(_) | Classifier::DomainsUrl { .. } => false,
            Classifier::Record(item) => self.matches_classifier(item, target, resolving),
        }
    }

    fn from_value(value: Value, environment: &BTreeMap<String, String>) -> Result<Self> {
        let root = object(value, "root configuration")?;
        reject_underscore_keys(&root, "root configuration")?;
        reject_unknown_keys(
            &root,
            &[
                "servers",
                "listen-address",
                "timeout-seconds",
                "max-idle-conns",
                "max-idle-conns-per-host",
                "max-concurrent-connections",
                "classifiers",
                "forwards",
                "allowlist",
                "blocklist",
                "interception",
                "cache",
                "dns",
                "observability",
                "portal",
                "statistics",
            ],
            "root configuration",
        )?;
        let mut config = Self::default();
        if let Some(value) = root.get("servers") {
            config.servers = array(value, "servers")?
                .iter()
                .enumerate()
                .map(|(index, value)| parse_server(value, index, environment))
                .collect::<Result<Vec<_>>>()?;
        }
        if let Some(value) = root.get("listen-address") {
            config.servers = vec![ServerConfig {
                listen_address: string(value, environment, "listen-address")?,
                ..ServerConfig::default()
            }];
        }
        set_u64(
            &mut config.timeout_seconds,
            root.get("timeout-seconds"),
            environment,
            "timeout-seconds",
        )?;
        set_usize(
            &mut config.max_idle_conns,
            root.get("max-idle-conns"),
            environment,
            "max-idle-conns",
        )?;
        set_usize(
            &mut config.max_idle_conns_per_host,
            root.get("max-idle-conns-per-host"),
            environment,
            "max-idle-conns-per-host",
        )?;
        if let Some(value) = root.get("classifiers") {
            let values = object(value.clone(), "classifiers")?;
            config.classifiers = values
                .iter()
                .map(|(name, classifier)| {
                    Ok((name.clone(), parse_classifier(classifier, environment)?))
                })
                .collect::<Result<_>>()?;
        }
        if let Some(value) = root.get("allowlist") {
            config.allowlist = Some(parse_classifier(value, environment)?);
        }
        if let Some(value) = root.get("blocklist") {
            config.blocklist = Some(parse_classifier(value, environment)?);
        }
        if let Some(value) = root.get("forwards") {
            config.forwards = array(value, "forwards")?
                .iter()
                .map(|value| parse_forward(value, environment))
                .collect::<Result<_>>()?;
        }
        if let Some(value) = root.get("interception") {
            config.interception = parse_interception(value, environment)?;
        }
        if let Some(value) = root.get("cache") {
            config.cache = parse_cache(value, environment)?;
        }
        if let Some(value) = root.get("dns") {
            config.dns = parse_dns(value, environment)?;
        }
        if let Some(value) = root.get("observability") {
            config.observability = parse_observability(value, environment)?;
        }
        Ok(config)
    }

    fn apply_environment(&mut self, environment: &BTreeMap<String, String>) -> Result<()> {
        set_env_u64(
            &mut self.timeout_seconds,
            environment,
            "MSGTAUSCH_TIMEOUTSECONDS",
        )?;
        set_env_usize(
            &mut self.max_idle_conns,
            environment,
            "MSGTAUSCH_MAXIDLECONNS",
        )?;
        set_env_usize(
            &mut self.max_idle_conns_per_host,
            environment,
            "MSGTAUSCH_MAXIDLECONNSPERHOST",
        )?;
        set_env_bool(
            &mut self.interception.enabled,
            environment,
            "MSGTAUSCH_INTERCEPT",
        )?;
        set_env_bool(
            &mut self.interception.http,
            environment,
            "MSGTAUSCH_INTERCEPTHTTP",
        )?;
        set_env_bool(
            &mut self.interception.https,
            environment,
            "MSGTAUSCH_INTERCEPTHTTPS",
        )?;
        if let Some(value) = environment.get("MSGTAUSCH_HTTPSCLASSIFIER") {
            self.interception.https_classifier = Some(Classifier::Ref(value.clone()));
        }
        if let Some(value) = environment.get("MSGTAUSCH_EXCLUDECLASSIFIER") {
            self.interception.exclude_classifier = Some(Classifier::Ref(value.clone()));
        }
        set_env_path(
            &mut self.interception.ca_file,
            environment,
            "MSGTAUSCH_CAFILE",
        );
        set_env_path(
            &mut self.interception.ca_key_file,
            environment,
            "MSGTAUSCH_CAKEYFILE",
        );
        set_env_string(
            &mut self.interception.ca_key_passwd,
            environment,
            "MSGTAUSCH_CAKEYPASSWD",
        );
        set_env_bool(
            &mut self.interception.insecure_skip_verify,
            environment,
            "MSGTAUSCH_INSECURE_SKIP_VERIFY",
        )?;
        if let Some(value) = environment.get("MSGTAUSCH_LISTENADDRESS") {
            if let Some(server) = self.servers.first_mut() {
                server.listen_address = value.clone();
            } else {
                self.servers.push(ServerConfig {
                    listen_address: value.clone(),
                    ..ServerConfig::default()
                });
            }
        }
        for index in 0.. {
            let prefix = format!("MSGTAUSCH_SERVER_{index}_");
            let Some(address) = environment.get(&(prefix.clone() + "LISTENADDRESS")) else {
                break;
            };
            let server = self.servers.get_mut(index);
            let server = if let Some(server) = server {
                server
            } else {
                self.servers.push(ServerConfig::default());
                self.servers.last_mut().expect("server was just pushed")
            };
            server.listen_address = address.clone();
            if let Some(kind) = environment.get(&(prefix.clone() + "TYPE")) {
                server.kind = kind.parse()?;
            }
            if let Some(enabled) = environment.get(&(prefix.clone() + "ENABLED")) {
                server.enabled = parse_bool(enabled, &(prefix.clone() + "ENABLED"))?;
            }
            if self.interception.ca_file.is_none() {
                set_env_path(
                    &mut self.interception.ca_file,
                    environment,
                    &(prefix.clone() + "CAFILE"),
                );
            }
            if self.interception.ca_key_file.is_none() {
                set_env_path(
                    &mut self.interception.ca_key_file,
                    environment,
                    &(prefix + "CAKEYFILE"),
                );
            }
        }
        set_env_bool(&mut self.dns.enabled, environment, "MSGTAUSCH_DNS_ENABLED")?;
        set_env_bool(
            &mut self.cache.enabled,
            environment,
            "MSGTAUSCH_CACHE_ENABLED",
        )?;
        set_env_u64(
            &mut self.cache.default_ttl_seconds,
            environment,
            "MSGTAUSCH_CACHE_DEFAULT_TTL",
        )?;
        set_env_u64(
            &mut self.cache.refresh_interval_seconds,
            environment,
            "MSGTAUSCH_CACHE_REFRESH_INTERVAL",
        )?;
        set_env_u64(
            &mut self.cache.http_timeout_seconds,
            environment,
            "MSGTAUSCH_CACHE_HTTP_TIMEOUT",
        )?;
        set_env_usize(
            &mut self.cache.max_retries,
            environment,
            "MSGTAUSCH_CACHE_MAX_RETRIES",
        )?;
        set_env_u64(
            &mut self.cache.retry_delay_seconds,
            environment,
            "MSGTAUSCH_CACHE_RETRY_DELAY",
        )?;
        let mut environment_servers = Vec::new();
        for index in 0.. {
            let prefix = format!("MSGTAUSCH_DNS_SERVER_{index}_");
            let Some(address) = environment.get(&(prefix.clone() + "ADDRESS")) else {
                break;
            };
            environment_servers.push(DnsServerConfig {
                address: address.clone(),
                kind: environment
                    .get(&(prefix.clone() + "TYPE"))
                    .map_or(Ok(DnsServerKind::Udp), |value| value.parse())?,
                timeout_seconds: environment
                    .get(&(prefix.clone() + "TIMEOUT_SECONDS"))
                    .map_or(Ok(10), |value| {
                        parse_u64(value, &(prefix.clone() + "TIMEOUT_SECONDS"))
                    })?,
                tls_host: environment.get(&(prefix + "TLS_HOST")).cloned(),
            });
        }
        if !environment_servers.is_empty() {
            self.dns.servers = environment_servers;
        }
        set_env_string(
            &mut self.observability.prometheus_listen_address,
            environment,
            "MSGTAUSCH_PROMETHEUS_LISTEN_ADDRESS",
        );
        set_env_string(
            &mut self.observability.otlp_endpoint,
            environment,
            "MSGTAUSCH_OTLP_ENDPOINT",
        );
        set_env_string(
            &mut self.observability.otlp_service_name,
            environment,
            "MSGTAUSCH_OTLP_SERVICE_NAME",
        );
        Ok(())
    }
}

fn read_dotenv(path: &Path) -> Result<BTreeMap<String, String>> {
    let mut values = BTreeMap::new();
    for line in fs::read_to_string(path)?.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if key.is_empty() {
            continue;
        }
        let value = value.trim().trim_matches(['\'', '"']);
        values.insert(key.to_owned(), value.to_owned());
    }
    Ok(values)
}

fn reject_underscore_keys(values: &Map<String, Value>, context: &str) -> Result<()> {
    const HYPHENATED: &[&str] = &[
        "listen-address",
        "timeout-seconds",
        "max-idle-conns",
        "max-idle-conns-per-host",
        "max-concurrent-connections",
        "max-connections",
        "connections-per-client",
        "interceptor-name",
        "force-ipv4",
        "ca-file",
        "ca-key-file",
        "ca-key-passwd",
        "insecure-skip-verify",
        "https-classifier",
        "exclude-classifier",
        "domains-file",
        "domains-url",
        "not-equal",
        "not-contains",
        "default-network",
        "tls-host",
        "prometheus-listen-address",
        "otlp-endpoint",
        "otlp-service-name",
        "default-ttl",
        "refresh-interval",
        "http-timeout",
        "max-retries",
        "retry-delay",
        "chunked-ac-enabled",
        "chunk-size",
        "chunk-threshold",
    ];
    for (key, value) in values {
        // These blocks only configured the removed database collector and admin portal.
        // Do not inspect them, since a legacy installation may retain unavailable secrets here.
        if matches!(key.as_str(), "portal" | "statistics") {
            continue;
        }
        if key != "_secret" {
            let hyphenated = key.replace('_', "-");
            if key != &hyphenated && HYPHENATED.contains(&hyphenated.as_str()) {
                return Err(ConfigError::Invalid(format!(
                    "invalid {context} key `{key}`: use `{hyphenated}`"
                )));
            }
        }
        match value {
            Value::Object(child) => reject_underscore_keys(child, context)?,
            Value::Array(items) => {
                for item in items {
                    if let Value::Object(child) = item {
                        reject_underscore_keys(child, context)?;
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn reject_unknown_keys(values: &Map<String, Value>, allowed: &[&str], context: &str) -> Result<()> {
    if let Some(key) = values.keys().find(|key| !allowed.contains(&key.as_str())) {
        return Err(ConfigError::Invalid(format!(
            "unknown {context} key `{key}`"
        )));
    }
    Ok(())
}

fn object(value: Value, context: &str) -> Result<Map<String, Value>> {
    value
        .as_object()
        .cloned()
        .ok_or_else(|| ConfigError::Invalid(format!("{context} must be an object")))
}

fn array<'a>(value: &'a Value, context: &str) -> Result<&'a [Value]> {
    value
        .as_array()
        .map(Vec::as_slice)
        .ok_or_else(|| ConfigError::Invalid(format!("{context} must be an array")))
}

fn secret(value: &Value, environment: &BTreeMap<String, String>) -> Result<Option<String>> {
    let Some(object) = value.as_object() else {
        return Ok(None);
    };
    let Some(name) = object.get("_secret").and_then(Value::as_str) else {
        return Ok(None);
    };
    reject_unknown_keys(object, &["_secret"], "secret reference")?;
    environment
        .get(name)
        .cloned()
        .map(Some)
        .ok_or_else(|| ConfigError::Invalid(format!("secret `{name}` is not set")))
}

fn string(value: &Value, environment: &BTreeMap<String, String>, context: &str) -> Result<String> {
    if let Some(value) = secret(value, environment)? {
        return Ok(value);
    }
    value
        .as_str()
        .map(str::to_owned)
        .ok_or_else(|| ConfigError::Invalid(format!("{context} must be a string")))
}

fn optional_string(
    value: Option<&Value>,
    environment: &BTreeMap<String, String>,
    context: &str,
) -> Result<Option<String>> {
    value
        .map(|value| string(value, environment, context))
        .transpose()
}

fn bool_value(
    value: &Value,
    environment: &BTreeMap<String, String>,
    context: &str,
) -> Result<bool> {
    if let Some(value) = secret(value, environment)? {
        return parse_bool(&value, context);
    }
    value
        .as_bool()
        .ok_or_else(|| ConfigError::Invalid(format!("{context} must be a boolean")))
}

fn u64_value(value: &Value, environment: &BTreeMap<String, String>, context: &str) -> Result<u64> {
    if let Some(value) = secret(value, environment)? {
        return parse_u64(&value, context);
    }
    value
        .as_u64()
        .ok_or_else(|| ConfigError::Invalid(format!("{context} must be a non-negative integer")))
}

fn set_u64(
    field: &mut u64,
    value: Option<&Value>,
    environment: &BTreeMap<String, String>,
    context: &str,
) -> Result<()> {
    if let Some(value) = value {
        *field = u64_value(value, environment, context)?;
    }
    Ok(())
}

fn set_usize(
    field: &mut usize,
    value: Option<&Value>,
    environment: &BTreeMap<String, String>,
    context: &str,
) -> Result<()> {
    if let Some(value) = value {
        *field = usize::try_from(u64_value(value, environment, context)?)
            .map_err(|_| ConfigError::Invalid(format!("{context} is too large")))?;
    }
    Ok(())
}

fn parse_server(
    value: &Value,
    index: usize,
    environment: &BTreeMap<String, String>,
) -> Result<ServerConfig> {
    let values = object(value.clone(), &format!("server at index {index}"))?;
    reject_unknown_keys(
        &values,
        &[
            "type",
            "listen-address",
            "enabled",
            "interceptor-name",
            "max-connections",
            "connections-per-client",
        ],
        &format!("server at index {index}"),
    )?;
    let mut server = ServerConfig::default();
    if let Some(value) = values.get("type") {
        server.kind = string(value, environment, "server type")?.parse()?;
    }
    if let Some(value) = values.get("listen-address") {
        server.listen_address = string(value, environment, "server listen-address")?;
    }
    if let Some(value) = values.get("enabled") {
        server.enabled = bool_value(value, environment, "server enabled")?;
    }
    server.interceptor_name = optional_string(
        values.get("interceptor-name"),
        environment,
        "server interceptor-name",
    )?;
    Ok(server)
}

fn parse_forward(value: &Value, environment: &BTreeMap<String, String>) -> Result<Forward> {
    let values = object(value.clone(), "forward")?;
    reject_unknown_keys(
        &values,
        &[
            "type",
            "classifier",
            "force-ipv4",
            "log",
            "address",
            "username",
            "password",
        ],
        "forward",
    )?;
    let kind_name = values
        .get("type")
        .ok_or_else(|| ConfigError::Invalid("forward requires type".into()))
        .and_then(|value| string(value, environment, "forward type"))?;
    let classifier = values
        .get("classifier")
        .map(|value| parse_classifier(value, environment))
        .transpose()?
        .unwrap_or(Classifier::True);
    let force_ipv4 = values
        .get("force-ipv4")
        .map(|value| bool_value(value, environment, "forward force-ipv4"))
        .transpose()?
        .unwrap_or(false);
    let log = values
        .get("log")
        .map(|value| bool_value(value, environment, "forward log"))
        .transpose()?
        .unwrap_or(false);
    let upstream = || -> Result<(String, Option<String>, Option<String>)> {
        let address = values
            .get("address")
            .ok_or_else(|| ConfigError::Invalid(format!("{kind_name} forward requires address")))
            .and_then(|value| string(value, environment, "forward address"))?;
        Ok((
            address,
            optional_string(values.get("username"), environment, "forward username")?,
            optional_string(values.get("password"), environment, "forward password")?,
        ))
    };
    let kind = match kind_name.as_str() {
        "default-network" => ForwardKind::Direct,
        "socks5" => {
            let (address, username, password) = upstream()?;
            ForwardKind::Socks5 {
                address,
                username,
                password,
            }
        }
        "proxy" | "http-proxy" => {
            let (address, username, password) = upstream()?;
            ForwardKind::HttpProxy {
                address,
                username,
                password,
            }
        }
        _ => {
            return Err(ConfigError::Invalid(format!(
                "unsupported forward type `{kind_name}`"
            )));
        }
    };
    Ok(Forward {
        kind,
        classifier,
        force_ipv4,
        log,
    })
}

fn parse_classifier(value: &Value, environment: &BTreeMap<String, String>) -> Result<Classifier> {
    let values = object(value.clone(), "classifier")?;
    let kind = values
        .get("type")
        .ok_or_else(|| ConfigError::Invalid("classifier requires type".into()))
        .and_then(|value| string(value, environment, "classifier type"))?;
    let required = |name: &str| {
        values
            .get(name)
            .ok_or_else(|| ConfigError::Invalid(format!("{kind} classifier requires `{name}`")))
    };
    let nested = |name: &str| -> Result<Vec<Classifier>> {
        array(required(name)?, &format!("{kind} classifier {name}"))?
            .iter()
            .map(|value| parse_classifier(value, environment))
            .collect()
    };
    match kind.as_str() {
        "true" => {
            reject_unknown_keys(&values, &["type"], "true classifier")?;
            Ok(Classifier::True)
        }
        "false" => {
            reject_unknown_keys(&values, &["type"], "false classifier")?;
            Ok(Classifier::False)
        }
        "and" => {
            reject_unknown_keys(&values, &["type", "classifiers"], "and classifier")?;
            Ok(Classifier::And(nested("classifiers")?))
        }
        "or" => {
            reject_unknown_keys(&values, &["type", "classifiers"], "or classifier")?;
            Ok(Classifier::Or(nested("classifiers")?))
        }
        "not" => {
            reject_unknown_keys(&values, &["type", "classifier"], "not classifier")?;
            Ok(Classifier::Not(Box::new(parse_classifier(
                required("classifier")?,
                environment,
            )?)))
        }
        "domain" => {
            reject_unknown_keys(&values, &["type", "op", "domain"], "domain classifier")?;
            Ok(Classifier::Domain {
                op: values
                    .get("op")
                    .map(|value| string(value, environment, "domain op"))
                    .transpose()?
                    .map(|value| value.parse())
                    .transpose()?
                    .unwrap_or_default(),
                domain: string(required("domain")?, environment, "domain")?,
            })
        }
        "ref" => {
            reject_unknown_keys(&values, &["type", "id"], "ref classifier")?;
            Ok(Classifier::Ref(string(
                required("id")?,
                environment,
                "classifier id",
            )?))
        }
        "ip" => {
            reject_unknown_keys(&values, &["type", "ip"], "ip classifier")?;
            Ok(Classifier::Ip(string(
                required("ip")?,
                environment,
                "classifier ip",
            )?))
        }
        "network" => {
            reject_unknown_keys(&values, &["type", "cidr"], "network classifier")?;
            Ok(Classifier::Network(string(
                required("cidr")?,
                environment,
                "classifier cidr",
            )?))
        }
        "port" => {
            reject_unknown_keys(&values, &["type", "port"], "port classifier")?;
            Ok(Classifier::Port(
                u16::try_from(u64_value(
                    required("port")?,
                    environment,
                    "classifier port",
                )?)
                .map_err(|_| {
                    ConfigError::Invalid("classifier port is outside the valid range".into())
                })?,
            ))
        }
        "domains-file" => {
            reject_unknown_keys(&values, &["type", "file"], "domains-file classifier")?;
            Ok(Classifier::DomainsFile(PathBuf::from(string(
                required("file")?,
                environment,
                "domains-file file",
            )?)))
        }
        "domains-url" => {
            reject_unknown_keys(
                &values,
                &["type", "url", "mirrors", "format", "timeout"],
                "domains-url classifier",
            )?;
            Ok(Classifier::DomainsUrl {
                url: string(required("url")?, environment, "domains-url url")?,
                mirrors: values
                    .get("mirrors")
                    .map(|value| {
                        array(value, "domains-url mirrors")?
                            .iter()
                            .map(|item| string(item, environment, "domains-url mirror"))
                            .collect()
                    })
                    .transpose()?
                    .unwrap_or_default(),
                format: string(required("format")?, environment, "domains-url format")?.parse()?,
                timeout_seconds: values
                    .get("timeout")
                    .map(|value| u64_value(value, environment, "domains-url timeout"))
                    .transpose()?
                    .unwrap_or(30),
            })
        }
        "record" => {
            reject_unknown_keys(&values, &["type", "classifier"], "record classifier")?;
            Ok(Classifier::Record(Box::new(parse_classifier(
                required("classifier")?,
                environment,
            )?)))
        }
        "domains_file" | "domains_url" => Err(ConfigError::Invalid(format!(
            "invalid classifier type `{kind}`: use hyphens"
        ))),
        _ => Err(ConfigError::Invalid(format!(
            "unsupported classifier type `{kind}`"
        ))),
    }
}

fn classifier_or_ref(
    value: &Value,
    environment: &BTreeMap<String, String>,
    context: &str,
) -> Result<Classifier> {
    if value.is_string() {
        return Ok(Classifier::Ref(string(value, environment, context)?));
    }
    parse_classifier(value, environment)
}

fn parse_interception(
    value: &Value,
    environment: &BTreeMap<String, String>,
) -> Result<InterceptionConfig> {
    let values = object(value.clone(), "interception")?;
    reject_unknown_keys(
        &values,
        &[
            "enabled",
            "http",
            "https",
            "https-classifier",
            "exclude-classifier",
            "exclude",
            "ca-file",
            "ca-key-file",
            "ca-key-passwd",
            "insecure-skip-verify",
        ],
        "interception",
    )?;
    let mut config = InterceptionConfig::default();
    if let Some(value) = values.get("enabled") {
        config.enabled = bool_value(value, environment, "interception enabled")?;
    }
    if let Some(value) = values.get("http") {
        config.http = bool_value(value, environment, "interception http")?;
    }
    if let Some(value) = values.get("https") {
        config.https = bool_value(value, environment, "interception https")?;
    }
    config.https_classifier = values
        .get("https-classifier")
        .map(|value| classifier_or_ref(value, environment, "interception https-classifier"))
        .transpose()?;
    config.exclude_classifier = values
        .get("exclude-classifier")
        .or_else(|| values.get("exclude"))
        .map(|value| classifier_or_ref(value, environment, "interception exclude-classifier"))
        .transpose()?;
    config.ca_file = optional_string(values.get("ca-file"), environment, "interception ca-file")?
        .map(PathBuf::from);
    config.ca_key_file = optional_string(
        values.get("ca-key-file"),
        environment,
        "interception ca-key-file",
    )?
    .map(PathBuf::from);
    config.ca_key_passwd = optional_string(
        values.get("ca-key-passwd"),
        environment,
        "interception ca-key-passwd",
    )?;
    if let Some(value) = values.get("insecure-skip-verify") {
        config.insecure_skip_verify =
            bool_value(value, environment, "interception insecure-skip-verify")?;
    }
    Ok(config)
}

fn parse_cache(value: &Value, environment: &BTreeMap<String, String>) -> Result<CacheConfig> {
    let values = object(value.clone(), "cache")?;
    reject_unknown_keys(
        &values,
        &[
            "enabled",
            "default-ttl",
            "refresh-interval",
            "http-timeout",
            "max-retries",
            "retry-delay",
            "chunked-ac-enabled",
            "chunk-size",
            "chunk-threshold",
        ],
        "cache",
    )?;
    let mut config = CacheConfig::default();
    if let Some(value) = values.get("enabled") {
        config.enabled = bool_value(value, environment, "cache enabled")?;
    }
    set_u64(
        &mut config.default_ttl_seconds,
        values.get("default-ttl"),
        environment,
        "cache default-ttl",
    )?;
    set_u64(
        &mut config.refresh_interval_seconds,
        values.get("refresh-interval"),
        environment,
        "cache refresh-interval",
    )?;
    set_u64(
        &mut config.http_timeout_seconds,
        values.get("http-timeout"),
        environment,
        "cache http-timeout",
    )?;
    set_usize(
        &mut config.max_retries,
        values.get("max-retries"),
        environment,
        "cache max-retries",
    )?;
    set_u64(
        &mut config.retry_delay_seconds,
        values.get("retry-delay"),
        environment,
        "cache retry-delay",
    )?;
    if let Some(value) = values.get("chunked-ac-enabled") {
        config.chunked_ac_enabled = bool_value(value, environment, "cache chunked-ac-enabled")?;
    }
    set_usize(
        &mut config.chunk_size,
        values.get("chunk-size"),
        environment,
        "cache chunk-size",
    )?;
    set_usize(
        &mut config.chunk_threshold,
        values.get("chunk-threshold"),
        environment,
        "cache chunk-threshold",
    )?;
    Ok(config)
}

fn parse_dns(value: &Value, environment: &BTreeMap<String, String>) -> Result<DnsConfig> {
    let values = object(value.clone(), "dns")?;
    reject_unknown_keys(&values, &["enabled", "servers"], "dns")?;
    let mut config = DnsConfig::default();
    if let Some(value) = values.get("enabled") {
        config.enabled = bool_value(value, environment, "dns enabled")?;
    }
    if let Some(value) = values.get("servers") {
        config.servers = array(value, "dns servers")?
            .iter()
            .enumerate()
            .map(|(index, value)| {
                let server = object(value.clone(), &format!("DNS server at index {index}"))?;
                reject_unknown_keys(
                    &server,
                    &["address", "type", "timeout-seconds", "tls-host"],
                    &format!("DNS server at index {index}"),
                )?;
                let address = server
                    .get("address")
                    .ok_or_else(|| {
                        ConfigError::Invalid(format!(
                            "DNS server at index {index} requires address"
                        ))
                    })
                    .and_then(|value| string(value, environment, "DNS server address"))?;
                let kind = server
                    .get("type")
                    .map(|value| string(value, environment, "DNS server type"))
                    .transpose()?
                    .map(|value| value.parse())
                    .transpose()?
                    .unwrap_or_default();
                let timeout_seconds = server
                    .get("timeout-seconds")
                    .map(|value| u64_value(value, environment, "DNS server timeout-seconds"))
                    .transpose()?
                    .unwrap_or(10);
                let tls_host =
                    optional_string(server.get("tls-host"), environment, "DNS server tls-host")?;
                Ok(DnsServerConfig {
                    address,
                    kind,
                    timeout_seconds,
                    tls_host,
                })
            })
            .collect::<Result<_>>()?;
    }
    Ok(config)
}

fn parse_observability(
    value: &Value,
    environment: &BTreeMap<String, String>,
) -> Result<ObservabilityConfig> {
    let values = object(value.clone(), "observability")?;
    reject_unknown_keys(
        &values,
        &[
            "prometheus-listen-address",
            "otlp-endpoint",
            "otlp-service-name",
        ],
        "observability",
    )?;
    Ok(ObservabilityConfig {
        prometheus_listen_address: optional_string(
            values.get("prometheus-listen-address"),
            environment,
            "observability prometheus-listen-address",
        )?,
        otlp_endpoint: optional_string(
            values.get("otlp-endpoint"),
            environment,
            "observability otlp-endpoint",
        )?,
        otlp_service_name: optional_string(
            values.get("otlp-service-name"),
            environment,
            "observability otlp-service-name",
        )?,
    })
}

fn validate_address(value: &str, context: &str) -> Result<()> {
    let Some((host, port)) = value.rsplit_once(':') else {
        return Err(ConfigError::Invalid(format!("{context} must be host:port")));
    };
    if host.trim().is_empty() || port.parse::<u16>().is_err() {
        return Err(ConfigError::Invalid(format!("{context} must be host:port")));
    }
    Ok(())
}

fn validate_classifier(
    classifier: &Classifier,
    named: &BTreeMap<String, Classifier>,
) -> Result<()> {
    match classifier {
        Classifier::Ref(name) if !named.contains_key(name) => Err(ConfigError::Invalid(format!(
            "classifier reference `{name}` does not exist"
        ))),
        Classifier::And(items) | Classifier::Or(items) => items
            .iter()
            .try_for_each(|item| validate_classifier(item, named)),
        Classifier::Not(item) | Classifier::Record(item) => validate_classifier(item, named),
        Classifier::Network(value) => value
            .parse::<ipnet::IpNet>()
            .map(|_| ())
            .map_err(|_| ConfigError::Invalid(format!("invalid CIDR `{value}`"))),
        Classifier::Ip(value) => value
            .parse::<IpAddr>()
            .map(|_| ())
            .map_err(|_| ConfigError::Invalid(format!("invalid IP address `{value}`"))),
        _ => Ok(()),
    }
}

fn parse_bool(value: &str, context: &str) -> Result<bool> {
    match value.to_ascii_lowercase().as_str() {
        "true" | "1" => Ok(true),
        "false" | "0" => Ok(false),
        _ => Err(ConfigError::Invalid(format!(
            "{context} must be true or false"
        ))),
    }
}

fn parse_u64(value: &str, context: &str) -> Result<u64> {
    value
        .parse()
        .map_err(|_| ConfigError::Invalid(format!("{context} must be a non-negative integer")))
}

fn set_env_bool(
    field: &mut bool,
    environment: &BTreeMap<String, String>,
    name: &str,
) -> Result<()> {
    if let Some(value) = environment.get(name) {
        *field = parse_bool(value, name)?;
    }
    Ok(())
}

fn set_env_u64(field: &mut u64, environment: &BTreeMap<String, String>, name: &str) -> Result<()> {
    if let Some(value) = environment.get(name) {
        *field = parse_u64(value, name)?;
    }
    Ok(())
}

fn set_env_usize(
    field: &mut usize,
    environment: &BTreeMap<String, String>,
    name: &str,
) -> Result<()> {
    if let Some(value) = environment.get(name) {
        *field = value
            .parse()
            .map_err(|_| ConfigError::Invalid(format!("{name} must be a non-negative integer")))?;
    }
    Ok(())
}

fn set_env_path(field: &mut Option<PathBuf>, environment: &BTreeMap<String, String>, name: &str) {
    if let Some(value) = environment.get(name) {
        *field = Some(PathBuf::from(value));
    }
}

fn set_env_string(field: &mut Option<String>, environment: &BTreeMap<String, String>, name: &str) {
    if let Some(value) = environment.get(name) {
        *field = Some(value.clone());
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, fs};

    use tempfile::tempdir;

    use super::{Classifier, Config, ConfigError, DnsServerKind, ForwardKind};

    fn environment(values: &[(&str, &str)]) -> BTreeMap<String, String> {
        values
            .iter()
            .map(|(key, value)| ((*key).into(), (*value).into()))
            .collect()
    }

    #[test]
    fn json_hcl_secrets_and_environment_share_one_model() {
        let directory = tempdir().unwrap();
        let json = directory.path().join("config.json");
        let hcl = directory.path().join("config.hcl");
        fs::write(
            &json,
            r#"{
                "servers": [{"type":"standard","listen-address":"127.0.0.1:18080"}],
                "timeout-seconds": 12,
                "classifiers": {"corp":{"type":"domain","op":"is","domain":"example.test"}},
                "forwards": [{"type":"socks5","address":"127.0.0.1:1080","username":{"_secret":"UPSTREAM_USER"},"classifier":{"type":"ref","id":"corp"}}],
                "dns": {"enabled":true,"servers":[{"address":"1.1.1.1:853","type":"dot","tls-host":"one.one.one.one"}]},
                "observability": {"prometheus-listen-address":"127.0.0.1:9090","otlp-endpoint":"http://collector:4317"}
            }"#,
        )
        .unwrap();
        fs::write(
            &hcl,
            r#"
                servers = [{ type = "standard", listen-address = "127.0.0.1:18080" }]
                timeout-seconds = 12
                classifiers = { corp = { type = "domain", op = "is", domain = "example.test" } }
                forwards = [{ type = "socks5", address = "127.0.0.1:1080", username = { _secret = "UPSTREAM_USER" }, classifier = { type = "ref", id = "corp" } }]
                dns = { enabled = true, servers = [{ address = "1.1.1.1:853", type = "dot", tls-host = "one.one.one.one" }] }
                observability = { prometheus-listen-address = "127.0.0.1:9090", otlp-endpoint = "http://collector:4317" }
            "#,
        )
        .unwrap();
        let env = environment(&[
            ("UPSTREAM_USER", "operator"),
            ("MSGTAUSCH_TIMEOUTSECONDS", "45"),
        ]);
        let json_config = Config::load_file(&json, &env).unwrap();
        let hcl_config = Config::load_file(&hcl, &env).unwrap();
        assert_eq!(json_config, hcl_config);
        assert_eq!(json_config.timeout_seconds, 45);
        assert_eq!(json_config.dns.servers[0].kind, DnsServerKind::Dot);
        assert_eq!(
            json_config.classifiers["corp"],
            Classifier::Domain {
                op: super::DomainOp::Is,
                domain: "example.test".into()
            }
        );
        assert!(
            matches!(&json_config.forwards[0].kind, ForwardKind::Socks5 { username: Some(username), .. } if username == "operator")
        );
    }

    #[test]
    fn legacy_portal_statistics_and_connection_limits_are_ignored_without_secret_lookups() {
        let directory = tempdir().unwrap();
        let json = directory.path().join("config.json");
        let hcl = directory.path().join("config.hcl");
        fs::write(
            &json,
            r#"{
                "max-concurrent-connections": {"_secret":"UNSET_GLOBAL_LIMIT"},
                "portal": {"username":"admin","password":{"_secret":"UNSET_PORTAL_PASSWORD"}},
                "statistics": {"postgres-dsn":{"_secret":"UNSET_DATABASE_DSN"}},
                "servers": [{
                    "listen-address":"127.0.0.1:18080",
                    "max-connections":{"_secret":"UNSET_SERVER_LIMIT"},
                    "connections-per-client":{"_secret":"UNSET_CLIENT_LIMIT"}
                }]
            }"#,
        )
        .unwrap();
        fs::write(
            &hcl,
            r#"
                max-concurrent-connections = { _secret = "UNSET_GLOBAL_LIMIT" }
                portal = { username = "admin", password = { _secret = "UNSET_PORTAL_PASSWORD" } }
                statistics = { postgres-dsn = { _secret = "UNSET_DATABASE_DSN" } }
                servers = [{
                    listen-address = "127.0.0.1:18081"
                    max-connections = { _secret = "UNSET_SERVER_LIMIT" }
                    connections-per-client = { _secret = "UNSET_CLIENT_LIMIT" }
                }]
            "#,
        )
        .unwrap();

        let json_config = Config::load_file(json, &BTreeMap::new()).unwrap();
        let hcl_config = Config::load_file(hcl, &BTreeMap::new()).unwrap();
        assert_eq!(json_config.servers[0].listen_address, "127.0.0.1:18080");
        assert_eq!(hcl_config.servers[0].listen_address, "127.0.0.1:18081");
    }

    #[test]
    fn underscore_configuration_keys_are_rejected() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(&path, r#"{"listen_address":"127.0.0.1:18080"}"#).unwrap();
        let error = Config::load_file(path, &BTreeMap::new()).unwrap_err();
        assert!(error.to_string().contains("listen-address"));
    }

    #[test]
    fn unknown_keys_are_rejected_at_every_supported_configuration_level() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("config.json");
        for (name, content) in [
            ("root", r#"{"not-a-setting":true}"#),
            ("server", r#"{"servers":[{"unexpected":true}]}"#),
            (
                "classifier",
                r#"{"blocklist":{"type":"true","unexpected":true}}"#,
            ),
            (
                "forward",
                r#"{"forwards":[{"type":"default-network","unexpected":true}]}"#,
            ),
            ("dns", r#"{"dns":{"unexpected":true}}"#),
            ("observability", r#"{"observability":{"unexpected":true}}"#),
            (
                "secret",
                r#"{"forwards":[{"type":"proxy","address":"127.0.0.1:8081","password":{"_secret":"PASSWORD","unexpected":true}}]}"#,
            ),
        ] {
            fs::write(&path, content).unwrap();
            let error = Config::load_file(&path, &BTreeMap::new()).unwrap_err();
            assert!(error.to_string().contains("unknown"), "{name}: {error}");
        }
    }

    #[test]
    fn first_failed_path_uses_environment_but_later_failures_do_not_replace_a_config() {
        let directory = tempdir().unwrap();
        let configured = directory.path().join("configured.json");
        fs::write(&configured, r#"{"listen-address":"127.0.0.1:18081"}"#).unwrap();
        let env = environment(&[("MSGTAUSCH_LISTENADDRESS", "127.0.0.1:18082")]);
        let config =
            Config::load_paths(&[directory.path().join("missing.json"), configured], &env).unwrap();
        assert_eq!(config.servers[0].listen_address, "127.0.0.1:18082");
    }

    #[test]
    fn missing_secret_does_not_leak_any_other_value() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("config.json");
        fs::write(&path, r#"{"forwards":[{"type":"proxy","address":"127.0.0.1:8081","password":{"_secret":"MISSING"}}]}"#).unwrap();
        let error =
            Config::load_file(path, &environment(&[("OTHER_SECRET", "do-not-print")])).unwrap_err();
        assert!(matches!(error, ConfigError::Invalid(_)));
        assert!(!error.to_string().contains("do-not-print"));
    }

    #[test]
    fn shipped_rust_examples_load() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        for name in [
            "config.json",
            "config-with-ipv4-forcing.json",
            "config-with-ipv6-dns.json",
            "otel-prometheus.json",
        ] {
            Config::load_file(root.join("examples").join(name), &BTreeMap::new())
                .unwrap_or_else(|error| panic!("{name} failed to load: {error}"));
        }
    }
}
