use std::{collections::BTreeMap, sync::LazyLock};

use divan::AllocProfiler;
use msgtausch_config::{Config, Target};

#[global_allocator]
static ALLOC: AllocProfiler = AllocProfiler::system();

const CONFIG_JSON: &str = r#"
{
  "servers": [
    {"type": "standard", "listen-address": "127.0.0.1:8080", "enabled": true},
    {"type": "https", "listen-address": "127.0.0.1:8443", "enabled": true, "interceptor-name": "default"}
  ],
  "timeout-seconds": 45,
  "max-idle-conns": 4096,
  "max-idle-conns-per-host": 128,
  "classifiers": {
    "private-network": {"type": "network", "cidr": "10.0.0.0/8"},
    "internal-api": {"type": "domain", "op": "is", "domain": "internal.example.com"},
    "safe-request": {"type": "and", "classifiers": [
      {"type": "ref", "id": "private-network"},
      {"type": "ref", "id": "internal-api"},
      {"type": "port", "port": 443}
    ]}
  },
  "allowlist": {"type": "or", "classifiers": [
    {"type": "ref", "id": "safe-request"},
    {"type": "domain", "op": "is", "domain": "public.example.com"}
  ]},
  "blocklist": {"type": "domain", "op": "is", "domain": "ads.example.com"},
  "forwards": [
    {"type": "proxy", "address": "127.0.0.1:3128", "username": "bench", "password": "bench", "force-ipv4": true, "log": true,
     "classifier": {"type": "ref", "id": "safe-request"}},
    {"type": "default-network", "classifier": {"type": "true"}}
  ],
  "interception": {
    "enabled": true,
    "http": true,
    "https": true,
    "https-classifier": "safe-request",
    "exclude-classifier": {"type": "domain", "op": "is", "domain": "telemetry.example.com"},
    "insecure-skip-verify": false
  },
  "cache": {
    "enabled": true,
    "default-ttl": 3600,
    "refresh-interval": 300,
    "http-timeout": 15,
    "max-retries": 2,
    "retry-delay": 1,
    "chunked-ac-enabled": true,
    "chunk-size": 4096,
    "chunk-threshold": 8192
  },
  "dns": {
    "enabled": true,
    "servers": [
      {"address": "1.1.1.1:53", "type": "udp", "timeout-seconds": 5},
      {"address": "[2606:4700:4700::1111]:853", "type": "dot", "timeout-seconds": 10, "tls-host": "cloudflare-dns.com"}
    ]
  },
  "observability": {
    "prometheus-listen-address": "127.0.0.1:9090",
    "otlp-endpoint": "http://127.0.0.1:4318",
    "otlp-service-name": "msgtausch-bench"
  }
}
"#;

static ENVIRONMENT: LazyLock<BTreeMap<String, String>> = LazyLock::new(|| {
    BTreeMap::from([
        ("MSGTAUSCH_TIMEOUTSECONDS".into(), "60".into()),
        ("MSGTAUSCH_CACHE_MAX_RETRIES".into(), "3".into()),
        ("MSGTAUSCH_SERVER_1_ENABLED".into(), "true".into()),
    ])
});

static CONFIG_FILE: LazyLock<tempfile::NamedTempFile> = LazyLock::new(|| {
    let file = tempfile::Builder::new()
        .prefix("msgtausch-config-bench-")
        .suffix(".json")
        .tempfile()
        .expect("create benchmark config file");
    std::fs::write(file.path(), CONFIG_JSON).expect("write benchmark config");
    file
});

static CONFIG: LazyLock<Config> = LazyLock::new(|| {
    Config::load_file(CONFIG_FILE.path(), &ENVIRONMENT).expect("load benchmark config")
});

static MATCHING_TARGET: LazyLock<Target> = LazyLock::new(|| Target {
    host: "api.internal.example.com".into(),
    port: 443,
    ip: Some("10.42.0.7".parse().expect("valid benchmark IP")),
});

#[divan::bench]
fn load_json_config(bencher: divan::Bencher) {
    bencher.bench(|| Config::load_file(CONFIG_FILE.path(), &ENVIRONMENT).expect("valid config"));
}

#[divan::bench]
fn validate_loaded_config(bencher: divan::Bencher) {
    bencher.bench(|| CONFIG.validate().expect("valid config"));
}

#[divan::bench]
fn match_allowlist_and_blocklist(bencher: divan::Bencher) {
    bencher.bench(|| CONFIG.allows(&MATCHING_TARGET));
}

#[divan::bench]
fn select_matching_forward(bencher: divan::Bencher) {
    bencher.bench(|| CONFIG.select_forward(&MATCHING_TARGET));
}

fn main() {
    LazyLock::force(&ENVIRONMENT);
    LazyLock::force(&CONFIG_FILE);
    LazyLock::force(&CONFIG);
    LazyLock::force(&MATCHING_TARGET);
    divan::main();
}
