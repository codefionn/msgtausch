# Configuration

msgtausch reads JSON and HCL. The filename extension selects the parser. If no config option is present, the service tries `config.json`.

```bash
msgtausch --config base.json --config production.hcl --envfile /run/msgtausch.env
```

`--config` may repeat. Each file starts from defaults. The last file that loads successfully becomes the full configuration, so files replace one another rather than merge. Environment variables override each loaded file. If the first file cannot be loaded, msgtausch tries an environment-only configuration. A later bad file is skipped.

The CLI also accepts the legacy spellings `-config`, `-envfile`, `-debug`, `-trace`, and `-version`.

## Minimal config

```json
{
  "servers": [
    {
      "type": "standard",
      "listen-address": "127.0.0.1:8080",
      "enabled": true
    }
  ],
  "timeout-seconds": 30,
  "observability": {
    "prometheus-listen-address": "127.0.0.1:9090"
  }
}
```

With no file or environment overrides, the service uses one standard listener at `127.0.0.1:8080`, a 30 second connection timeout, 2,048 idle connections, and 256 idle connections per host.

## Top-level fields

| Field | Purpose |
|---|---|
| `servers` | Proxy listeners. |
| `listen-address` | Legacy shorthand for one standard listener. |
| `timeout-seconds` | Connect and tunnel idle timeout. |
| `max-idle-conns` | Retained connection-pool setting. |
| `max-idle-conns-per-host` | Retained per-host pool setting. |
| `max-concurrent-connections` | Legacy admission limit. Accepted and ignored. |
| `classifiers` | Named traffic classifiers. |
| `allowlist` | Requests must match this classifier. |
| `blocklist` | Matching requests are rejected with HTTP 403. |
| `forwards` | Ordered upstream routes. The first match wins. |
| `interception` | CA-backed HTTPS and HTTP/3 interception. |
| `cache` | Domain list cache settings. |
| `dns` | Custom resolver settings. |
| `observability` | Prometheus and OTLP endpoints. |
| `portal` | Legacy admin page settings. Accepted and ignored. |
| `statistics` | Legacy database collector settings. Accepted and ignored. |

The Rust service has no admin page, SQLite collector, PostgreSQL collector, or request body recorder. It accepts the legacy `portal` and `statistics` blocks so an existing deployment can start unchanged, then ignores their contents. Values in either block are never resolved, including `{"_secret":"NAME"}` values.

The legacy `max-concurrent-connections` top-level field and each listener's `max-connections` and `connections-per-client` fields are also accepted and ignored. This rewrite has no global connection admission limit or client connection limit yet. Capacity is currently controlled by the operating system, container limits, and the proxy's available resources.

## Listeners

Each server has `type`, `listen-address`, `enabled`, and optional `interceptor-name` fields. It may retain `max-connections` and `connections-per-client` from an earlier configuration, but the Rust proxy does not enforce either limit. `standard` and `http` accept TCP forward-proxy traffic. `https` accepts TLS directly and pins the upstream to ClientHello SNI on port 443. `quic` accepts HTTP/3 over UDP, pins `:authority` to ClientHello SNI, uses TLS 1.3, and rejects 0-RTT data.

Ordinary HTTPS works through a standard listener. By default, the proxy creates a CONNECT tunnel and never sees the encrypted HTTP request. When `interception.enabled` and `interception.https` are true, matching CONNECT requests use a cached CA-signed leaf certificate. Dedicated `https` and `quic` listeners require `ca-file` and `ca-key-file` but do not require those two global switches.

HTTP/3 uses direct UDP upstream connections. A matching SOCKS5 or HTTP proxy forward rule produces a clear 502 response because those TCP forwarding protocols cannot carry native QUIC datagrams.

## Forward rules

Rules run in array order. A missing classifier means `true`.

```json
{
  "forwards": [
    {
      "type": "socks5",
      "address": "127.0.0.1:1080",
      "username": {"_secret": "SOCKS_USER"},
      "password": {"_secret": "SOCKS_PASSWORD"},
      "force-ipv4": true,
      "classifier": {"type": "ref", "id": "private"}
    },
    {
      "type": "default-network",
      "classifier": {"type": "true"}
    }
  ]
}
```

Supported types are `default-network`, `socks5`, and `proxy`. The `proxy` route opens an HTTP CONNECT tunnel through its configured address. SOCKS5 and proxy credentials must contain both a username and password.

## Classifiers

Classifiers receive the target host, target port, and downstream client IP.

| Type | Fields |
|---|---|
| `true`, `false` | No extra fields. |
| `and`, `or` | `classifiers` array. |
| `not` | `classifier`. |
| `domain` | `domain`, optional `op`: `equal`, `not-equal`, `contains`, `not-contains`, or `is`. |
| `ip` | `ip`. Matches the downstream client IP. |
| `network` | `cidr`. Matches the downstream client IP. |
| `port` | `port`. |
| `ref` | `id` naming an entry in `classifiers`. |
| `domains-file` | `file`, one domain per line. |
| `domains-url` | `url`, optional `mirrors`, `format`, and `timeout`. |
| `record` | `classifier`. Retained as a predicate only. Bodies are never stored. |

`is` matches one domain and its child domains. Classifier reference cycles and missing references fail startup.

## DNS

```json
{
  "dns": {
    "enabled": true,
    "servers": [
      {
        "address": "1.1.1.1:853",
        "type": "dot",
        "timeout-seconds": 10,
        "tls-host": "cloudflare-dns.com"
      }
    ]
  }
}
```

The resolver accepts `udp`, `tcp`, and `dot`. It selects one configured server in round-robin order for each lookup. TCP and DoT use DNS length framing. DoT verifies the server certificate, sends the `dot` ALPN token, and uses `tls-host` for SNI when set. Direct targets and forward-proxy endpoints use the configured resolver. Upstream SOCKS5 and HTTP proxies resolve destination names unless `force-ipv4` asks msgtausch to resolve first.

## Interception

```json
{
  "interception": {
    "enabled": true,
    "https": true,
    "ca-file": "/run/msgtausch/ca.crt",
    "ca-key-file": "/run/msgtausch/ca.key",
    "ca-key-passwd": {"_secret": "MSGTAUSCH_CA_PASSWORD"},
    "insecure-skip-verify": false
  }
}
```

The CA key may be unencrypted, encrypted PKCS#8, or a legacy RFC1423 AES/DES PEM retained for configuration compatibility. Generated leaves are cached and contain a DNS or IP subject alternative name for the target. `https-classifier` limits interception and `exclude-classifier` takes precedence. Upstream certificates are verified unless `insecure-skip-verify` is true.

`domains-url` classifiers fetch the primary URL and then mirrors in order. Successes and failures are shared and cached, concurrent fetches are coalesced, and a background task refreshes entries. Supported formats are `plain`, `wildcard`, `adblock`, and `rpz`. A failed fetch classifies as false until a later refresh succeeds.

## Observability

```json
{
  "observability": {
    "prometheus-listen-address": "0.0.0.0:9090",
    "otlp-endpoint": "http://otel-collector:4318",
    "otlp-service-name": "msgtausch-edge"
  }
}
```

Prometheus is disabled when its listen address is absent. The endpoint returns OpenMetrics text and records active and total connections, access decisions, HTTP status classes, durations, selected routes, bounded error kinds, tunnel bytes, and tunnel durations. Hosts, URLs, user names, and client addresses are never metric labels.

OTLP is disabled when its endpoint is absent. When configured, spans are exported with OTLP/HTTP. Export failure does not stop proxy traffic.

Environment overrides:

| Variable | Field |
|---|---|
| `MSGTAUSCH_PROMETHEUS_LISTEN_ADDRESS` | Prometheus listen address. |
| `MSGTAUSCH_OTLP_ENDPOINT` | OTLP/HTTP endpoint. |
| `MSGTAUSCH_OTLP_SERVICE_NAME` | OpenTelemetry service name. |

## Environment and secrets

The loader retains compatibility environment names, including `MSGTAUSCH_TIMEOUTSECONDS`, `MSGTAUSCH_MAXIDLECONNS`, `MSGTAUSCH_MAXIDLECONNSPERHOST`, `MSGTAUSCH_LISTENADDRESS`, interception variables, indexed server variables, indexed DNS variables, and cache variables.

Indexed servers stop at the first missing address:

```text
MSGTAUSCH_SERVER_0_LISTENADDRESS=0.0.0.0:8080
MSGTAUSCH_SERVER_0_TYPE=standard
MSGTAUSCH_SERVER_0_ENABLED=true
```

Any scalar file value may read an environment variable:

```json
{"password": {"_secret": "UPSTREAM_PASSWORD"}}
```

A missing or empty secret fails startup. Secret values are not printed.

Dotenv files use `KEY=VALUE` lines. Blank lines and trimmed comment lines are ignored. Values may have one pair of surrounding single or double quotes. Dotenv values override inherited process variables.
