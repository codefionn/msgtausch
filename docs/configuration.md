# Configuration Documentation

This document provides comprehensive documentation for the msgtausch proxy configuration system. The configuration can be provided via JSON/HCL files or environment variables.

## Configuration Sources

msgtausch supports configuration from multiple sources, processed in this order:
1. JSON configuration file (`.json` extension)
2. HCL configuration file (`.hcl` extension)
3. Environment variables (with `MSGTAUSCH_` prefix)

## Configuration Structure

### Top-Level Configuration

The root configuration object contains the following fields:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `servers` | `[]ServerConfig` | `[{...}]` | List of proxy server configurations |
| `timeout-seconds` | `int` | `30` | Request timeout in seconds |
| `max-concurrent-connections` | `int` | `100` | Global maximum concurrent connections |
| `classifiers` | `map[string]Classifier` | `{}` | Named classifier definitions |
| `allowlist` | `Classifier` | `null` | Allow only hosts matching this classifier |
| `blocklist` | `Classifier` | `null` | Block hosts matching this classifier |
| `forwards` | `[]Forward` | `[]` | Forwarding rules for different destinations |
| `interception` | `InterceptionConfig` | `{...}` | Global interception settings |
| `statistics` | `StatisticsConfig` | `{...}` | Statistics collection configuration |
| `cache` | `CacheConfig` | `{...}` | Domain URL cache configuration |

### Cache Configuration

The `cache` object controls background caching of domain lists fetched from URLs:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `true` | Enable background caching of domain URLs |
| `default-ttl` | `int` | `3600` | Default cache time-to-live in seconds (1 hour) |
| `refresh-interval` | `int` | `300` | Background refresh interval in seconds (5 minutes) |
| `http-timeout` | `int` | `30` | HTTP request timeout in seconds |
| `max-retries` | `int` | `3` | Maximum retry attempts for failed requests |
| `retry-delay` | `int` | `5` | Delay between retry attempts in seconds |

#### Cache Behavior

- **Background Refresh**: Cache entries are automatically refreshed in the background before they expire
- **Error Handling**: Failed fetch attempts are cached for a short duration (5 minutes) to avoid repeated failed requests
- **Retry Logic**: Failed requests are retried up to `max-retries` times with `retry-delay` between attempts
- **Memory Efficiency**: Uses Aho-Corasick tries for efficient domain matching
- **Graceful Degradation**: Classification continues with stale data if refresh fails, rather than blocking requests

#### Cache Configuration Examples

```json
{
  "cache": {
    "enabled": true,
    "default-ttl": 7200,
    "refresh-interval": 600,
    "http-timeout": 45,
    "max-retries": 5,
    "retry-delay": 10
  }
}
```

#### HCL Cache Configuration
```hcl
cache = {
  enabled          = true
  default-ttl      = 7200  # 2 hours
  refresh-interval = 600   # 10 minutes
  http-timeout     = 45    # 45 seconds
  max-retries      = 5
  retry-delay      = 10    # 10 seconds
}
```

#### Environment Variables

| Environment Variable | Description | Type |
|---------------------|-------------|------|
| `MSGTAUSCH_CACHE_ENABLED` | Enable domain URL caching | bool |
| `MSGTAUSCH_CACHE_DEFAULT_TTL` | Cache TTL in seconds | int |
| `MSGTAUSCH_CACHE_REFRESH_INTERVAL` | Refresh interval in seconds | int |
| `MSGTAUSCH_CACHE_HTTP_TIMEOUT` | HTTP timeout in seconds | int |
| `MSGTAUSCH_CACHE_MAX_RETRIES` | Maximum retry attempts | int |
| `MSGTAUSCH_CACHE_RETRY_DELAY` | Retry delay in seconds | int |

### Statistics Configuration

The `statistics` object controls statistics collection and monitoring:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Enable statistics collection |
| `backend` | `string` | `"sqlite"` | Storage backend: `"sqlite"`, `"postgres"`, or `"dummy"` |
| `sqlite-path` | `string` | `"msgtausch_stats.db"` | Path to SQLite database file |
| `postgres-dsn` | `string` | `""` | PostgreSQL connection string |
| `buffer-size` | `int` | `1000` | Buffer size for batch operations |
| `flush-interval` | `int` | `300` | Flush interval in seconds (5 minutes) |

### Server Configuration

Each server in the `servers` array supports the following configuration:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `type` | `string` | `"standard"` | Proxy type: `standard`, `http`, `https`, `quic` |
| `listen-address` | `string` | `"127.0.0.1:8080"` | Address and port to listen on |
| `enabled` | `bool` | `true` | Whether this server is enabled |
| `interceptor-name` | `string` | `""` | Identifier for this interceptor (optional) |
| `max-connections` | `int` | `100` | Maximum connections for this server |
| `connections-per-client` | `int` | `10` | Maximum connections per client IP |

#### Proxy Types

- **standard**: Standard HTTP/HTTPS forward proxy
- **http**: HTTP-only proxy server
- **https**: HTTPS proxy server with TLS
- **quic**: QUIC/HTTP3 proxy server

### Interception Configuration

The `interception` object controls traffic interception capabilities:

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `enabled` | `bool` | `false` | Master switch for traffic interception |
| `http` | `bool` | `false` | Enable HTTP traffic interception |
| `https` | `bool` | `false` | Enable HTTPS traffic interception |
| `insecure-skip-verify` | `bool` | `false` | Skip TLS verification for upstream connections during interception (useful for self-signed upstreams in tests/dev). Set to `true` to bypass upstream TLS verification. |
| `ca-file` | `string` | `""` | Path to CA certificate file |
| `ca-key-file` | `string` | `""` | Path to CA private key file |
| `ca-key-passwd` | `string` | `""` | Optional password for encrypted CA private key file |

### Classifiers

Classifiers are rule-based matching systems used for allowlists, blocklists, and forwarding decisions. They can be defined as named classifiers in the `classifiers` map or used inline.

#### Classifier Types

##### Boolean Logic Classifiers

- **`and`**: Matches if all sub-classifiers match
- **`or`**: Matches if any sub-classifier matches  
- **`not`**: Negates the result of a sub-classifier

**Fields:**
- `classifiers`: Array of sub-classifiers to evaluate

##### Domain Classifiers

- **`domain`**: Match by domain name patterns

**Fields:**
- `domain`: The domain pattern to match
- `op`: Matching operation (`is`, `contains`, `starts-with`, `is`, `regex`)

##### Network Classifiers

- **`ip`**: Match by exact IP address
- **`network`**: Match by CIDR network range

**Fields:**
- `ip`: Exact IP address (for `ip` type)
- `cidr`: CIDR notation (e.g., "192.168.1.0/24") (for `network` type)

##### Port Classifiers

- **`port`**: Match by port number

**Fields:**
- `port`: Port number to match

##### File-based Classifiers

- **`domains-file`**: Match domains from a file

**Fields:**
- `file`: Path to file containing domain patterns (one per line)

- **`domains-url`**: Match domains fetched from a URL with mirror fallback support

**Fields:**
- `url`: Primary URL to fetch domain patterns from
- `mirrors`: Array of mirror URLs for fallback (optional, max 5 URLs)
- `format`: Format of the domain list (`rpz`, `wildcard`, `adblock`, `plain`)
- `timeout`: Timeout in seconds for HTTP request (optional, default: 30)

**URL Formats:**
- **`rpz`**: RPZ format with `domain CNAME .` entries
- **`wildcard`**: Wildcard format with `*.domain` entries  
- **`adblock`**: AdBlock format with `||domain^` entries
- **`plain`**: Plain domain names, one per line

#### Mirror URL Behavior

- **Primary First**: The system always tries the primary URL first
- **Sequential Fallback**: If primary fails, mirrors are tried in order
- **Independent Caching**: Each URL (primary + mirrors combination) is cached separately
- **Retry Logic**: Each URL gets its own retry attempts before trying the next
- **Success Logging**: The system logs which URL successfully provided the content
- **Cache Source**: Cache entries remember which URL provided the content for debugging

#### Mirror URL Best Practices

- **Geographic Distribution**: Use mirrors in different geographic regions
- **Different Providers**: Use different hosting providers for redundancy
- **Content Consistency**: Ensure all mirrors serve identical content
- **URL Limits**: Maximum 5 mirrors per classifier to avoid complexity
- **Format Consistency**: All mirrors must serve the same format as the primary

##### Reference Classifiers

- **`ref`**: Reference a named classifier defined in the `classifiers` map

**Fields:**
- `id`: Name of the classifier to reference

##### Constant Classifiers

- **`true`**: Always matches
- **`false`: Never matches

### Forwarding Rules

The `forwards` array defines how traffic should be forwarded based on matching classifiers. Rules are evaluated in order, and the first matching rule is used.

#### Forward Types

##### Default Network Forward

- **Type**: `default-network`
- **Description**: Uses the system's default network routing
- **Fields**:
  - `classifier`: Classifier to determine when this forward applies
  - `force-ipv4`: Force IPv4 connections (boolean, optional)

##### SOCKS5 Forward

- **Type**: `socks5`
- **Description**: Routes traffic through a SOCKS5 proxy
- **Fields**:
  - `classifier`: Classifier to determine when this forward applies
  - `address`: SOCKS5 server address (host:port)
  - `username`: Username for authentication (optional)
  - `password`: Password for authentication (optional)
  - `force-ipv4`: Force IPv4 connections (boolean, optional)

##### HTTP Proxy Forward

- **Type**: `proxy`
- **Description**: Routes traffic through an HTTP proxy
- **Fields**:
  - `classifier`: Classifier to determine when this forward applies
  - `address`: HTTP proxy address (host:port)
  - `username`: Username for authentication (optional)
  - `password`: Password for authentication (optional)
  - `force-ipv4`: Force IPv4 connections (boolean, optional)

## Environment Variables

Configuration can be overridden using environment variables with the `MSGTAUSCH_` prefix.

### Global Configuration Variables

| Environment Variable | Description | Type |
|---------------------|-------------|------|
| `MSGTAUSCH_TIMEOUTSECONDS` | Request timeout in seconds | int |
| `MSGTAUSCH_MAXCONCURRENTCONNECTIONS` | Maximum concurrent connections | int |
| `MSGTAUSCH_INTERCEPT` | Enable traffic interception | bool |
| `MSGTAUSCH_INTERCEPTHTTP` | Enable HTTP traffic interception | bool |
| `MSGTAUSCH_INTERCEPTHTTPS` | Enable HTTPS traffic interception | bool |
| `MSGTAUSCH_CAFILE` | Path to CA certificate file | string |
| `MSGTAUSCH_CAKEYFILE` | Path to CA private key file | string |
| `MSGTAUSCH_INSECURE_SKIP_VERIFY` | Skip upstream TLS verification (`true`/`false`) | bool |
| `MSGTAUSCH_CAKEYPASSWD` | Password for encrypted CA private key file | string |
| `MSGTAUSCH_STATISTICS_ENABLED` | Enable statistics collection | bool |
| `MSGTAUSCH_STATISTICS_BACKEND` | Statistics backend type | string |
| `MSGTAUSCH_STATISTICS_SQLITE_PATH` | Path to SQLite stats database | string |
| `MSGTAUSCH_STATISTICS_POSTGRES_DSN` | PostgreSQL connection string | string |
| `MSGTAUSCH_STATISTICS_BUFFER_SIZE` | Buffer size for batch operations | int |
| `MSGTAUSCH_STATISTICS_FLUSH_INTERVAL` | Flush interval in seconds | int |
| `MSGTAUSCH_LISTENADDRESS` | Address for single server (backward compatibility) | string |

### Server-Specific Variables

For multiple servers, use indexed environment variables where `N` is the server index (0, 1, 2, etc.):

| Environment Variable Pattern | Description | Type |
|------------------------------|-------------|------|
| `MSGTAUSCH_SERVER_N_LISTENADDRESS` | Listen address for server N | string |
| `MSGTAUSCH_SERVER_N_TYPE` | Proxy type for server N | string |
| `MSGTAUSCH_SERVER_N_ENABLED` | Enable/disable server N | bool |
| `MSGTAUSCH_SERVER_N_MAXCONNECTIONS` | Max connections for server N | int |
| `MSGTAUSCH_SERVER_N_CONNECTIONSPCLIENT` | Max connections per client for server N | int |
| `MSGTAUSCH_SERVER_N_CAFILE` | CA file for server N | string |
| `MSGTAUSCH_SERVER_N_CAKEYFILE` | CA key file for server N | string |

### Statistics Environment Variables

| Environment Variable Pattern | Description | Type |
|------------------------------|-------------|------|
| `MSGTAUSCH_STATISTICS_ENABLED` | Enable statistics collection | bool |
| `MSGTAUSCH_STATISTICS_BACKEND` | Statistics backend type | string |
| `MSGTAUSCH_STATISTICS_SQLITE_PATH` | Path to SQLite database | string |
| `MSGTAUSCH_STATISTICS_POSTGRES_DSN` | PostgreSQL connection string | string |
| `MSGTAUSCH_STATISTICS_BUFFER_SIZE` | Buffer size for batch operations | int |
| `MSGTAUSCH_STATISTICS_FLUSH_INTERVAL` | Flush interval in seconds | int |

### Examples

#### Basic Environment Configuration
```bash
export MSGTAUSCH_TIMEOUTSECONDS=60
export MSGTAUSCH_MAXCONCURRENTCONNECTIONS=200
export MSGTAUSCH_LISTENADDRESS=0.0.0.0:8080
```

#### Multi-Server Environment Configuration
```bash
export MSGTAUSCH_SERVER_0_LISTENADDRESS=127.0.0.1:8080
export MSGTAUSCH_SERVER_0_TYPE=standard
export MSGTAUSCH_SERVER_1_LISTENADDRESS=127.0.0.1:8443
export MSGTAUSCH_SERVER_1_TYPE=https
export MSGTAUSCH_SERVER_1_ENABLED=true
```

## Configuration Examples

### Basic Forward Proxy
```json
{
  "servers": [
    {
      "type": "standard",
      "listen-address": "127.0.0.1:8080",
      "enabled": true,
      "max-connections": 100,
      "connections-per-client": 10
    }
  ],
  "timeout-seconds": 30,
  "max-concurrent-connections": 100,
  "statistics": {
    "enabled": true,
    "backend": "sqlite",
    "sqlite-path": "proxy_stats.db",
    "flush-interval": 300
  }
  "allowlist": {
    "type": "ref",
    "id": "internal-network"
  },
  "allowlist": {
    "type": "ref",
    "id": "internal-network"
  },
  "allowlist": {
    "type": "ref",
    "id": "internal-network"
  }
}
```

### Advanced Configuration with Classifiers
```json
{
  "servers": [
    {
      "type": "standard",
      "listen-address": "0.0.0.0:8080",
      "max-connections": 1000,
      "connections-per-client": 50
    },
    {
      "type": "https",
      "listen-address": "0.0.0.0:8443",
      "max-connections": 500,
      "connections-per-client": 25
    }
  ],
  "classifiers": {
    "internal-network": {
      "type": "network",
      "cidr": "192.168.0.0/16"
    },
    "trusted-domains": {
      "type": "or",
      "classifiers": [
        {
          "type": "domain",
          "op": "is",
          "domain": ".company.com"
        },
        {
          "type": "domain",
          "op": "is",
          "domain": "api.trusted-service.com"
        }
      ]
    }
  },
  "allowlist": {
    "type": "or",
    "classifiers": [
      { "type": "ref", "id": "internal-network" },
      { "type": "ref", "id": "trusted-domains" }
    ]
  },
  "forwards": [
    {
      "classifier": { "type": "ref", "id": "internal-network" },
      "type": "default-network"
    },
    {
      "classifier": { "type": "true" },
      "type": "socks5",
      "address": "corporate-proxy.company.com:1080",
      "username": "proxyuser",
      "password": "proxypass"
    }
  ]
}
```

### Domains-URL Configuration Example

#### Using Different URL Formats with Mirrors
```json
{
  "servers": [
    {
      "type": "standard",
      "listen-address": "127.0.0.1:8080"
    }
  ],
  "classifiers": {
    "hagezi-dyndns": {
      "type": "domains-url",
      "url": "https://github.com/hagezi/dns-blocklists/raw/main/domains/rpz.txt",
      "mirrors": [
        "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@main/domains/rpz.txt",
        "https://raw.githubusercontent.com/hagezi/dns-blocklists/main/domains/rpz.txt"
      ],
      "format": "rpz",
      "timeout": 45
    },
    "wildcard-blocklist": {
      "type": "domains-url",
      "url": "https://github.com/hagezi/dns-blocklists/raw/main/domains/wildcard.txt",
      "format": "wildcard"
    },
    "adblock-tracker": {
      "type": "domains-url",
      "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=adblockplus",
      "mirrors": [
        "https://mirror1.example.com/adservers.txt",
        "https://mirror2.example.com/adservers.txt"
      ],
      "format": "adblock",
      "timeout": 30
    },
    "plain-domains": {
      "type": "domains-url",
      "url": "https://example.com/simple-domains.txt",
      "mirrors": [
        "https://backup.example.com/simple-domains.txt"
      ],
      "format": "plain",
      "timeout": 60
    }
  },
  "blocklist": {
    "type": "or",
    "classifiers": [
      { "type": "ref", "id": "hagezi-dyndns" },
      { "type": "ref", "id": "wildcard-blocklist" },
      { "type": "ref", "id": "adblock-tracker" },
      { "type": "ref", "id": "plain-domains" }
    ]
  }
}
```

#### HCL Example with Domains-URL and Mirrors
```hcl
servers = [
  {
    type = "standard"
    listen-address = "127.0.0.1:8080"
  }
]

classifiers = {
  "reliable-blocklist" = {
    type = "domains-url"
    url = "https://primary.example.com/blocklist.txt"
    mirrors = [
      "https://mirror1.example.com/blocklist.txt"
      "https://mirror2.example.com/blocklist.txt"
      "https://backup.example.com/blocklist.txt"
    ]
    format = "plain"
    timeout = 45
  }
  
  "hagezi-mirrored" = {
    type = "domains-url"
    url = "https://github.com/hagezi/dns-blocklists/raw/main/domains/rpz.txt"
    mirrors = [
      "https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@main/domains/rpz.txt"
    ]
    format = "rpz"
  }
}

blocklist = {
  type = "or"
  classifiers = [
    { type = "ref", id = "reliable-blocklist" }
    { type = "ref", id = "hagezi-mirrored" }
  ]
}
```

### HCL Configuration Example
```hcl
servers = [
  {
    type = "standard"
    listen-address = "127.0.0.1:8080"
    enabled = true
    max-connections = 100
    connections-per-client = 10
  }
]

timeout-seconds = 60
max-concurrent-connections = 200

classifiers = {
  internal-network = {
    type = "network"
    cidr = "192.168.1.0/24"
  }
}

allowlist = {
  type = "ref"
  id = "internal-network"
}
```

### Statistics Configuration Example

#### Basic Statistics
```json
{
  "servers": [
    {
      "type": "standard",
      "listen-address": "127.0.0.1:8080"
    }
  ],
  "statistics": {
    "enabled": true,
    "backend": "sqlite",
    "sqlite-path": "./proxy_stats.db"
  }
}
```

#### PostgreSQL Statistics
```json
{
  "statistics": {
    "enabled": true,
    "backend": "postgres",
    "postgres-dsn": "postgres://user:pass@localhost/msgtausch?sslmode=disable",
    "buffer-size": 2000,
    "flush-interval": 600
  }
}
```

#### Statistics via Environment Variables
```bash
export MSGTAUSCH_STATISTICS_ENABLED=true
export MSGTAUSCH_STATISTICS_BACKEND=sqlite
export MSGTAUSCH_STATISTICS_SQLITE_PATH=./proxy_stats.db
```

### Interception Configuration Examples

#### Basic HTTP Interception
```json
{
  "servers": [
    {
      "type": "http",
      "listen-address": "127.0.0.1:8080"
    }
  ],
  "interception": {
    "enabled": true,
    "http": true,
    "https": false
  }
}
```

#### HTTPS Interception with CA Certificate
```json
{
  "servers": [
    {
      "type": "https",
      "listen-address": "127.0.0.1:8443"
    }
  ],
  "interception": {
    "enabled": true,
    "http": false,
    "https": true,
    "ca-file": "/path/to/ca.crt",
    "ca-key-file": "/path/to/ca.key"
  }
}
```

#### Full Interception with Password-Protected CA Key
```json
{
  "servers": [
    {
      "type": "https",
      "listen-address": "0.0.0.0:8443"
    },
    {
      "type": "http",
      "listen-address": "0.0.0.0:8080"
    }
  ],
  "interception": {
    "enabled": true,
    "http": true,
    "https": true,
    "ca-file": "/etc/ssl/proxy/ca.crt",
    "ca-key-file": "/etc/ssl/proxy/ca.key",
    "ca-key-passwd": "secret-ca-password"
  }
}
```

#### HCL Interception Configuration
```hcl
servers = [
  {
    type = "https"
    listen-address = "127.0.0.1:8443"
  }
]

interception = {
  enabled = true
  http = false
  https = true
  ca-file = "/opt/certs/proxy-ca.pem"
  ca-key-file = "/opt/certs/proxy-ca-key.pem"
  ca-key-passwd = "ca-key-password"
}
```

#### Interception via Environment Variables
```bash
# Enable interception globally
export MSGTAUSCH_INTERCEPT=true

# Enable both HTTP and HTTPS interception
export MSGTAUSCH_INTERCEPTHTTP=true
export MSGTAUSCH_INTERCEPTHTTPS=true

# Set CA certificate files
export MSGTAUSCH_CAFILE=/etc/ssl/certs/proxy-ca.crt
export MSGTAUSCH_CAKEYFILE=/etc/ssl/private/proxy-ca.key
export MSGTAUSCH_CAKEYPASSWD=my-secure-password

# Set up HTTPS intercepting server
export MSGTAUSCH_SERVER_0_LISTENADDRESS=0.0.0.0:8443
export MSGTAUSCH_SERVER_0_TYPE=https
export MSGTAUSCH_SERVER_0_ENABLED=true
```

#### Using Secrets for Sensitive Configuration
```json
{
  "interception": {
    "enabled": true,
    "https": true,
    "ca-file": "/etc/ssl/proxy/ca.crt",
    "ca-key-file": "/etc/ssl/proxy/ca.key",
    "ca-key-passwd": {
      "_secret": "CA_KEY_PASSWORD"
    }
  }
}
```

Then set the environment variable:
```bash
export CA_KEY_PASSWORD=your-actual-password
```

In a systemd service you can use `EnvironmentFile` to securely include your secrets.

## Configuration Validation

The configuration is validated on startup with the following rules:

- All server addresses must be valid host:port combinations
- CIDR notation must be valid (e.g., "192.168.1.0/24")
- File paths must be accessible (for CA files, domains files)
- Classifier references must point to existing named classifiers
- Forward addresses must be valid host:port combinations
- Interception CA files must exist and be readable when HTTPS interception is enabled
- CA private key files must match the CA certificate
- Configuration keys must use hyphens, not underscores (e.g., `ca-file` not `ca_file`)

## Best Practices

### General Configuration
1. **Use named classifiers** for complex rules that are reused
2. **Order forwarding rules** from most specific to least specific
3. **Set appropriate connection limits** based on expected load
4. **Use environment variables** for deployment-specific settings
5. **Test configuration changes** in a non-production environment first
6. **Monitor connection usage** and adjust limits accordingly

### Interception Configuration
1. **Secure CA private keys** with appropriate file permissions (600 or 400)
2. **Use password-protected CA keys** in production environments
3. **Store CA passwords** in environment variables or secrets management systems
4. **Generate dedicated CA certificates** for proxy interception (don't reuse existing CAs)
5. **Test certificate chain validity** before deployment
6. **Monitor certificate expiration** and implement renewal processes
7. **Use separate servers** for HTTP and HTTPS interception when possible
8. **Consider performance impact** of HTTPS interception on high-traffic systems

### Statistics Configuration
1. **Monitor statistics database** growth and implement retention policies
2. **Test statistics configuration** in non-production environments
3. **Use appropriate buffer sizes** based on expected traffic volume
4. **Consider PostgreSQL** for high-traffic deployments
5. **Implement regular database backups** for important statistics data
