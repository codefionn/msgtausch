# msgtausch

> This project is activly in intial development. Use at your own risk!

A configurable forward proxy written in Go that can be configured using either JSON or environment variables.

## Features

- HTTP/HTTPS forward proxy
- Configuration via JSON file or environment variables
- Configurable timeout and connection limits
- Host allowlist support
- Graceful shutdown

## Configuration

Msgtausch supports configuration in both **JSON** and **HCL** formats. The configuration file path can be specified via CLI or environment variable. Most options can also be set via environment variables.

### Example (JSON)
```json
{
  "servers": [
    {
      "type": "standard",
      "listen_address": "127.0.0.1:8080",
      "enabled": true,
      "max_connections": 100,
      "connections_per_client": 10
    }
  ],
  "timeout_seconds": 60,
  "max_concurrent_connections": 200,
  "classifiers": {
    "internal_network": {
      "type": "network",
      "cidr": "192.168.1.0/24"
    },
    "google_services": {
      "type": "domain",
      "op": "is",
      "domain": ".google.com"
    }
  },
  "allowlist": {
    "type": "or",
    "classifiers": [
      { "type": "ref", "id": "internal_network" },
      { "type": "ref", "id": "google_services" }
    ]
  },
  "blocklist": {
    "type": "domain",
    "op": "is",
    "domain": "ads.example.com"
  },
  "forwards": [
    {
      "classifier": { "type": "ref", "id": "internal_network" },
      "type": "socks5",
      "address": "10.0.0.1:1080",
      "username": "sockuser",
      "password": "sockpass"
    },
    {
      "classifier": { "type": "true" },
      "type": "default_network"
    }
  ],
  "interception": {
    "enabled": false,
    "http": false,
    "https": false,
    "ca_file": "",
    "ca_key_file": ""
  }
}
```

### Top-level options

| Field                        | Type                     | Default              | Description                                                      |
|------------------------------|--------------------------|----------------------|------------------------------------------------------------------|
| `servers`                    | list[ServerConfig]       | See below            | List of proxy server configurations                              |
| `timeout_seconds`            | int                      | `30`                 | Request timeout in seconds                                       |
| `max_concurrent_connections` | int                      | `100`                | Maximum concurrent connections                                   |
| `classifiers`                | map[string]Classifier    | `{}`                 | Named classifier definitions (see below)                         |
| `allowlist`                  | Classifier (optional)    |                      | Allow only hosts matching this classifier                        |
| `blocklist`                  | Classifier (optional)    |                      | Block hosts matching this classifier                             |
| `forwards`                   | list[Forward]            | `[]`                 | Forwarding rules (see below)                                     |
| `interception`               | InterceptionConfig       | See below            | Global settings for traffic interception                         |

### Server Configuration

Each server in the `servers` array has the following fields:

| Field                    | Type   | Default           | Description                                      |
|--------------------------|--------|-------------------|--------------------------------------------------|
| `type`                   | string | `standard`        | Proxy type: `standard`, `http`, `https`, `quic` |
| `listen_address`         | string | `127.0.0.1:8080`  | Address and port to listen on                    |
| `enabled`                | bool   | `true`            | Whether this server is enabled                   |
| `interceptor_name`       | string |                   | Identifier for this interceptor (optional)      |
| `max_connections`        | int    | `100`             | Maximum connections for this server instance     |
| `connections_per_client` | int    | `10`              | Maximum connections per client IP                |

### Interception Configuration

The `interception` object has the following fields:

| Field        | Type   | Default | Description                                    |
|--------------|--------|---------|------------------------------------------------|
| `enabled`    | bool   | `false` | Whether interception is enabled                |
| `http`       | bool   | `false` | Whether to intercept HTTP traffic             |
| `https`      | bool   | `false` | Whether to intercept HTTPS traffic            |
| `ca_file`    | string |         | Path to CA certificate file (for HTTPS/QUIC)  |
| `ca_key_file`| string |         | Path to CA private key file (for HTTPS/QUIC)  |

### Classifiers

Classifiers define matching rules for hosts/requests. Supported types:

- `and` / `or`: Boolean logic over sub-classifiers
- `not`: Negates a classifier
- `domain`: Match by domain (fields: `domain`, `op` = `is`, `contains`, etc.)
- `ip`: Match by exact IP (field: `ip`)
- `network`: Match by CIDR (field: `cidr`)
- `port`: Match by port (field: `port`)
- `ref`: Reference another named classifier (field: `id`)
- `true` / `false`: Always match / never match
- `domains-file`: Match domains from a file (field: `file`)

### Forwards

Each forward rule has:

- `type`: One of `default_network`, `socks5`, `proxy`
- `classifier`: Classifier object (see above)
- `address`: (for `socks5`/`proxy`) Target address
- `username`/`password`: (optional, for `socks5`/`proxy`)

### Environment Variables

Configuration options can be overridden by environment variables with the `MSGTAUSCH_` prefix:

#### Global Configuration

| Environment Variable                   | Description                           | Type    |
|---------------------------------------|---------------------------------------|---------|
| `MSGTAUSCH_TIMEOUTSECONDS`           | Request timeout in seconds            | int     |
| `MSGTAUSCH_MAXCONCURRENTCONNECTIONS` | Maximum concurrent connections        | int     |
| `MSGTAUSCH_INTERCEPT`                | Enable traffic interception           | bool    |
| `MSGTAUSCH_INTERCEPTHTTP`            | Enable HTTP traffic interception      | bool    |
| `MSGTAUSCH_INTERCEPTHTTPS`           | Enable HTTPS traffic interception     | bool    |
| `MSGTAUSCH_CAFILE`                   | Path to CA certificate file           | string  |
| `MSGTAUSCH_CAKEYFILE`                | Path to CA private key file           | string  |
| `MSGTAUSCH_LISTENADDRESS`            | Address for single server (backward compatibility) | string |

#### Server-Specific Configuration

For multiple servers, use indexed environment variables:

| Environment Variable Pattern          | Description                           | Type    |
|---------------------------------------|---------------------------------------|---------|
| `MSGTAUSCH_SERVER_N_LISTENADDRESS`   | Listen address for server N           | string  |
| `MSGTAUSCH_SERVER_N_TYPE`            | Proxy type for server N               | string  |
| `MSGTAUSCH_SERVER_N_ENABLED`         | Enable/disable server N               | bool    |
| `MSGTAUSCH_SERVER_N_MAXCONNECTIONS`  | Max connections for server N          | int     |
| `MSGTAUSCH_SERVER_N_CONNECTIONSPCLIENT` | Max connections per client for server N | int  |
| `MSGTAUSCH_SERVER_N_CAFILE`          | CA file for server N                  | string  |
| `MSGTAUSCH_SERVER_N_CAKEYFILE`       | CA key file for server N              | string  |

Where `N` is the server index (0, 1, 2, etc.).

**Example:**
```bash
MSGTAUSCH_TIMEOUTSECONDS=60
MSGTAUSCH_SERVER_0_LISTENADDRESS=127.0.0.1:8080
MSGTAUSCH_SERVER_0_TYPE=standard
MSGTAUSCH_SERVER_1_LISTENADDRESS=127.0.0.1:8443
MSGTAUSCH_SERVER_1_TYPE=https
```

### Format

- File extension determines format: `.json` for JSON, `.hcl` for HCL.
- For HCL, use equivalent field names (`listen_address`, etc).

## Building with Docker

This project uses Docker Bake for building and testing. Make sure you have Docker and `docker buildx` installed.

### Supported Platforms

The build system supports the following platforms:
- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64)

### Quick Start with Docker

1. Run tests and build binaries:
```bash
# Run default targets (test and build)
docker buildx bake --set=*.output=type=cacheonly --set=*.cache-from= --set=*.cache-to=
```

2. Build a specific target:
```bash
# Only run tests
docker buildx bake test --set=*.output=type=cacheonly --set=*.cache-from= --set=*.cache-to=

# Only build binaries
docker buildx bake build --set=*.output=type=cacheonly --set=*.cache-from= --set=*.cache-to=
```

3. Create a release:
```bash
VERSION=v1.0.0 docker buildx bake release --set=*.output=type=cacheonly --set=*.cache-from= --set=*.cache-to=
```

4. Run simulation:
```bash
docker buildx bake simulation --set=*.output=type=cacheonly --set=*.cache-from= --set=*.cache-to=
```

## License

This project is licensed under the GNU General Public License v3.0 (GPL-3.0). This means:

- You are free to use, modify, and distribute this software
- If you distribute this software or modified versions, you must provide the source code
- Any modifications must also be licensed under the GPL-3.0
- There is no warranty for this software

See the [LICENSE](LICENSE) file for the full license text.
