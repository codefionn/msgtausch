# msgtausch

![msgtausch logo](./logo.png)

> This project is actively in intial development. Use at your own risk!

A configurable forward proxy written in Go that can be configured using either JSON or environment variables.

## Features

- HTTP/HTTPS forward proxy
- HTTP/HTTPS/QUIC interception support
- Forward support (forward specific connections to socks5 proxy, upstream proxy
  or default connection)
- A single binary

## Non-goals

- HTML-Filtering

## Configuration

**msgtausch** supports configuration in both **JSON** and **HCL** formats.
The configuration file path can be specified via CLI or environment variable.
Most options can also be set via environment variables.

For comprehensive configuration documentation, see [docs/configuration.md](docs/configuration.md).

### Format

- File extension determines format: `.json` for JSON, `.hcl` for HCL.
- For HCL, use equivalent field names (`listen-address`, etc).

## Project overview

- **cmd/proxy-test/main.go** - Testing the proxy in the real world
- **cmd/simulation/main.go** - Attempt for implementing simulation tests that kinda work
  (kinda like fuzzy testing but way cooler)
- **cmd/throughput-test/main.go** - Testing throughput on localhost
  (May your downloads be fast)
- **main.go** - Main program for running the proxy

## Building with Docker

This project uses Docker Bake for building and testing. Make sure you have Docker and `docker buildx` installed.

### Supported Platforms

The build system supports Linux `amd64` and `arm64` (and the containers are published as such).

This project may work for other operating systems but is specialized for Linux.

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
