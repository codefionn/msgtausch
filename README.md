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

**msgtausch** supports configuration in both **JSON** and **HCL** formats.
The configuration file path can be specified via CLI or environment variable.
Most options can also be set via environment variables.

For comprehensive configuration documentation, see [docs/configuration.md](docs/configuration.md).

### Format

- File extension determines format: `.json` for JSON, `.hcl` for HCL.
- For HCL, use equivalent field names (`listen-address`, etc).

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
