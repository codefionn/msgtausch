# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

msgtausch is a configurable forward proxy written in Go that supports HTTP/HTTPS traffic interception, classification, and forwarding. It's a sophisticated proxy server that can handle multiple server instances with different protocols and configurations.

## Architecture

### Core Components

- **Main Entry Point**: `main.go` - CLI parsing, configuration loading, signal handling
- **Configuration System**: `msgtausch-srv/config/` - JSON/HCL config parsing, environment variable support
- **Proxy Engine**: `msgtausch-srv/proxy/` - Core proxy logic, request handling, tunneling
- **Dashboard**: `msgtausch-srv/dashboard/` - Web dashboard with templ-generated HTML templates
- **Logging**: `msgtausch-srv/logger/` - Structured logging system
- **Simulation**: `msgtausch-simulation/` - Performance testing and simulation tools

### Key Architecture Patterns

- **Multi-Server Architecture**: Single proxy instance can run multiple server types (standard, HTTP, HTTPS, QUIC)
- **Interceptor Pattern**: Pluggable interceptors for HTTP/HTTPS traffic inspection
- **Classifier System**: Rule-based traffic classification for forwarding decisions
- **Forward Chains**: Support for SOCKS5, HTTP proxy, and direct network forwarding

### Server Types

- `standard` - Basic HTTP proxy (default)
- `http` - HTTP intercepting proxy with traffic inspection
- `https` - HTTPS intercepting proxy with TLS termination
- `quic` - QUIC/HTTP3 intercepting proxy

## Build and Development Commands

### Using Docker Bake (Recommended)

```bash
# Run tests and build (default)
docker buildx bake

# Generate templ files
docker buildx bake templ

# Run only tests
docker buildx bake test

# Check code formatting
docker buildx bake format

# Build binaries for all platforms
docker buildx bake build

# Create release build
VERSION=v1.0.0 docker buildx bake release

# Run simulation tests
docker buildx bake simulation
```

### Standard Go Commands

```bash
# Generate templ files
templ generate

# Run tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Build binary
go build -o msgtausch .

# Run with debug logging
go run . -debug -config examples/config.json

# Format code
go fmt ./...

# Run linter (if installed)
golangci-lint run
```

## Testing

- Main test suite: `go test ./...`
- Individual package tests: `go test ./msgtausch-srv/proxy/`
- Simulation tests: `docker buildx bake simulation`
- Configuration tests: `go test ./msgtausch-srv/config/`

## Template Generation (templ)

The dashboard uses [templ](https://templ.guide/) for type-safe HTML template generation. Template files (*.templ) are located in `msgtausch-srv/dashboard/templates/` and must be compiled to Go code before building.

### Working with Templates

- Template files: `msgtausch-srv/dashboard/templates/*.templ`
- Generated Go files: `msgtausch-srv/dashboard/templates/*_templ.go`
- Install templ: `go install github.com/a-h/templ/cmd/templ@latest`
- Generate code: `templ generate` or `docker buildx bake templ`

### Important Notes

- Generated files are committed to the repository for build compatibility
- CI/CD checks that generated files are up to date
- Always run `templ generate` after modifying .templ files
- The Docker build process automatically generates templates during builds

## Configuration

The proxy uses a hierarchical configuration system:

1. **Default values** (hardcoded)
2. **JSON/HCL config files** (via `-config` flag)
3. **Environment variables** (prefixed with `MSGTAUSCH_`)

### Key Configuration Areas

- **Servers**: Array of server configurations with different types and addresses
- **Classifiers**: Named rules for traffic classification (domain, IP, network, etc.)
- **Forwards**: Rules for traffic forwarding (SOCKS5, HTTP proxy, direct)
- **Interception**: Settings for HTTP/HTTPS traffic inspection
- **Allowlist/Blocklist**: Access control based on classifiers

## Important Development Notes

### Proxy Chain Handling

The codebase has sophisticated support for proxy chains, especially for WebSocket connections. Pay attention to:

- `handleWebSocketTunnel()` in `proxy.go:711` - WebSocket upgrade handling
- `handleConnect()` in `proxy.go:864` - HTTPS/tunnel establishment
- Forward chain logic in `createForwardTCPClient()` in `proxy.go:1082`

### Error Handling

- Custom `ProxyError` types with error codes
- Structured error responses via `writeProxyErrorResponse()`
- Proper timeout handling for different connection types

### Context Management

- HTTP clients are stored in request context via `WithClient()`/`ClientFromContext()`
- Proper context cancellation for connection management
- Timeout handling through context and connection-level timeouts

### Signal Handling

- SIGHUP: Configuration reload without restart
- SIGINT/SIGTERM: Graceful shutdown
- Configuration change detection to avoid unnecessary restarts

## Common Development Tasks

### Adding New Server Types

1. Define new `ProxyType` constant in `config/config.go`
2. Add server initialization logic in `proxy.go` `NewProxy()` function
3. Implement server-specific handling in `ProxyServer.Start()` method
4. Add corresponding interceptor if needed

### Adding New Classifiers

1. Define new classifier type in `config/classifier.go`
2. Implement `ConfigClassifier` interface
3. Add parsing logic in `config.go` `parseClassifier()` function
4. Add compilation logic in `proxy/classifier.go`

### Adding New Forward Types

1. Define new forward type constant in `config/config.go`
2. Create new forward struct implementing `ConfigForward` interface
3. Add parsing logic in `loadJSONConfig()` function
4. Implement forwarding logic in `createForwardTCPClient()` function

## Testing Patterns

- Use `testify` for assertions (`github.com/stretchr/testify`)
- Configuration tests use JSON parsing validation
- Proxy tests often use `httptest` for HTTP server mocking
- WebSocket tests require special tunnel handling
- Interceptor tests need CA certificate management

## Dependencies

- `golang.org/x/net` - Extended network libraries
- `github.com/quic-go/quic-go` - QUIC protocol support
- `github.com/gorilla/websocket` - WebSocket handling
- `github.com/armon/go-socks5` - SOCKS5 proxy support
- `github.com/stretchr/testify` - Testing framework