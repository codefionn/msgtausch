# CLAUDE.md

## Project

msgtausch is a Rust forward proxy workspace. The production binary is in `crates/msgtausch-cli/`.

## Rust layout

- `crates/msgtausch-cli/`: startup, listeners, signals, reload, and compatible CLI parsing.
- `crates/msgtausch-config/`: JSON, HCL, environment, secrets, and validation.
- `crates/msgtausch-policy/`: compiled access and route predicates plus remote domain lists.
- `crates/msgtausch-routing/`: direct, SOCKS5, and HTTP proxy connections.
- `crates/msgtausch-proxy/`: HTTP forwarding, CONNECT, and upgrades.
- `crates/msgtausch-interception/`: TLS certificate issuance and HTTPS interception.
- `crates/msgtausch-quic/`: QUIC and HTTP/3 transport primitives.
- `crates/msgtausch-observability/`: Prometheus and OTLP reporting.

## Commands

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo run -- --config examples/config.json
```

## Compatibility policy

Preserve supported config names, file and environment precedence, secret handling, first-match routes, HTTP semantics, and CONNECT behavior. Database statistics and the admin portal are not part of the Rust service.

Keep Prometheus labels bounded. Do not use hosts, URLs, client addresses, or user names as labels. Never print secret values.
