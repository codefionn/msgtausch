# msgtausch

![msgtausch logo](./logo.png)

msgtausch is a configurable forward proxy written in Rust on the Compio async runtime. It handles ordinary HTTP requests, HTTPS CONNECT tunnels and interception, HTTP/3, WebSocket upgrades, access rules, and per-target forwarding through direct, SOCKS5, or upstream HTTP proxy connections.

The proxy has no database or admin page. It reports through Prometheus and optional OTLP traces.

## Current protocol support

- Standard HTTP forward proxy listeners
- HTTPS through CONNECT tunnels, with optional CA-backed interception
- Dedicated HTTPS and HTTP/3 listeners
- HTTP/1 upgrade and WebSocket tunnels
- Direct, forced IPv4, SOCKS5, and upstream HTTP CONNECT routes
- UDP, TCP, and DNS-over-TLS resolvers
- Domain, IP, network, port, boolean, reference, file-backed, and remote-list classifiers
- Allowlist and blocklist rules
- Prometheus counters, gauges, and duration histograms
- Optional OTLP trace export
- SIGHUP configuration reload

On Linux, Compio selects io_uring when the kernel supports the required operations and falls back to polling when it does not. The selected driver is written to the startup log.

## Run locally

```bash
cargo run -p msgtausch-cli -- --config examples/config.json
```

Legacy flag spellings are accepted too:

```bash
cargo run -p msgtausch-cli -- -config examples/config.json -debug
```

See [configuration.md](docs/configuration.md) for JSON, HCL, environment variables, routing, and observability.

## Checks

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets
cargo build -p msgtausch-cli --bin msgtausch
cargo run -p msgtausch-internet-test
cargo run -p msgtausch-simulation -- 9000 --binary target/debug/msgtausch --runs 4 --jobs 2 --enable-policy-fixtures --stats
cargo run -p msgtausch-throughput -- --protocol both --requests 1000 --concurrency 32 --body-size 65536
cargo bench --workspace
```

The Docker simulation target replays every checked-in scenario, then runs four
generated seeds across two workers. Generated cases mix HTTP and CONNECT,
request methods and body sizes, forwarding routes, blocked requests, broken
routes, concurrent batches, and metric reconciliation.

`msgtausch-internet-test` is the opt-in public-network check. It starts the
debug proxy and requests HTTP and HTTPS URLs from Example.com, Example.org,
Cloudflare, GitHub, Wikipedia, and Google. Pass `--proxy` to test an existing
instance or provide URLs as positional arguments. It is kept out of the regular
test suite because DNS and remote sites can fail independently of the proxy.

`msgtausch-throughput` starts a loopback origin and the compiled proxy by default. Pass `--proxy host:port` to measure an already-running proxy. It checks every response body, supports HTTP and CONNECT traffic, and reports request rate, IEC-scaled throughput, and p50/p95/p99 latency. Use `--requests 0 --duration 30s` for a duration-only run.

## Benchmarks

The microbenchmarks report elapsed time and heap allocation counts. Run the full
set with `cargo bench --workspace`, or pass a Divan name filter after `--` to
measure one path. The normal workspace test command runs every benchmark once
as a smoke test without collecting statistics.

See [benchmarking.md](docs/benchmarking.md) for the benchmark groups and advice
on comparing runs.

## Docker and Nix

```bash
docker buildx bake test
docker buildx bake simulation
docker buildx bake throughput
docker buildx bake build
docker buildx bake image
nix build .#msgtausch
```

`build` writes the native binaries into separate directories, `bin/linux-amd64/`
and `bin/linux-arm64/`. `image` writes one multi-platform OCI archive to
`dist/msgtausch-dev.oci`. It contains both Linux manifests and does not depend
on the single-platform `docker load` format.

To publish the production proxy image, use a Buildx builder with amd64 and
arm64 support, then push the manifest list:

```bash
IMAGE=registry.example/msgtausch VERSION=v1.2.3 \
  BUILD_CONFIGURATION=release docker buildx bake release
```

The GitHub main-branch workflow publishes the two-platform
`quay.io/codefionn/msgtausch:main` image used by both Helm charts. Tag builds
publish version, major-minor, and major tags to Docker Hub and Quay. The GitLab
tag pipeline publishes `${CI_COMMIT_TAG}` to its project registry.

The container exposes the proxy on the addresses in the mounted config. Port 9090 is conventional for the optional Prometheus listener, but it is disabled unless configured.

## License

msgtausch is licensed under GPL-3.0. See [LICENSE](LICENSE).
