# Simulation runner

The simulation runner treats the compiled `msgtausch` binary as a black box. It starts loopback origins, forward proxies, DNS, and a remote domain-list server. The oracle is built from the scenario before the proxy starts. It does not call the proxy, routing, policy, or observability crates.

Generated scenarios cover the HTTP and CONNECT protocol matrix across direct, SOCKS5, and HTTP-forward routes. They send GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, and an extension method. Body sizes include empty, one byte, 31 bytes, 1 KiB, and 16 KiB. Each scenario mixes successful requests, policy blocks, refused upstream connections, and concurrent client groups.

Every run checks response status and body integrity, the selected route, origin and forward-fixture request counts, custom UDP DNS names and A/AAAA query counts, and remote domain-list use. A policy block must return 403 without touching a route or origin. A refused upstream must return 502 and increment the matching route error.

The runner takes a Prometheus snapshot after readiness and compares post-run deltas with its oracle. It checks:

- downstream connection total and the final active gauge;
- allow and block decisions;
- request totals by bounded method and status class;
- request-duration histogram count, sum validity, bucket monotonicity, and the `+Inf` bucket;
- selected routes and route errors for direct, SOCKS5, and HTTP-forward traffic;
- bounded proxy error kinds, including blocked, connect, and HTTP-forward failures;
- exact CONNECT tunnel bytes in each direction;
- tunnel-duration histogram structure and count;
- whole-family totals, which catch unexpected labels or extra events.

Run the fixed corpus against a debug binary:

```sh
cargo build -p msgtausch-cli -p msgtausch-simulation
target/debug/msgtausch-simulation --scenario crates/msgtausch-simulation/corpus/plain-connect-789.json --stats
target/debug/msgtausch-simulation --scenario crates/msgtausch-simulation/corpus/http-methods-bodies-792.json --stats
target/debug/msgtausch-simulation --scenario crates/msgtausch-simulation/corpus/forward-routes-790.json --enable-forwards --stats
target/debug/msgtausch-simulation --scenario crates/msgtausch-simulation/corpus/policy-dns-domains-791.json --enable-policy-fixtures --stats
target/debug/msgtausch-simulation --scenario crates/msgtausch-simulation/corpus/routes-policy-failures-793.json --enable-policy-fixtures --stats
```

Generated concurrent runs are useful after the fixed cases:

```sh
target/debug/msgtausch-simulation 2000 --runs 8 --jobs 2 --enable-policy-fixtures --stats
```

A failed run prints its seed and writes `simulation-artifacts/failure-SEED.json`. Replay it with `--replay`. The artifact contains the complete scenario, event log, last metrics scrape, redacted config, proxy stderr, and the error chain.

TLS interception, HTTP upgrades, HTTP/3, TCP and DNS-over-TLS resolvers, reload, and domain-list refresh or failure are not in this runner yet. Those paths need protocol-specific fixtures and should not be faked with unit-level calls.
