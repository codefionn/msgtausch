# Performance benchmarks

The workspace uses Divan for microbenchmarks. Every benchmark binary installs
Divan's allocation profiler, so one run reports elapsed time, allocated bytes,
allocation count, deallocation count, and the maximum observed allocation.

Run every microbenchmark in release mode:

```bash
cargo bench --workspace
```

Filter by benchmark or package when working on one path:

```bash
cargo bench -p msgtausch-policy -- domain_matcher
cargo bench -p msgtausch-interception -- cached_leaf_config
cargo bench -p msgtausch-observability -- recording
```

`cargo test --workspace --all-targets` runs each benchmark function once. This
catches invalid fixtures and panics, but it does not collect performance data.

The suite covers these costs:

- JSON configuration loading, validation, and rule matching
- classifier compilation, ordered routing rules, and domain sets at several sizes
- proxy runtime construction and cheap runtime cloning
- interception CA loading, leaf certificate issuance, cached leaves, and policy
- observability setup plus first-label and repeated metric recording
- deterministic simulation generation and JSON conversion
- throughput report formatting

Setup that is not part of the operation stays outside the measured closure.
Cold-path benchmarks say so in their names. For example, leaf issuance uses a
new hostname for each sample, while cached leaf lookup reuses one hostname.

Do not compare timings from unrelated machines. CPU power policy, background
load, allocator behavior, and kernel versions all move the result. Compare two
commits on the same machine, keep the working tree and build profile the same,
and check allocation counts before chasing small timing changes. Allocation
counts are usually the cleaner signal.

The `msgtausch-throughput` package remains the end-to-end test for real TCP
traffic. Use it when a change affects listeners, parsing, routing, or copying:

```bash
cargo run --release -p msgtausch-throughput -- \
  --protocol both --requests 1000 --concurrency 32 --body-size 65536
```
