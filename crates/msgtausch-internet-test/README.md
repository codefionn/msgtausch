`msgtausch-internet-test` is an opt-in smoke-test binary. It sends real HTTP
and HTTPS requests through msgtausch, so it is intentionally not part of the
regular test suite.

Build the debug proxy first, then run the smoke test from the repository root:

```sh
cargo build -p msgtausch-cli
cargo run -p msgtausch-internet-test
```

By default it starts `target/debug/msgtausch` with a temporary direct-route
configuration. To test an already running proxy instead:

```sh
cargo run -p msgtausch-internet-test -- --proxy 127.0.0.1:8080
```

Pass `--binary PATH` to start a proxy binary somewhere else.

The default set checks Example.com, Example.org, Cloudflare, GitHub, Wikipedia,
and Google. It includes plain HTTP, HTTPS through CONNECT, a small API response,
and an empty 204 response.

URLs are positional and repeatable. Supplying any URLs replaces those defaults:

```sh
cargo run -p msgtausch-internet-test -- \
  http://example.com/ https://example.com/
```

Use `--timeout-seconds` to set the per-request upper bound. The binary does
not read `HTTP_PROXY`, `HTTPS_PROXY`, or `NO_PROXY`; every request uses the
proxy selected by this command.
