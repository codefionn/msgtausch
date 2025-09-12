Interception Tests (docker/podman compose)

This harness spins up a tiny HTTP and HTTPS backend (custom Go server), the msgtausch proxy with HTTP+HTTPS interception enabled, and a client that verifies end-to-end interception using curl.

Usage

- Prefer podman compose if available; falls back to docker compose.
- Run: `tests/compose-intercept/run.sh`
- The script builds the proxy image, runs tests, and tears everything down.

What it validates

- HTTP GET through the proxy reaches the backend and returns expected payload.
- HTTPS CONNECT is intercepted (MITM) and succeeds when the client trusts the test CA used by msgtausch.

Files

- `docker-compose.yml`: Services for proxy, custom backends, and client test.
- `proxy-config.json`: Standard proxy with interception enabled; uses CA at `/ca`.
- `ca/test_ca.crt` and `ca/test_ca.key`: Test CA (same as used in unit tests); do not use in production.
- `client/test.sh`: Curl-based assertions; fails the compose run on error.
- `backend/`: Minimal HTTP/HTTPS server used as upstream targets for the proxy.
