# Legacy HTTP/1 compatibility tests

This Compose stack puts a raw TCP origin behind msgtausch. The origin writes
HTTP bytes itself, which lets the suite cover behavior that normal server
libraries hide or rewrite.

Run it with:

```bash
tests/compose-legacy-http/run.sh
```

The client checks:

- HTTP/1.0 response bodies delimited by connection close
- HTTP/1.1 response bodies delimited by connection close
- fragmented chunked bodies with chunk extensions and an upstream trailer
- a final response preceded by `103 Early Hints`
- `HEAD` and `204 No Content` body rules
- an HTTP/1.0 client request using absolute form through the proxy
- truncated and conflicting upstream framing failing without killing the proxy

The malformed cases do not require a particular downstream error page. They
require the request to fail and a subsequent healthy request to succeed. This
keeps the test about isolation instead of coupling it to Hyper's error text.

The client reports whether msgtausch forwards trailers and informational
responses, but does not require either. The compatibility check is that these
upstream messages do not corrupt or hide the final response body.

Files:

- `origin/server.py` is the raw origin fixture.
- `origin/healthcheck.py` checks the fixture directly.
- `client/run.py` sends and parses raw requests through msgtausch.
- `proxy-config.json` enables a standard direct proxy listener.
- `docker-compose.yml` builds and connects the three services.
