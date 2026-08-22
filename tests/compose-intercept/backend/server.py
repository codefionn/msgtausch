import os
import ssl
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class BackendHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        tls_enabled = os.environ.get("TLS", "false").lower() == "true"
        if self.path == "/curl-http":
            body = f"curl-http-response path={self.path} method={self.command}"
        elif self.path == "/curl-https":
            body = f"curl-https-response path={self.path} method={self.command}"
        elif self.path == "/connect":
            body = f"connect-response path={self.path} method={self.command}"
        else:
            scheme = "https" if tls_enabled else "http"
            body = f"hello-{scheme} path={self.path}"

        encoded = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, _format, *_args):
        pass


port = int(os.environ.get("PORT", "5678"))
server = ThreadingHTTPServer(("", port), BackendHandler)
if os.environ.get("TLS", "false").lower() == "true":
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        os.environ.get("CA_CERT_FILE", "/ca/test_ca.crt"),
        os.environ.get("CA_KEY_FILE", "/ca/test_ca.key"),
    )
    server.socket = context.wrap_socket(server.socket, server_side=True)

server.serve_forever()
