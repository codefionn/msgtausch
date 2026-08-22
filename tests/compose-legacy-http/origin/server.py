"""Raw HTTP/1 fixture for wire-level proxy compatibility tests.

This server intentionally does not use Python's HTTP stack. Each endpoint writes
the response bytes itself, including invalid framing where noted.
"""

import logging
import os
import signal
import socket
import socketserver
import threading
from urllib.parse import urlsplit


HEADER_LIMIT = int(os.environ.get("HEADER_LIMIT", "32768"))
MAX_CONNECTIONS = int(os.environ.get("MAX_CONNECTIONS", "64"))
PORT = int(os.environ.get("PORT", "8081"))
READ_SIZE = 4096

if HEADER_LIMIT < 1024:
    raise ValueError("HEADER_LIMIT must be at least 1024")
if MAX_CONNECTIONS < 1:
    raise ValueError("MAX_CONNECTIONS must be at least 1")


class RequestError(Exception):
    def __init__(self, status: int, reason: str):
        self.status = status
        self.reason = reason
        super().__init__(f"{status} {reason}")


def response(status: int, reason: str, headers: tuple[tuple[str, str], ...], body: bytes = b"") -> bytes:
    lines = [f"HTTP/1.1 {status} {reason}\r\n".encode("ascii")]
    lines.extend(f"{name}: {value}\r\n".encode("ascii") for name, value in headers)
    lines.append(b"\r\n")
    lines.append(body)
    return b"".join(lines)


def regular_response(body: bytes) -> bytes:
    return response(
        200,
        "OK",
        (
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(body))),
            ("Connection", "close"),
        ),
        body,
    )


def read_request(connection: socket.socket) -> tuple[str, str]:
    """Return method and path, retaining at most HEADER_LIMIT header bytes."""
    data = bytearray()
    marker = -1

    while marker < 0:
        marker = data.find(b"\r\n\r\n")
        if marker >= 0:
            if marker + 4 > HEADER_LIMIT:
                raise RequestError(431, "Request Header Fields Too Large")
            break
        if len(data) >= HEADER_LIMIT:
            raise RequestError(431, "Request Header Fields Too Large")

        chunk = connection.recv(min(READ_SIZE, HEADER_LIMIT - len(data)))
        if not chunk:
            raise RequestError(400, "Bad Request")
        data.extend(chunk)

    try:
        request_line = bytes(data[:marker]).split(b"\r\n", 1)[0].decode("iso-8859-1")
        method, target, version = request_line.split(" ", 2)
    except ValueError as error:
        raise RequestError(400, "Bad Request") from error

    if not method or not target or not version.startswith("HTTP/"):
        raise RequestError(400, "Bad Request")

    parsed = urlsplit(target)
    path = parsed.path if parsed.scheme or parsed.netloc else target.split("?", 1)[0]
    return method.upper(), path or "/"


def write_fragments(connection: socket.socket, *fragments: bytes) -> None:
    for fragment in fragments:
        connection.sendall(fragment)


def handle_endpoint(connection: socket.socket, method: str, path: str) -> str:
    if path == "/health":
        connection.sendall(regular_response(b"healthy"))
        return "health"

    if path == "/http10-close":
        write_fragments(
            connection,
            b"HTTP/1.0 200 OK\r\n",
            b"Content-Type: text/plain\r\n",
            b"Connection: close\r\n\r\n",
            b"http10-close",
        )
        return "http10-close"

    if path == "/http11-close":
        write_fragments(
            connection,
            b"HTTP/1.1 200 OK\r\n",
            b"Content-Type: text/plain\r\n",
            b"Connection: close\r\n\r\n",
            b"http11-close",
        )
        return "http11-close"

    if path == "/chunked-trailers":
        write_fragments(
            connection,
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n",
            b"Trailer: X-Legacy-Trailer\r\nConnection: close\r\n\r\n",
            b"8;part=one\r\nchunked \r\n",
            b"8;part=two\r\ntrailers\r\n",
            b"0\r\nX-Legacy-Trailer: present\r\n\r\n",
        )
        return "chunked-trailers"

    if path == "/early-hints":
        write_fragments(
            connection,
            b"HTTP/1.1 103 Early Hints\r\n",
            b"Link: </legacy.css>; rel=preload; as=style\r\n\r\n",
            regular_response(b"early hints"),
        )
        return "early-hints"

    if path == "/head":
        body = b"head response"
        headers = (
            ("Content-Type", "text/plain"),
            ("Content-Length", str(len(body))),
            ("Connection", "close"),
        )
        connection.sendall(response(200, "OK", headers, b"" if method == "HEAD" else body))
        return "head"

    if path == "/no-content":
        connection.sendall(response(204, "No Content", (("Connection", "close"),)))
        return "no-content"

    if path == "/truncated-content-length":
        write_fragments(
            connection,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n",
            b"Content-Length: 32\r\nConnection: close\r\n\r\n",
            b"too short",
        )
        return "truncated-content-length"

    if path == "/conflicting-framing":
        write_fragments(
            connection,
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n",
            b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n",
            b"Connection: close\r\n\r\n",
            b"5\r\nhello\r\n0\r\n\r\n",
        )
        return "conflicting-framing"

    connection.sendall(
        response(
            404,
            "Not Found",
            (("Content-Length", "10"), ("Connection", "close")),
            b"not found",
        )
    )
    return "not-found"


class LegacyHttpHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        self.request.settimeout(5)
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        try:
            method, path = read_request(self.request)
            endpoint = handle_endpoint(self.request, method, path)
            logging.info("%s %s %s -> %s", peer, method, path, endpoint)
        except RequestError as error:
            logging.info("%s rejected request: %s", peer, error)
            try:
                self.request.sendall(
                    response(
                        error.status,
                        error.reason,
                        (("Connection", "close"), ("Content-Length", "0")),
                    )
                )
            except OSError:
                pass
        except (OSError, ValueError) as error:
            logging.info("%s connection ended: %s", peer, error)


class BoundedThreadingTcpServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True
    request_queue_size = MAX_CONNECTIONS

    def __init__(self, address: tuple[str, int], handler: type[socketserver.BaseRequestHandler]):
        self.connections = threading.BoundedSemaphore(MAX_CONNECTIONS)
        super().__init__(address, handler)

    def process_request(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        if not self.connections.acquire(blocking=False):
            logging.warning("%s:%s rejected: connection limit", *client_address)
            try:
                request.sendall(response(503, "Service Unavailable", (("Connection", "close"), ("Content-Length", "0"))))
            finally:
                self.shutdown_request(request)
            return

        try:
            super().process_request(request, client_address)
        except BaseException:
            self.connections.release()
            raise

    def process_request_thread(self, request: socket.socket, client_address: tuple[str, int]) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self.connections.release()


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

    def stop(_signum: int, _frame: object) -> None:
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)
    with BoundedThreadingTcpServer(("0.0.0.0", PORT), LegacyHttpHandler) as server:
        logging.info(
            "legacy HTTP fixture listening on port %s, header limit %s, connection limit %s",
            PORT,
            HEADER_LIMIT,
            MAX_CONNECTIONS,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logging.info("legacy HTTP fixture stopped")


if __name__ == "__main__":
    main()
