#!/usr/bin/env python3
"""Exercise HTTP response framing that ordinary HTTP clients tend to hide."""

from __future__ import annotations

import socket
import sys
import time
from dataclasses import dataclass


PROXY = ("proxy", 8080)
ORIGIN = "legacy-origin:8081"
HEADER_LIMIT = 64 * 1024
BODY_LIMIT = 8 * 1024 * 1024


class ProtocolError(RuntimeError):
    pass


@dataclass
class Response:
    status: int
    reason: str
    headers: list[tuple[str, str]]
    body: bytes
    trailers: list[tuple[str, str]]
    informational: list[tuple[int, list[tuple[str, str]]]]

    def header_values(self, name: str) -> list[str]:
        wanted = name.lower()
        return [value for key, value in self.headers if key.lower() == wanted]

    def trailer_values(self, name: str) -> list[str]:
        wanted = name.lower()
        return [value for key, value in self.trailers if key.lower() == wanted]


class BufferedSocket:
    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self.buffer = bytearray()

    def _receive(self) -> None:
        chunk = self.sock.recv(8192)
        if not chunk:
            raise EOFError("unexpected end of response")
        self.buffer.extend(chunk)

    def read_until(self, marker: bytes, limit: int) -> bytes:
        while True:
            position = self.buffer.find(marker)
            if position >= 0:
                end = position + len(marker)
                result = bytes(self.buffer[:end])
                del self.buffer[:end]
                return result
            if len(self.buffer) >= limit:
                raise ProtocolError("response headers exceed limit")
            self._receive()

    def read_exact(self, count: int) -> bytes:
        while len(self.buffer) < count:
            self._receive()
        result = bytes(self.buffer[:count])
        del self.buffer[:count]
        return result

    def read_to_close(self) -> bytes:
        result = bytearray(self.buffer)
        self.buffer.clear()
        while True:
            chunk = self.sock.recv(8192)
            if not chunk:
                return bytes(result)
            result.extend(chunk)
            if len(result) > BODY_LIMIT:
                raise ProtocolError("response body exceeds limit")


def parse_headers(raw: bytes) -> tuple[int, str, list[tuple[str, str]]]:
    if not raw.endswith(b"\r\n\r\n"):
        raise ProtocolError("header block is not CRLF terminated")
    lines = raw[:-4].split(b"\r\n")
    if not lines or not lines[0]:
        raise ProtocolError("missing status line")
    try:
        parts = lines[0].decode("iso-8859-1").split(" ", 2)
        version, status = parts[:2]
        reason = parts[2] if len(parts) == 3 else ""
        status_code = int(status)
    except (UnicodeDecodeError, ValueError) as error:
        raise ProtocolError("invalid status line") from error
    if version not in {"HTTP/1.0", "HTTP/1.1"} or not 100 <= status_code <= 999:
        raise ProtocolError("invalid status line")

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line or line[:1] in b" \t" or b":" not in line:
            raise ProtocolError("invalid header line")
        name, value = line.split(b":", 1)
        try:
            decoded_name = name.decode("ascii")
            decoded_value = value.decode("iso-8859-1").strip(" \t")
        except UnicodeDecodeError as error:
            raise ProtocolError("invalid header encoding") from error
        if not decoded_name:
            raise ProtocolError("empty header name")
        headers.append((decoded_name, decoded_value))
    return status_code, reason, headers


def header_values(headers: list[tuple[str, str]], name: str) -> list[str]:
    wanted = name.lower()
    return [value for key, value in headers if key.lower() == wanted]


def content_length(headers: list[tuple[str, str]]) -> int | None:
    raw_values = header_values(headers, "content-length")
    if not raw_values:
        return None
    values = [item.strip() for value in raw_values for item in value.split(",")]
    if not values or any(not value.isascii() or not value.isdecimal() for value in values):
        raise ProtocolError("invalid content-length")
    if len(set(values)) != 1:
        raise ProtocolError("conflicting content-length values")
    length = int(values[0])
    if length > BODY_LIMIT:
        raise ProtocolError("content-length exceeds limit")
    return length


def transfer_encoding(headers: list[tuple[str, str]]) -> list[str]:
    return [
        item.strip().lower()
        for value in header_values(headers, "transfer-encoding")
        for item in value.split(",")
        if item.strip()
    ]


def read_chunked(stream: BufferedSocket) -> tuple[bytes, list[tuple[str, str]]]:
    body = bytearray()
    while True:
        line = stream.read_until(b"\r\n", HEADER_LIMIT)[:-2]
        size_text = line.split(b";", 1)[0].strip()
        try:
            size = int(size_text, 16)
        except ValueError as error:
            raise ProtocolError("invalid chunk size") from error
        if size < 0:
            raise ProtocolError("negative chunk size")
        if size == 0:
            trailer_lines = bytearray()
            while True:
                line = stream.read_until(b"\r\n", HEADER_LIMIT)
                if line == b"\r\n":
                    break
                trailer_lines.extend(line)
                if len(trailer_lines) > HEADER_LIMIT:
                    raise ProtocolError("response trailers exceed limit")
            if trailer_lines:
                _, _, trailers = parse_headers(
                    b"HTTP/1.1 200 trailers\r\n" + trailer_lines + b"\r\n"
                )
            else:
                trailers = []
            return bytes(body), trailers
        if len(body) + size > BODY_LIMIT:
            raise ProtocolError("chunked body exceeds limit")
        body.extend(stream.read_exact(size))
        if stream.read_exact(2) != b"\r\n":
            raise ProtocolError("chunk is not CRLF terminated")


def read_response(stream: BufferedSocket, method: str) -> Response:
    informational: list[tuple[int, list[tuple[str, str]]]] = []
    while True:
        status, reason, headers = parse_headers(stream.read_until(b"\r\n\r\n", HEADER_LIMIT))
        if 100 <= status < 200 and status != 101:
            informational.append((status, headers))
            continue
        break

    if method == "HEAD" or status in {204, 304} or status == 101:
        return Response(status, reason, headers, b"", [], informational)

    encoding = transfer_encoding(headers)
    length = content_length(headers)
    if encoding and length is not None:
        raise ProtocolError("response contains both transfer-encoding and content-length")
    if encoding:
        if encoding[-1] != "chunked" or any(item != "chunked" for item in encoding):
            raise ProtocolError("unsupported transfer-encoding")
        body, trailers = read_chunked(stream)
        return Response(status, reason, headers, body, trailers, informational)
    if length is not None:
        return Response(status, reason, headers, stream.read_exact(length), [], informational)
    return Response(status, reason, headers, stream.read_to_close(), [], informational)


def request(path: str, *, method: str = "GET", version: str = "HTTP/1.1") -> Response:
    target = f"http://{ORIGIN}{path}"
    request_bytes = (
        f"{method} {target} {version}\r\n"
        f"Host: {ORIGIN}\r\n"
        "Connection: close\r\n"
        "User-Agent: msgtausch-legacy-http-test/1\r\n"
        "\r\n"
    ).encode("ascii")
    with socket.create_connection(PROXY, timeout=3) as sock:
        sock.settimeout(5)
        sock.sendall(request_bytes)
        return read_response(BufferedSocket(sock), method)


def expect(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def expect_response(
    path: str,
    body: bytes,
    *,
    method: str = "GET",
    version: str = "HTTP/1.1",
    status: int = 200,
) -> Response:
    response = request(path, method=method, version=version)
    expect(response.status == status, f"{path}: expected {status}, got {response.status}")
    expect(response.body == body, f"{path}: unexpected body {response.body!r}")
    print(f"[client] {path} OK")
    return response


def wait_until_ready() -> None:
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        try:
            response = request("/health")
            if response.status == 200 and response.body == b"healthy":
                print("[client] proxy and legacy origin ready")
                return
        except (OSError, EOFError, ProtocolError):
            pass
        time.sleep(0.5)
    raise RuntimeError("proxy or legacy origin did not become ready within 30 seconds")


def expect_malformed(path: str) -> None:
    try:
        response = request(path)
    except (OSError, EOFError, ProtocolError):
        print(f"[client] {path} rejected")
        return
    expect(response.status >= 400, f"{path}: malformed upstream response reached client as {response.status}")
    print(f"[client] {path} rejected with {response.status}")


def main() -> None:
    wait_until_ready()

    expect_response("/http10-close", b"http10-close", version="HTTP/1.0")
    expect_response("/http11-close", b"http11-close")

    chunked = expect_response("/chunked-trailers", b"chunked trailers")
    if chunked.trailer_values("x-legacy-trailer") == ["present"]:
        print("[client] /chunked-trailers trailer forwarded")
    else:
        print("[client] /chunked-trailers body accepted; trailer not forwarded")

    hints = expect_response("/early-hints", b"early hints")
    if any(status == 103 for status, _headers in hints.informational):
        print("[client] /early-hints informational response forwarded")
    else:
        print("[client] /early-hints final response accepted; 103 not forwarded")

    head = expect_response("/head", b"", method="HEAD")
    expect(head.header_values("content-length"), "/head: missing representation length")
    expect_response("/no-content", b"", status=204)

    expect_malformed("/truncated-content-length")
    expect_response("/health", b"healthy")
    expect_malformed("/conflicting-framing")
    expect_response("/health", b"healthy")
    print("[client] legacy HTTP compatibility tests passed")


if __name__ == "__main__":
    try:
        main()
    except (AssertionError, OSError, EOFError, ProtocolError, RuntimeError, socket.timeout) as error:
        print(f"[client] FAIL: {error}", file=sys.stderr)
        sys.exit(1)
