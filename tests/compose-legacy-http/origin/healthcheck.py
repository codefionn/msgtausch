"""Small dependency-free health probe for the raw HTTP fixture."""

import os
import socket
import sys


def main() -> int:
    port = int(os.environ.get("PORT", "8081"))
    request = b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"

    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1) as connection:
            connection.settimeout(1)
            connection.sendall(request)
            chunks = []
            while chunk := connection.recv(1024):
                chunks.append(chunk)
    except OSError as error:
        print(f"health probe failed: {error}", file=sys.stderr)
        return 1

    response = b"".join(chunks)
    if b"HTTP/1.1 200 OK\r\n" not in response or not response.endswith(b"healthy"):
        print("health probe received an unexpected response", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
