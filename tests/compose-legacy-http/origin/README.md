# Raw legacy HTTP origin

This dependency-free TCP server writes response bytes itself. It exists for
compose tests that need behavior normal web servers tend to hide.

| Path | Response behavior |
| --- | --- |
| `/health` | Normal HTTP/1.1 response with body `healthy`. |
| `/http10-close` | HTTP/1.0 response. Its body is delimited only by connection close. |
| `/http11-close` | HTTP/1.1 response. Its body is delimited only by connection close. |
| `/chunked-trailers` | Fragmented chunked response with extensions and trailer `X-Legacy-Trailer: present`. |
| `/early-hints` | `103 Early Hints`, followed by a normal `200` response. |
| `/head` | `HEAD` returns `Content-Length: 13` and no body. `GET` returns `head response`. |
| `/no-content` | `204 No Content`, with no message body. |
| `/truncated-content-length` | Declares `Content-Length: 32`, sends `too short`, then closes. |
| `/conflicting-framing` | Sends both `Content-Length` and `Transfer-Encoding: chunked`. |

The server accepts up to 64 concurrent connections. It limits request headers to
32 KiB and closes every response connection so EOF-delimited endpoints remain
unambiguous.
