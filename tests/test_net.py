import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from raven.net.http import (
    MAX_RESPONSE_BYTES,
    Request,
    TransportError,
    json_request,
    urllib_transport,
)


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:
        body = self.rfile.read(int(self.headers["Content-Length"]))
        self.send_response(418 if body == b'{"teapot": true}' else 200)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args: object) -> None:
        pass


@pytest.fixture
def server() -> Iterator[str]:
    httpd = HTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{httpd.server_port}"
    httpd.shutdown()
    httpd.server_close()


def test_roundtrip_and_http_errors_become_responses(server: str) -> None:
    ok = urllib_transport(json_request("POST", server, {"a": 1}))
    assert (ok.status, ok.body) == (200, b'{"a": 1}')
    assert urllib_transport(json_request("POST", server, {"teapot": True})).status == 418


@pytest.mark.security
def test_connection_errors_do_not_leak_the_url() -> None:
    with pytest.raises(TransportError) as err:
        urllib_transport(Request("GET", "http://127.0.0.1:1/token-in-path", timeout=2))
    assert "token-in-path" not in str(err.value) and "127.0.0.1" not in str(err.value)


@pytest.mark.security
@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/y", "gopher://x"])
def test_only_http_schemes_are_allowed(url: str) -> None:
    with pytest.raises(TransportError):
        urllib_transport(Request("GET", url))


@pytest.mark.security
def test_a_redirect_is_never_followed_so_headers_cannot_leak_to_another_host() -> None:
    seen: dict[str, str | None] = {}

    class Target(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            seen["auth"] = self.headers.get("Authorization")
            self.send_response(200)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_: object) -> None:
            pass

    target = HTTPServer(("127.0.0.1", 0), Target)
    port = target.server_address[1]

    class Redirector(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            self.rfile.read(int(self.headers["Content-Length"]))
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{port}/x")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def log_message(self, *_: object) -> None:
            pass

    redirector = HTTPServer(("127.0.0.1", 0), Redirector)
    for server in (target, redirector):
        threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        url = f"http://127.0.0.1:{redirector.server_address[1]}/"
        response = urllib_transport(Request("POST", url, b"{}", {"Authorization": "Bearer KEY"}))
    finally:
        for server in (target, redirector):
            server.shutdown()
            server.server_close()
    assert response.status == 302 and seen == {}  # the second host was never contacted


@pytest.mark.security
def test_an_oversized_reply_is_refused_instead_of_buffered(server: str) -> None:
    big = {"blob": "x" * (MAX_RESPONSE_BYTES + 10)}
    with pytest.raises(TransportError, match="too large"):
        urllib_transport(json_request("POST", server, big))
    small = {"blob": "x" * 1000}
    assert urllib_transport(json_request("POST", server, small)).status == 200
