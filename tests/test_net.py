import threading
from collections.abc import Iterator
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from sentinel.net.http import Request, TransportError, json_request, urllib_transport


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
