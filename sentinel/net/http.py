"""Minimal HTTP transport (stdlib). Errors never include the URL: URLs can carry secrets."""

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any


class TransportError(Exception):
    """Network-level failure (DNS, refused, timeout). The message names the cause class only."""


@dataclass(frozen=True)
class Request:
    method: str
    url: str = field(repr=False)
    body: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict, repr=False)
    timeout: float = 10.0


@dataclass(frozen=True)
class Response:
    status: int
    body: bytes


Transport = Callable[[Request], Response]


def json_request(
    method: str,
    url: str,
    payload: Any,
    headers: dict[str, str] | None = None,
    timeout: float = 10.0,
) -> Request:
    body = None if payload is None else json.dumps(payload).encode()
    base = {"Content-Type": "application/json"} if body is not None else {}
    return Request(method, url, body, base | (headers or {}), timeout)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """A redirect would re-send our headers (an LLM API key) to whatever host it names."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)
MAX_RESPONSE_BYTES = (
    4 * 1024 * 1024
)  # webhook and LLM replies are tiny; a server cannot make us buffer more


def _read(stream: Any) -> bytes:
    data: bytes = stream.read(MAX_RESPONSE_BYTES + 1)
    if len(data) > MAX_RESPONSE_BYTES:
        raise TransportError("response too large")
    return data


def urllib_transport(request: Request) -> Response:
    if not request.url.startswith(("http://", "https://")):
        raise TransportError("only http and https URLs are allowed")
    req = urllib.request.Request(  # noqa: S310 - scheme checked above
        request.url, data=request.body, headers=request.headers, method=request.method
    )
    try:
        with _OPENER.open(req, timeout=request.timeout) as resp:
            return Response(resp.status, _read(resp))
    except urllib.error.HTTPError as exc:
        return Response(exc.code, _read(exc))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TransportError(
            type(exc.reason if isinstance(exc, urllib.error.URLError) else exc).__name__
        ) from None
