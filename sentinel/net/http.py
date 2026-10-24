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


def urllib_transport(request: Request) -> Response:
    if not request.url.startswith(("http://", "https://")):
        raise TransportError("only http and https URLs are allowed")
    req = urllib.request.Request(  # noqa: S310 - scheme checked above
        request.url, data=request.body, headers=request.headers, method=request.method
    )
    try:
        with urllib.request.urlopen(req, timeout=request.timeout) as resp:  # noqa: S310
            return Response(resp.status, resp.read())
    except urllib.error.HTTPError as exc:
        return Response(exc.code, exc.read())
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise TransportError(
            type(exc.reason if isinstance(exc, urllib.error.URLError) else exc).__name__
        ) from None
