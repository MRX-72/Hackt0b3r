"""Delivery policy: severity floor, dedupe per incident, rate limit, retry, circuit breaker."""

import json
import time
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from raven.config.secrets import Secrets
from raven.config.settings import NotifySettings
from raven.contracts.models import Channel, Delivery, Explanation, SanitizedIncident
from raven.net.http import Request, Response, Transport, TransportError
from raven.notify.channels import Notification, build_builders

_MAX_RETRY_AFTER_SECONDS = 30.0  # never let a server stall detection for long
_BACKOFF_BASE_SECONDS = 1.0
_RATE_WINDOW_SECONDS = 60.0
_HTTP_OK_MIN = 200
_HTTP_OK_MAX = 299
_HTTP_RATE_LIMITED = 429
_HTTP_SERVER_ERROR = 500


@dataclass
class _ChannelState:
    failures: int = 0
    open_until: float = 0.0
    sent: deque[float] = field(default_factory=deque)


def _retry_after(response: Response) -> float | None:
    """Discord: top-level retry_after. Telegram: parameters.retry_after (both seconds)."""
    try:
        body: Any = json.loads(response.body)
        value = body.get("retry_after") or body.get("parameters", {}).get("retry_after")
        return min(float(value), _MAX_RETRY_AFTER_SECONDS) if value else None
    except (ValueError, AttributeError, TypeError):
        return None


def _succeeded(channel: Channel, response: Response) -> bool:
    if not _HTTP_OK_MIN <= response.status <= _HTTP_OK_MAX:
        return False
    if channel == "telegram":  # Telegram answers 200 with {"ok": false, ...} on some errors
        try:
            return bool(json.loads(response.body).get("ok"))
        except (ValueError, AttributeError):
            return False
    return True


class Notifier:
    def __init__(
        self,
        settings: NotifySettings,
        secrets: Secrets,
        transport: Transport,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        self._s = settings
        self._builders = build_builders(secrets, settings.timeout_seconds)
        self._transport, self._clock, self._sleep = transport, clock, sleep
        self.on_delivery: Callable[[Delivery, str], None] | None = None  # set by the pipeline
        self._state: dict[Channel, _ChannelState] = {
            c: _ChannelState() for c in ("slack", "discord", "telegram")
        }
        self._notified: dict[str, int] = {}

    def notify(self, incident: SanitizedIncident, explanation: Explanation) -> list[Delivery]:
        """Send once per incident, again only when a new technique joins its chain."""
        if not self._s.enabled:
            return []
        size = len({s.technique for s in incident.steps})
        if incident.severity < self._s.min_severity:
            return self._skip_all(incident.incident_id, "below minimum severity")
        if self._notified.get(incident.incident_id, 0) >= size:
            return self._skip_all(incident.incident_id, "already notified")
        self._notified[incident.incident_id] = size
        link = (
            f"{self._s.link_base_url.rstrip('/')}/{incident.incident_id}"
            if self._s.link_base_url
            else None
        )
        note = Notification(incident, explanation, link)
        return self._record(incident.incident_id, [self._send(c, note) for c in self._s.channels])

    def _skip_all(self, incident_id: str, detail: str) -> list[Delivery]:
        skipped = [Delivery(channel=c, status="skipped", detail=detail) for c in self._s.channels]
        return self._record(incident_id, skipped)

    def test(
        self, channel: Channel, incident: SanitizedIncident, explanation: Explanation
    ) -> Delivery:
        """Send a message now, ignoring severity, dedupe and enabled flag."""
        return self._send(channel, Notification(incident, explanation))

    def _record(self, incident_id: str, deliveries: list[Delivery]) -> list[Delivery]:
        if self.on_delivery:
            for d in deliveries:
                self.on_delivery(d, incident_id)
        return deliveries

    def _send(self, channel: Channel, note: Notification) -> Delivery:
        build = self._builders.get(channel)
        if build is None:
            return Delivery(channel=channel, status="skipped", detail="no credentials configured")
        state, now = self._state[channel], self._clock()
        if now < state.open_until:
            return Delivery(
                channel=channel, status="skipped", detail="circuit open after repeated failures"
            )
        while state.sent and now - state.sent[0] > _RATE_WINDOW_SECONDS:
            state.sent.popleft()
        if len(state.sent) >= self._s.max_per_minute:
            return Delivery(channel=channel, status="skipped", detail="rate limit")
        detail = self._attempt(channel, build(note))
        state.sent.append(now)
        if detail is None:
            state.failures = 0
            return Delivery(channel=channel, status="sent", detail="ok")
        state.failures += 1
        if state.failures >= self._s.breaker_failures:
            state.open_until = self._clock() + self._s.breaker_cooloff_seconds
            state.failures = 0
        return Delivery(channel=channel, status="failed", detail=detail)

    def _attempt(self, channel: Channel, request: Request) -> str | None:
        """None on success, else a short failure reason (no URL, no secrets)."""
        reason = "unknown"
        for attempt in range(self._s.retries + 1):
            try:
                response = self._transport(request)
            except TransportError as exc:
                reason, wait = f"network error: {exc}", _BACKOFF_BASE_SECONDS * 2**attempt
            else:
                if _succeeded(channel, response):
                    return None
                reason = f"HTTP {response.status}"
                transient = (
                    response.status == _HTTP_RATE_LIMITED or response.status >= _HTTP_SERVER_ERROR
                )
                if not transient:
                    return reason  # a malformed payload or dead webhook will not fix itself
                wait = _retry_after(response) or _BACKOFF_BASE_SECONDS * 2**attempt
            if attempt < self._s.retries:
                self._sleep(wait)
        return reason
