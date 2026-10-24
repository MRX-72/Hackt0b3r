"""Drives window state and detectors in event time, with per-host cooldown."""

from sentinel.config.settings import BUCKET_SECONDS, DetectionSettings
from sentinel.contracts.models import Alert, Event
from sentinel.detect.interface import Detector
from sentinel.detect.rules import Beaconing, BruteForce, DnsTunnel, PortScan
from sentinel.features.windows import WindowEngine


class DetectionEngine:
    def __init__(
        self, settings: DetectionSettings, detectors: list[Detector] | None = None
    ) -> None:
        self.windows = WindowEngine(settings)
        self._detectors: list[Detector] = detectors or [
            PortScan(settings), BruteForce(settings), Beaconing(settings), DnsTunnel(settings),
        ]  # fmt: skip
        self._cooldown = settings.cooldown_seconds
        self._last_alert: dict[tuple[str, str], float] = {}
        self._next_tick: float | None = None
        self._latest = 0.0

    def process(self, event: Event, ts: float) -> list[Alert]:
        """Feed one event; returns alerts raised by any evaluation tick the event's time passed."""
        alerts: list[Alert] = []
        if self._next_tick is None:
            self._next_tick = (ts // BUCKET_SECONDS + 1) * BUCKET_SECONDS
        elif ts >= self._next_tick:
            alerts = self._evaluate(self._next_tick)
            self._next_tick = (ts // BUCKET_SECONDS + 1) * BUCKET_SECONDS
        self.windows.observe(event)
        self._latest = max(self._latest, ts)
        return alerts

    def flush(self) -> list[Alert]:
        """Evaluate once at the latest event time (end of a replay)."""
        return self._evaluate(self._latest) if self._next_tick is not None else []

    def _evaluate(self, now: float) -> list[Alert]:
        raised: list[Alert] = []
        for ctx in self.windows.snapshot(now):
            for detector in self._detectors:
                key = (detector.name, ctx.host_mac)
                if now - self._last_alert.get(key, -self._cooldown) < self._cooldown:
                    continue
                if alerts := detector.on_window(ctx):
                    self._last_alert[key] = now
                    raised += alerts
        return raised
