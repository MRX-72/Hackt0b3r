"""Frames in, incidents out: parse, detect, correlate, sanitize, explain, notify, store."""

from collections.abc import Callable

from sentinel.config.settings import Settings
from sentinel.contracts.models import Alert, Event, Flow, IncidentReport, RunSummary
from sentinel.correlate.incidents import Correlator
from sentinel.detect.engine import DetectionEngine
from sentinel.explain.explainer import Explainer
from sentinel.explain.sanitize import sanitize_incident
from sentinel.notify.router import Notifier
from sentinel.sensor.parse import FrameParser
from sentinel.storage.db import Storage

_FLOW_BATCH = 500  # flows are written to SQLite in batches of this size


class Pipeline:
    def __init__(  # noqa: PLR0913 - one collaborator per pipeline stage
        self,
        settings: Settings,
        storage: Storage,
        explainer: Explainer,
        notifier: Notifier | None = None,
        *,
        on_event: Callable[[Event], None] | None = None,
        on_report: Callable[[IncidentReport], None] | None = None,
    ) -> None:
        self._storage, self._explainer, self._notifier = storage, explainer, notifier
        self._store = settings.storage
        self._on_event, self._on_report = on_event, on_report
        self._parser = FrameParser()
        self._engine = DetectionEngine(settings.detection)
        self._correlator = Correlator(settings.detection.incident_gap_seconds)
        self._pending_flows: list[Flow] = []
        self._explained: dict[str, int] = {}  # incident id -> chain length already explained
        self._flows = self._alerts = self._incidents = 0
        if notifier is not None:
            notifier.on_delivery = storage.log_delivery

    def ingest(self, ts: float, frame: bytes) -> None:
        for event in self._parser.parse(frame, ts):
            if self._on_event:
                self._on_event(event)
            if isinstance(event, Flow):
                self._flows += 1
                if self._store.store_flows:
                    self._pending_flows.append(event)
                    if len(self._pending_flows) >= _FLOW_BATCH:
                        self._flush_flows()
            for alert in self._engine.process(event, ts):
                self._handle(alert)

    def tick(self, now: float) -> None:
        """Live idle heartbeat: evaluate detectors even though no packet has arrived."""
        for alert in self._engine.advance(now):
            self._handle(alert)

    def finish(self) -> RunSummary:
        for alert in self._engine.flush():
            self._handle(alert)
        self._flush_flows()
        stats = self._explainer.stats
        return RunSummary(
            frames=self._parser.frames, flows=self._flows, alerts=self._alerts,
            incidents=self._incidents, parse_errors=self._parser.parse_errors,
            payload_errors=self._parser.payload_errors,
            truncated_payloads=self._parser.truncated_payloads,
            late_dropped=self._engine.windows.late_dropped,
            state_capped=self._engine.windows.state_capped,
            llm_used=stats.llm_used, llm_rejected=stats.llm_rejected, llm_errors=stats.llm_errors,
        )  # fmt: skip

    def prune(self, now: float) -> dict[str, int]:
        """Apply retention relative to `now` (wall-clock time in live mode)."""
        day = 86400.0
        return self._storage.prune(
            flows_before=now - self._store.flow_retention_days * day,
            alerts_before=now - self._store.alert_retention_days * day,
        )

    def _flush_flows(self) -> None:
        if self._pending_flows:
            self._storage.insert_flows(self._pending_flows)
            self._pending_flows = []

    def _handle(self, alert: Alert) -> None:
        self._alerts += 1
        self._storage.insert_alert(alert)
        incident = self._correlator.add(alert)
        known = self._explained.get(incident.id)
        if known is not None:
            previous = self._storage.get_incident(incident.id)
            if previous is not None:
                incident = incident.model_copy(
                    update={"summary": previous.summary, "status": previous.status}
                )
        self._storage.save_incident(incident)
        if known is not None and len(incident.chain) <= known:
            return
        if known is None:
            self._incidents += 1
        self._explained[incident.id] = len(incident.chain)
        sanitized = sanitize_incident(incident, self._correlator.alerts_of(alert.host_mac))
        explanation = self._explainer.explain(sanitized)
        deliveries = self._notifier.notify(sanitized, explanation) if self._notifier else []
        sent = any(d.status == "sent" for d in deliveries)
        incident = incident.model_copy(
            update={"summary": explanation.headline, "status": "notified" if sent else "explained"}
        )
        self._storage.save_incident(incident)
        if self._on_report:
            self._on_report(
                IncidentReport(incident=incident, explanation=explanation, deliveries=deliveries)
            )
