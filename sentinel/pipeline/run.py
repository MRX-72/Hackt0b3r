"""Frames in, incidents out: parse, detect, correlate, sanitize, explain, notify, store."""

import time
from collections.abc import Callable
from typing import Literal

from sentinel.config.settings import Settings
from sentinel.contracts.models import (
    Alert,
    AnomalyRecord,
    Event,
    Explanation,
    Flow,
    Incident,
    IncidentReport,
    RunSummary,
)
from sentinel.contracts.severity import severity_label
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
        source: Literal["live", "replay"] = "live",
    ) -> None:
        self._storage, self._explainer, self._notifier = storage, explainer, notifier
        self._store = settings.storage
        self._on_event, self._on_report = on_event, on_report
        self._source = source
        self._parser = FrameParser()
        self._engine = DetectionEngine(settings.detection)
        self._correlator = Correlator(settings.detection.incident_gap_seconds)
        self._pending_flows: list[Flow] = []
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

    def _log_anomaly(self, alert: Alert, incident: Incident, explanation: Explanation) -> None:
        """Append to the permanent history (never pruned), whatever the working tables do."""
        self._storage.log_anomaly(
            AnomalyRecord(
                ts=alert.ts,
                logged_at=time.time(),
                source=self._source,
                detector=alert.detector,
                technique=alert.technique,
                severity=alert.severity,
                confidence=alert.confidence,
                label=severity_label(incident.score).upper(),
                score=incident.score,
                host_mac=alert.host_mac,
                host_ip=alert.host_ip,
                target_ip=alert.target_ip,
                headline=explanation.headline,
                what_happened=explanation.what_happened,
                likely_cause=explanation.likely_cause,
                action=explanation.suggested_action,
                chain=incident.chain,
                incident_id=incident.id,
                evidence=alert.evidence,
            )
        )

    def _handle(self, alert: Alert) -> None:
        """Every alert yields its own report: the incident so far, explained by its newest step."""
        self._alerts += 1
        self._storage.insert_alert(alert)
        incident = self._correlator.add(alert)
        previous = self._storage.get_incident(incident.id)
        if previous is None:
            self._incidents += 1
        self._storage.save_incident(incident)
        sanitized = sanitize_incident(incident, self._correlator.alerts_of(alert.host_mac))
        explanation = self._explainer.explain(sanitized)
        deliveries = self._notifier.notify(sanitized, explanation) if self._notifier else []
        notified = any(d.status == "sent" for d in deliveries) or (
            previous is not None and previous.status == "notified"
        )
        incident = incident.model_copy(
            update={
                "summary": explanation.headline,
                "status": "notified" if notified else "explained",
            }
        )
        self._storage.save_incident(incident)
        self._log_anomaly(alert, incident, explanation)
        if self._on_report:
            self._on_report(
                IncidentReport(incident=incident, explanation=explanation, deliveries=deliveries)
            )
