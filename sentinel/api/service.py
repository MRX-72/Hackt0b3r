"""In-process service surface used by the CLI now and by an HTTP/GUI adapter later (D-013/D-015).

Returns contract models only; formatting and printing belong to the clients.
"""

import socket
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path

from sentinel.config.secrets import Secrets, SecretsError, load_secrets
from sentinel.config.settings import Settings
from sentinel.contracts.models import (
    Alert,
    Channel,
    Delivery,
    DoctorCheck,
    Event,
    Incident,
    IncidentDetail,
    IncidentReport,
    LlmTestResult,
    RunSummary,
)
from sentinel.explain.explainer import Explainer
from sentinel.explain.llm import LlmClient, LlmError, build_client
from sentinel.explain.sanitize import sanitize_incident
from sentinel.explain.templates import explain_template
from sentinel.net.http import Transport, urllib_transport
from sentinel.notify.router import Notifier
from sentinel.pipeline.run import Pipeline
from sentinel.sensor.replay import CaptureError, capture_live, read_pcap, tcpdump_argv
from sentinel.storage.db import Storage

_PRUNE_EVERY_SECONDS = 3600.0  # live capture applies the retention settings this often
OnEvent = Callable[[Event], None]
OnReport = Callable[[IncidentReport], None]


class ServiceError(Exception):
    """Any expected operational failure, with a message fit to show the user."""


@contextmanager
def _errors() -> Iterator[None]:
    try:
        yield
    except BrokenPipeError:
        raise  # the reader of our output went away (`| head`): not a service failure
    except (LlmError, CaptureError, SecretsError, OSError) as exc:
        raise ServiceError(str(exc)) from exc


def _sample_incident() -> tuple[Incident, list[Alert]]:
    mac, ip = "aa:bb:cc:dd:ee:ff", "192.0.2.10"
    alert = Alert(
        id="sample-1", ts=1.0, detector="portscan", host_mac=mac, host_ip=ip, severity=0.9,
        confidence=0.9, technique="T1046",
        evidence={"window_seconds": 10.0, "unique_dst_ports": 120.0, "failed_ratio": 0.95},
    )  # fmt: skip
    incident = Incident(
        id="sample", host_mac=mac, start_ts=1.0, end_ts=1.0, alerts=["sample-1"],
        chain=["T1046"], score=0.8,
    )  # fmt: skip
    return incident, [alert]


class SentinelService:
    def __init__(
        self,
        settings: Settings,
        secrets: Secrets,
        transport: Transport = urllib_transport,
        database: Path | None = None,
    ) -> None:
        self._settings, self._secrets, self._transport = settings, secrets, transport
        self._database = database or settings.database
        self._storage: Storage | None = None

    @property
    def storage(self) -> Storage:
        if self._storage is None:
            self._storage = Storage(self._database)
        return self._storage

    def close(self) -> None:
        if self._storage is not None:
            self._storage.close()
            self._storage = None

    def _llm(self) -> LlmClient | None:
        key = self._secrets.llm_api_key
        return build_client(
            self._settings.llm, key.get_secret_value() if key else None, self._transport
        )

    def _notifier(self) -> Notifier:
        return Notifier(self._settings.notify, self._secrets, self._transport)

    def _pipeline(
        self, on_event: OnEvent | None, on_report: OnReport | None, notify: bool
    ) -> Pipeline:
        notifier = self._notifier() if notify else None
        return Pipeline(
            self._settings, self.storage, Explainer(self._llm()), notifier,
            on_event=on_event, on_report=on_report,
        )  # fmt: skip

    def replay(
        self, path: Path, *, on_event: OnEvent | None = None, on_report: OnReport | None = None,
        notify: bool = False,
    ) -> RunSummary:  # fmt: skip
        pipeline = self._pipeline(on_event, on_report, notify)
        with _errors():
            for ts, frame in read_pcap(path):
                pipeline.ingest(ts, frame)
        return pipeline.finish()

    def watch(
        self, interface: str, *, on_event: OnEvent | None = None, on_report: OnReport | None = None,
        notify: bool = False,
    ) -> RunSummary:  # fmt: skip
        """Capture live with tcpdump (needs root) until interrupted or the capture ends."""
        cap = self._settings.capture
        pipeline = self._pipeline(on_event, on_report, notify)
        try:
            with _errors():
                last_prune = 0.0
                for ts, frame in capture_live(tcpdump_argv(interface, cap.snaplen, cap.bpf)):
                    pipeline.ingest(ts, frame)
                    if ts - last_prune > _PRUNE_EVERY_SECONDS:
                        pipeline.prune(time.time())
                        last_prune = ts
        except KeyboardInterrupt:
            pass
        return pipeline.finish()

    def incidents(self, limit: int = 20) -> list[Incident]:
        return self.storage.recent_incidents(limit)

    def incident(self, incident_id: str) -> IncidentDetail:
        incident = self.storage.get_incident(incident_id)
        if incident is None:
            raise ServiceError(f"no incident with id {incident_id!r}; see `sentinel incidents`")
        return IncidentDetail(
            incident=incident, alerts=self.storage.alerts_of_incident(incident_id)
        )

    def notify_test(self, channel: Channel) -> Delivery:
        incident, alerts = _sample_incident()
        sanitized = sanitize_incident(incident, alerts)
        return self._notifier().test(channel, sanitized, explain_template(sanitized))

    def llm_test(self) -> LlmTestResult:
        client = self._llm()
        if client is None:
            raise ServiceError("LLM is disabled: set [llm] enabled = true and model in config.toml")
        with _errors():
            models = client.models()
        incident, alerts = _sample_incident()
        explainer = Explainer(client)
        explanation = explainer.explain(sanitize_incident(incident, alerts))
        return LlmTestResult(
            models=models, explanation=explanation, fallback_reason=explainer.last_fallback_reason
        )

    def doctor(self, secrets_file: Path) -> list[DoctorCheck]:
        checks: list[DoctorCheck] = []
        try:
            load_secrets(secrets_file, {})
            checks.append(DoctorCheck(name="secrets file", ok=True, detail=str(secrets_file)))
        except SecretsError as exc:
            checks.append(DoctorCheck(name="secrets file", ok=False, detail=str(exc)))
        configured = {
            "slack": self._secrets.slack_webhook_url,
            "discord": self._secrets.discord_webhook_url,
            "telegram": self._secrets.telegram_bot_token and self._secrets.telegram_chat_id,
        }
        for name, value in configured.items():
            checks.append(
                DoctorCheck(name=f"{name} credentials", ok=True,
                            detail="set" if value else "not set (optional)")
            )  # fmt: skip
        interface = self._settings.capture.interface
        names = {name for _, name in socket.if_nameindex()}
        checks.append(
            DoctorCheck(
                name=f"interface {interface}",
                ok=interface in names,
                detail="found" if interface in names else f"not found; available: {sorted(names)}",
            )
        )
        if self._settings.llm.enabled:
            try:
                client = self._llm()
                models = client.models() if client else []
                ok = self._settings.llm.model in models
                detail = "model available" if ok else f"model not listed; server has {models}"
            except LlmError as exc:
                ok, detail = False, str(exc)
            checks.append(DoctorCheck(name="llm server", ok=ok, detail=detail))
        return checks
