"""In-process service surface used by the CLI now and by an HTTP/GUI adapter later (D-013/D-015).

Returns contract models only; formatting and printing belong to the clients.
"""

import fcntl
import os
import platform
import queue
import socket
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from importlib import resources
from importlib.metadata import version
from pathlib import Path
from typing import Any, Literal

from sentinel.config.secrets import Secrets, SecretsError, load_secrets
from sentinel.config.settings import Settings
from sentinel.contracts.models import (
    Alert,
    AnomalyRecord,
    Channel,
    Delivery,
    DoctorCheck,
    Event,
    HistoryQuery,
    Incident,
    IncidentDetail,
    IncidentReport,
    LlmTestResult,
    RunSummary,
    StatusReport,
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

_MAX_PACED_GAP_SECONDS = 1.0  # a paced replay never waits longer than this between frames
_IDLE_TICK_SECONDS = 1.0  # live mode runs the detectors at least this often
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
        self._capture_lock: int | None = None

    @property
    def database(self) -> Path:
        return self._database

    @property
    def secrets_file(self) -> Path:
        return self._settings.secrets_file

    @property
    def storage(self) -> Storage:
        if self._storage is None:
            self._storage = Storage(self._database)
        return self._storage

    def acquire_capture(self) -> None:
        """Only one live capture may feed a database: two would log every alert twice.

        Holds an advisory lock on `<database>.lock` until close() or process exit.
        """
        if self._capture_lock is not None:
            return
        self._database.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        path = self._database.with_name(self._database.name + ".lock")
        # O_NOFOLLOW: under sudo, never create or open through a link planted in the user's folder.
        try:
            fd = os.open(path, os.O_RDONLY | os.O_CREAT | os.O_NOFOLLOW, 0o644)
        except OSError as exc:
            raise ServiceError(f"cannot create the capture lock {path}: {exc}") from exc
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as exc:
            os.close(fd)
            raise ServiceError(
                f"another Sentinel is already capturing into {self._database}; "
                "stop it first (for example: pkill -f 'sentinel')"
            ) from exc
        self._capture_lock = fd

    def close(self) -> None:
        if self._capture_lock is not None:
            os.close(self._capture_lock)
            self._capture_lock = None
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
        self,
        on_event: OnEvent | None,
        on_report: OnReport | None,
        notify: bool,
        source: Literal["live", "replay"] = "live",
    ) -> Pipeline:
        notifier = self._notifier() if notify else None
        return Pipeline(
            self._settings, self.storage, Explainer(self._llm()), notifier,
            on_event=on_event, on_report=on_report, source=source,
        )  # fmt: skip

    def replay(  # noqa: PLR0913 - keyword-only options of one operation
        self, path: Path, *, on_event: OnEvent | None = None, on_report: OnReport | None = None,
        notify: bool = False, pace: float | None = None, stop: threading.Event | None = None,
    ) -> RunSummary:  # fmt: skip
        """Replay a capture. `pace` plays it at that multiple of real time (for live displays)."""
        pipeline = self._pipeline(on_event, on_report, notify, "replay")
        previous: float | None = None
        with _errors():
            for ts, frame in read_pcap(path):
                if stop is not None and stop.is_set():
                    break
                if pace and previous is not None:
                    time.sleep(min(_MAX_PACED_GAP_SECONDS, max(0.0, (ts - previous) / pace)))
                previous = ts
                pipeline.ingest(ts, frame)
        return pipeline.finish()

    def watch(  # noqa: PLR0913 - keyword-only options of one operation
        self, interface: str, *, on_event: OnEvent | None = None, on_report: OnReport | None = None,
        notify: bool = False, duration_seconds: float | None = None,
        halt: threading.Event | None = None,
    ) -> RunSummary:  # fmt: skip
        """Capture live with tcpdump until interrupted, `duration_seconds`, or the capture ends.

        Capture runs in a thread; the main loop also ticks the detectors once a second so an
        attack on a quiet link is reported without waiting for the next packet.
        """
        self.acquire_capture()
        cap = self._settings.capture
        pipeline = self._pipeline(on_event, on_report, notify)
        stop = halt if halt is not None else threading.Event()
        incoming: queue.Queue[tuple[float, bytes] | CaptureError | None] = queue.Queue()
        argv = tcpdump_argv(interface, cap.snaplen, cap.bpf)

        def pump() -> None:
            try:
                for item in capture_live(argv, duration_seconds, stop):
                    incoming.put(item)
            except CaptureError as exc:
                incoming.put(exc)
            finally:
                incoming.put(None)

        reader = threading.Thread(target=pump, daemon=True)
        reader.start()
        last_prune = 0.0
        try:
            while True:
                if stop.is_set():
                    break
                try:
                    item = incoming.get(timeout=_IDLE_TICK_SECONDS)
                except queue.Empty:
                    pipeline.tick(time.time())
                    continue
                if item is None:
                    break
                if isinstance(item, CaptureError):
                    raise ServiceError(str(item)) from item
                pipeline.ingest(*item)
                if item[0] - last_prune > _PRUNE_EVERY_SECONDS:
                    pipeline.prune(time.time())
                    last_prune = item[0]
        except KeyboardInterrupt:
            pass
        finally:
            stop.set()
            reader.join(timeout=5)
        return pipeline.finish()

    def history(self, query: HistoryQuery) -> tuple[int, list[AnomalyRecord]]:
        """The permanent anomaly history, newest first, with the number of matches."""
        return self.storage.anomalies(query)

    def history_item(self, anomaly_id: int) -> AnomalyRecord | None:
        return self.storage.anomaly(anomaly_id)

    def history_counts(self) -> dict[str, int]:
        return self.storage.anomaly_label_counts()

    def incidents(
        self,
        limit: int = 20,
        *,
        since_seconds: float | None = None,
        min_score: float = 0.0,
        include_closed: bool = False,
    ) -> list[Incident]:
        """Newest first. `since_seconds` is relative to now; closed = dismissed or resolved."""
        since = None if since_seconds is None else time.time() - since_seconds
        return self.storage.recent_incidents(
            limit, since=since, min_score=min_score, include_closed=include_closed
        )

    def resolve_incident_id(self, reference: str) -> str:
        """Accept a full id or any unambiguous prefix of one."""
        matches = self.storage.match_incident_ids(reference)
        if not matches:
            raise ServiceError(
                f"no incident matching {reference!r}; see `sentinel incidents --all`"
            )
        if len(matches) > 1:
            shown = ", ".join(matches[:5])
            raise ServiceError(f"{reference!r} is ambiguous ({len(matches)} matches): {shown}")
        return matches[0]

    def incident(self, reference: str) -> IncidentDetail:
        incident_id = self.resolve_incident_id(reference)
        incident = self.storage.get_incident(incident_id)
        assert incident is not None  # noqa: S101 - id came from the database
        return IncidentDetail(
            incident=incident, alerts=self.storage.alerts_of_incident(incident_id)
        )

    def set_incident_status(self, reference: str, status: str) -> Incident:
        """Acknowledge, dismiss or resolve an incident; recorded in the audit log."""
        incident_id = self.resolve_incident_id(reference)
        self.storage.set_incident_status(incident_id, status, actor="cli")
        updated = self.storage.get_incident(incident_id)
        assert updated is not None  # noqa: S101 - just updated
        return updated

    def status(self) -> StatusReport:
        s = self._settings
        counts = self.storage.incident_status_counts()
        newest = self.storage.recent_incidents(1, include_closed=True)
        creds = {
            "slack": self._secrets.slack_webhook_url,
            "discord": self._secrets.discord_webhook_url,
            "telegram": self._secrets.telegram_bot_token and self._secrets.telegram_chat_id,
        }
        size = self._database.stat().st_size if self._database.exists() else 0
        return StatusReport(
            database=str(self._database), database_bytes=size,
            alerts=self.storage.count_rows("alert"), flows_stored=self.storage.count_rows("flow"),
            incidents_by_status=counts, newest_incident_ts=newest[0].end_ts if newest else None,
            notify_enabled=s.notify.enabled, notify_channels=list(s.notify.channels),
            channels_with_credentials=[c for c, v in creds.items() if v],
            llm_enabled=s.llm.enabled, llm_model=s.llm.model,
        )  # fmt: skip

    def console_info(self, *, notify_armed: bool) -> dict[str, Any]:
        """Secret-free summary of how this run is set up, for the console's Health tab."""
        s, sec = self._settings, self._secrets
        creds = {
            "slack": sec.slack_webhook_url is not None,
            "discord": sec.discord_webhook_url is not None,
            "telegram": sec.telegram_bot_token is not None and sec.telegram_chat_id is not None,
        }
        ml = s.detection.ml
        return {
            "version": version("sentinel"), "python": platform.python_version(),
            "capture": {"interface": s.capture.interface, "snaplen": s.capture.snaplen},
            "detectors": {
                "windows": s.detection.windows, "cooldown_seconds": s.detection.cooldown_seconds,
                "rules": ["portscan", "bruteforce", "beaconing", "dns_tunnel"],
                "ngram_dns": ml.ngram_dns, "isolation_forest": ml.isolation_forest,
                "if_threshold": ml.if_threshold, "if_min_samples": ml.if_min_samples,
            },
            "notify": {
                "enabled": s.notify.enabled, "armed": notify_armed,
                "channels": list(s.notify.channels), "credentials": creds,
                "min_severity": s.notify.min_severity, "max_per_minute": s.notify.max_per_minute,
            },
            "llm": {"enabled": s.llm.enabled, "runtime": s.llm.runtime, "model": s.llm.model},
        }  # fmt: skip

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

    def doctor(self, secrets_file: Path, *, fix: bool = False) -> list[DoctorCheck]:
        checks: list[DoctorCheck] = []
        if fix and secrets_file.exists() and secrets_file.stat().st_mode & 0o077:
            secrets_file.chmod(0o600)
            checks.append(DoctorCheck(name="fixed", ok=True, detail=f"chmod 600 {secrets_file}"))
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
                ok=True,  # only `watch` needs it; replaying captures works without it
                detail=(
                    "found"
                    if interface in names
                    else f"not found (needed only for `watch`); available: {sorted(names)}"
                ),
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


def init_workspace(directory: Path) -> list[tuple[Path, bool]]:
    """Create config.toml and a private secrets.env if missing. Returns (path, created)."""
    templates = resources.files("sentinel.config") / "templates"
    results: list[tuple[Path, bool]] = []
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    for name, mode in (("config.toml", 0o644), ("secrets.env", 0o600)):
        target = directory / name
        created = not target.exists()
        if (
            created
        ):  # the template is not called secrets.env: that name is git-ignored and unpackaged
            target.write_text(
                (
                    templates / f"{name}.template" if name == "secrets.env" else templates / name
                ).read_text()
            )
            target.chmod(mode)
        results.append((target, created))
    return results
