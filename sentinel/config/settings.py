"""Validated settings loaded from config.toml. Holds no secrets (see secrets.py)."""

import ipaddress
import os
import pwd
import tomllib
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from sentinel.contracts.models import Channel

# Window state is kept in fixed time buckets; every configured window is a whole number of them.
BUCKET_SECONDS = 10


def sentinel_home() -> Path:
    """Where the database, config.toml and secrets.env live unless told otherwise.

    $SENTINEL_HOME, else ~/.sentinel. Under `sudo` that is the invoking user's folder, so a root
    capture and a normal-user `sentinel ui` share one history.
    """
    if env := os.environ.get("SENTINEL_HOME"):
        return Path(env).expanduser()
    if os.geteuid() == 0 and (user := os.environ.get("SUDO_USER")):
        try:
            return Path(pwd.getpwnam(user).pw_dir) / ".sentinel"
        except KeyError:
            pass
    return Path.home() / ".sentinel"


def _trusted(path: Path) -> bool:
    """As root (sudo), only use a config that root or the invoking user owns and nobody else can
    write: otherwise a config.toml planted in the current directory could point `database` at
    any path root can write."""
    if os.geteuid() != 0:
        return True
    try:
        info = path.stat()
        sudo_uid = int(os.environ.get("SUDO_UID", "0"))
    except (OSError, ValueError):
        return False
    return info.st_uid in (0, sudo_uid) and not info.st_mode & 0o022


def find_config(explicit: Path | None = None) -> Path | None:
    """--config, $SENTINEL_CONFIG, ./config.toml, <home>/config.toml; None = built-in defaults."""
    if explicit is not None:
        return explicit
    candidates = [Path("config.toml"), sentinel_home() / "config.toml"]
    if env := os.environ.get("SENTINEL_CONFIG"):
        candidates.insert(0, Path(env).expanduser())
    return next((c for c in candidates if c.is_file() and _trusted(c)), None)


class _Section(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MlSettings(_Section):
    """The two statistical detectors. Both are off-switchable; see docs/ABLATION.md for why."""

    # Character-trigram surprisal of DNS names: a fifth signal for the DNS tunnelling rule.
    ngram_dns: bool = True
    dns_min_surprisal: float = 4.8  # bits/char; ordinary names ~2.5-3.5, random names 5.4+
    # Isolation Forest over the 10 s per-device behaviour vectors of recent traffic.
    isolation_forest: bool = True
    # Modest on purpose: the extremity check in detect/behavior.py is the main false-positive guard.
    if_threshold: float = Field(0.6, gt=0.5, lt=1.0)
    if_min_samples: int = Field(200, ge=20)  # active device-windows to learn from first (~35 min)
    if_history: int = Field(2000, ge=50)  # recent normal vectors the forest is refitted on
    if_refit_every: int = Field(120, ge=1)  # new normal vectors between refits
    if_trees: int = Field(50, ge=10, le=500)
    if_sample_size: int = Field(128, ge=16, le=1024)
    if_seed: int = 0


class DetectionSettings(_Section):
    # 10 s catches fast attacks; 5 min and 1 h catch low-and-slow ones a short window misses.
    windows: list[int] = [10, 300, 3600]
    # After an alert, the same detector stays quiet for this host this long (alert fatigue).
    cooldown_seconds: int = 300
    # Alerts on one host closer together than this join one incident.
    incident_gap_seconds: int = 600
    # Port/host scans: distinct targets in a window, mostly failing. Slow scans (a few probes a
    # minute) only reach the 5 min and 1 h thresholds.
    scan_min_unique_ports: dict[int, int] = {10: 20, 300: 15, 3600: 60}
    scan_min_unique_hosts: dict[int, int] = {10: 20, 300: 15, 3600: 50}
    scan_min_failed_ratio: float = 0.6
    # Brute force: many connections to one auth service, mostly completing (each guess is a login).
    auth_ports: list[int] = [21, 22, 23, 445, 2222, 3389, 5900]  # 2222: common alternate SSH
    brute_min_attempts: dict[int, int] = {10: 8, 300: 20, 3600: 60}
    brute_min_completed_ratio: float = 0.3
    # Beaconing: this many connection starts to one destination with this little timing jitter.
    beacon_min_events: int = 10
    beacon_max_interval_cv: float = 0.15
    beacon_min_interval_seconds: float = 1.0
    # A TLS check-in is already ~5 KB of handshake; this only excludes bulk transfers.
    beacon_max_mean_bytes: float = 20_000.0
    # A beacon that missed this many expected check-ins is over; stop alerting on it.
    beacon_active_intervals: float = 3.0
    beacon_ignore_ports: list[int] = [53, 123]  # DNS and NTP are periodic by design
    # Mail clients, chat apps and update checkers beacon too. A destination that this many
    # different hosts connect to is a shared service, not one machine's C2.
    beacon_popular_hosts: int = 3
    # Beaconing means repeated *accepted* sessions; a retry loop against a dead port is not it.
    beacon_min_completed_ratio: float = 0.5
    beacon_allow_destinations: list[str] = []  # known-good servers (IPs or CIDRs)
    # Sources that are never alerted on (IPs or CIDRs), e.g. your own vulnerability scanner.
    trusted_ips: list[str] = []
    dns_popular_hosts: int = 3  # same idea for a domain looked up by this many hosts
    dns_ignore_domains: list[str] = []  # parent domains such as "example.net"
    # DNS tunnelling needs two independent signals among the four below.
    dns_min_queries: int = 10
    dns_min_entropy: float = 3.5  # Shannon bits/char of the subdomain part
    dns_min_mean_length: float = 40.0
    dns_min_unique_subdomains: int = 20  # under one parent domain
    dns_min_txt_null_share: float = 0.3
    ml: MlSettings = Field(default_factory=MlSettings)

    @field_validator("trusted_ips", "beacon_allow_destinations")
    @classmethod
    def _valid_networks(cls, v: list[str]) -> list[str]:
        for item in v:
            ipaddress.ip_network(item, strict=False)  # raises ValueError with a clear message
        return v

    @field_validator("windows")
    @classmethod
    def _windows_are_whole_buckets(cls, v: list[int]) -> list[int]:
        if not v or any(w <= 0 or w % BUCKET_SECONDS for w in v):
            raise ValueError(f"windows must be positive multiples of {BUCKET_SECONDS}")
        return sorted(set(v))

    @model_validator(mode="after")
    def _every_window_has_thresholds(self) -> "DetectionSettings":
        tables = {
            "scan_min_unique_ports": self.scan_min_unique_ports,
            "scan_min_unique_hosts": self.scan_min_unique_hosts,
            "brute_min_attempts": self.brute_min_attempts,
        }
        for name, table in tables.items():
            if missing := sorted(set(self.windows) - set(table)):
                raise ValueError(f"{name} has no threshold for window(s) {missing}")
        return self


class NotifySettings(_Section):
    enabled: bool = False
    channels: list[Channel] = []
    min_severity: float = Field(0.6, ge=0.0, le=1.0)
    retries: int = Field(2, ge=0, le=5)
    timeout_seconds: float = 10.0
    # After this many consecutive failures a channel is skipped until the cool-off passes.
    breaker_failures: int = 3
    breaker_cooloff_seconds: float = 300.0
    # Never more than this many messages per channel per minute.
    max_per_minute: int = 10
    link_base_url: str | None = None


class LlmSettings(_Section):
    enabled: bool = False
    runtime: Literal["ollama", "openai"] = "ollama"  # openai = any OpenAI-compatible server
    base_url: str = "http://127.0.0.1:11434"
    model: str = ""
    timeout_seconds: float = 60.0
    temperature: float = 0.2


class CliSettings(_Section):
    show_traffic: bool = False


class CaptureSettings(_Section):
    interface: str = "bridge100"  # ASSUMED Internet Sharing bridge name; check with ifconfig
    # Must cover a 255-byte DNS name (about 340 bytes of frame) or tunnels are truncated (D-011).
    snaplen: int = Field(384, ge=96, le=65535)
    bpf: str = ""


class StorageSettings(_Section):
    # Detection works in memory; stored flows only serve later forensics and cost disk space.
    store_flows: bool = False
    flow_retention_days: int = Field(1, ge=1)
    alert_retention_days: int = Field(30, ge=1)


class Settings(_Section):
    database: Path = Field(default_factory=lambda: sentinel_home() / "sentinel.db")
    secrets_file: Path = Field(default_factory=lambda: sentinel_home() / "secrets.env")
    gateway_ips: list[str] = []
    storage: StorageSettings = Field(default_factory=StorageSettings)
    capture: CaptureSettings = Field(default_factory=CaptureSettings)
    detection: DetectionSettings = Field(default_factory=DetectionSettings)
    notify: NotifySettings = Field(default_factory=NotifySettings)
    llm: LlmSettings = Field(default_factory=LlmSettings)
    cli: CliSettings = Field(default_factory=CliSettings)


def load_settings(path: Path | None) -> Settings:
    """Defaults when no file is given. Unknown keys and bad values fail loudly."""
    if path is None:
        return Settings()
    data = tomllib.loads(path.read_text())
    for key in ("database", "secrets_file"):  # relative paths mean "next to this file", not the cwd
        if isinstance(data.get(key), str):
            data[key] = str(path.resolve().parent / Path(data[key]).expanduser())
    return Settings.model_validate(data)
