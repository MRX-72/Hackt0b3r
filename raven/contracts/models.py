"""Shared data shapes. Every other module imports these; none defines its own copy."""

import ipaddress
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field, PositiveInt

MAC_PATTERN = r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$"
Mac = Annotated[str, Field(pattern=MAC_PATTERN)]
Unit = Annotated[float, Field(ge=0.0, le=1.0)]
Port = Annotated[int, Field(ge=0, le=65535)]


def _canonical_ip(value: str) -> str:
    return str(ipaddress.ip_address(value))


IpAddr = Annotated[str, AfterValidator(_canonical_ip)]
Proto = Literal["tcp", "udp", "icmp", "other"]
DhcpMsgType = Literal["discover", "offer", "request", "decline", "ack", "nak", "release", "inform"]


class _Frozen(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")


class Flow(_Frozen):
    """One flow record from the sensor. dns_query is network-derived and hostile."""

    ts: float
    src_ip: IpAddr
    dst_ip: IpAddr
    src_mac: Mac
    dst_mac: Mac
    proto: Proto
    src_port: Port | None = None
    dst_port: Port | None = None
    bytes: int = Field(ge=0)
    packets: int = Field(ge=0)
    tcp_flags: str | None = None
    dns_query: str | None = None
    dns_qtype: str | None = None


class Alert(_Frozen):
    """evidence holds numeric features only: no network-derived strings."""

    id: str
    ts: float
    detector: str
    host_mac: Mac
    host_ip: IpAddr
    severity: Unit
    confidence: Unit
    evidence: dict[str, float]
    technique: str
    target_ip: IpAddr | None = None  # the main victim/destination, when there is one


class Incident(_Frozen):
    id: str
    host_mac: Mac
    start_ts: float
    end_ts: float
    alerts: list[str]
    chain: list[str]
    score: float
    summary: str | None = None
    status: Literal[
        "open", "correlated", "explained", "notified", "acknowledged", "dismissed", "resolved"
    ] = "open"


class AuditEntry(_Frozen):
    id: int
    ts: float
    actor: str
    action: str
    target: str
    detail: dict[str, Any]


class ArpEvent(_Frozen):
    ts: float
    op: Literal["request", "reply"]
    eth_src_mac: Mac
    sender_mac: Mac
    sender_ip: IpAddr
    target_mac: Mac
    target_ip: IpAddr


class DhcpEvent(_Frozen):
    """hostname is network-derived and hostile."""

    ts: float
    msg_type: DhcpMsgType
    src_mac: Mac
    src_ip: IpAddr
    client_mac: Mac
    offered_ip: IpAddr | None = None
    hostname: str | None = None


class MdnsEvent(_Frozen):
    """name is network-derived and hostile."""

    ts: float
    src_mac: Mac
    src_ip: IpAddr
    name: str


Event = Flow | ArpEvent | DhcpEvent | MdnsEvent


class WindowFeatures(_Frozen):
    """Numeric per-host features for one window (spec Part 3 s6). Numeric only by construction."""

    host_mac: Mac
    host_ip: IpAddr
    window_seconds: int
    end_ts: float
    conns_started: int
    attempts: int
    failed_ratio: float
    top_target_ip: IpAddr | None
    unique_dst_ips: int
    unique_dst_ports: int
    novel_dsts: int
    bytes_out: int
    bytes_in: int
    dns_queries: int
    dns_unique_subdomains: int
    dns_max_subdomains_per_parent: int
    dns_mean_entropy: float
    dns_max_entropy: float
    dns_mean_length: float
    dns_txt_null_share: float
    dns_mean_surprisal: float = 0.0  # character-trigram bits/char, see raven.ml.ngram
    share_web: float
    share_ssh: float
    share_dns: float
    share_other: float
    hour_of_day: int


class DestinationTiming(_Frozen):
    """Connection-start regularity toward one destination, for beacon detection."""

    dst_ip: IpAddr
    dst_port: Port
    count: int
    mean_interval_seconds: float
    interval_cv: float
    mean_bytes: float
    seconds_since_last: float
    completed_ratio: float  # share of the connection starts that were accepted
    popularity: int  # how many hosts connect to this destination


ActionId = Literal[
    "investigate_device", "disconnect_device", "reset_credentials", "review_dns", "monitor"
]


class SanitizedStep(_Frozen):
    detector: str
    technique: str
    technique_name: str
    ts: float
    severity: Unit
    confidence: Unit
    evidence: dict[str, float]
    target_ip: IpAddr | None = None


class SanitizedIncident(_Frozen):
    """The only incident shape LLMs, notifiers and UIs may receive. See explain.sanitize."""

    incident_id: str
    host_ip: IpAddr
    host_mac: Mac
    severity: Unit
    confidence: Unit
    score: float
    start_ts: float
    end_ts: float
    steps: list[SanitizedStep]


class Explanation(_Frozen):
    headline: str
    what_happened: str
    likely_cause: str
    action_id: ActionId
    suggested_action: str
    confidence_note: str
    source: Literal["template", "llm"]


Channel = Literal["slack", "discord", "telegram"]


class Delivery(_Frozen):
    """Outcome of one notification attempt. detail never contains URLs or tokens."""

    channel: Channel
    status: Literal["sent", "failed", "skipped"]
    detail: str


class IncidentReport(_Frozen):
    """An incident with its explanation and notification outcomes (what clients display)."""

    incident: Incident
    explanation: Explanation
    deliveries: list[Delivery]


class RunSummary(_Frozen):
    frames: int
    flows: int
    alerts: int
    incidents: int
    parse_errors: int
    payload_errors: int
    truncated_payloads: int  # DNS/DHCP/mDNS payloads the snaplen cut short
    late_dropped: int
    state_capped: int  # times a flood hit a memory bound (counts stay far above thresholds)
    llm_used: int
    llm_rejected: int
    llm_errors: int


class AnomalyRecord(_Frozen):
    """One row of the permanent anomaly history. `id` is None until it is stored."""

    id: int | None = None
    ts: float  # capture time of the alert
    logged_at: float  # wall-clock time it was written
    source: Literal["live", "replay"]
    detector: str
    technique: str
    severity: Unit
    confidence: Unit
    label: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    score: float
    host_mac: Mac
    host_ip: IpAddr
    target_ip: IpAddr | None = None
    headline: str
    what_happened: str
    likely_cause: str
    action: str
    chain: list[str]
    incident_id: str
    evidence: dict[str, float]


class HistoryQuery(_Frozen):
    """Filters for the permanent anomaly history. Validated, so callers can pass user input."""

    label: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] | None = None
    source: Literal["live", "replay"] | None = None
    text: str | None = Field(default=None, max_length=100)
    since: float | None = None
    until: float | None = None
    limit: int = Field(default=100, ge=1, le=500)
    offset: int = Field(default=0, ge=0)


class HistoryDelete(_Frozen):
    """Which history entries to delete (by id). Validated: it comes straight from the web page."""

    ids: list[PositiveInt] = Field(min_length=1, max_length=500)


class DeliveryRecord(_Frozen):
    """One stored notification attempt, with the incident it was about (for the console)."""

    id: int
    ts: float
    channel: Channel
    status: Literal["sent", "failed", "skipped"]
    error: str | None
    incident_id: str
    headline: str | None
    label: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] | None


class DeviceRecord(_Frozen):
    """A device (MAC) the capture has seen, with its traffic totals and alert summary."""

    mac: Mac
    ips: list[str]
    name: str | None  # chosen by the admin; never derived from network data
    first_seen: float
    last_seen: float
    packets: int
    bytes_out: int
    bytes_in: int
    alerts: int
    worst_label: Literal["CRITICAL", "HIGH", "MEDIUM", "LOW"] | None
    last_alert_ts: float | None


class DeviceName(_Frozen):
    """Admin label for a device; empty clears it. Comes straight from the web page."""

    mac: Mac
    name: str = Field(max_length=40)


class ChannelTest(_Frozen):
    channel: Channel


class IncidentDetail(_Frozen):
    incident: Incident
    alerts: list[Alert]


class StatusReport(_Frozen):
    database: str
    database_bytes: int
    alerts: int
    flows_stored: int
    incidents_by_status: dict[str, int]
    newest_incident_ts: float | None
    notify_enabled: bool
    notify_channels: list[str]
    channels_with_credentials: list[str]
    llm_enabled: bool
    llm_model: str


class DoctorCheck(_Frozen):
    name: str
    ok: bool
    detail: str


class LlmTestResult(_Frozen):
    models: list[str]
    explanation: Explanation
    fallback_reason: str | None
