"""Shared data shapes. Every other module imports these; none defines its own copy."""

import ipaddress
from typing import Annotated, Any, Literal

from pydantic import AfterValidator, BaseModel, ConfigDict, Field

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
