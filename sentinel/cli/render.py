"""Terminal formatting for events and reports. Every network-derived string is escaped."""

import time

from sentinel.contracts.models import (
    ArpEvent,
    DhcpEvent,
    Event,
    Flow,
    IncidentReport,
    MdnsEvent,
    RunSummary,
)
from sentinel.contracts.text import terminal_safe

_SEVERITY_FLOORS = ((0.85, "CRITICAL"), (0.7, "HIGH"), (0.5, "MEDIUM"), (0.0, "LOW"))


def _clock(ts: float) -> str:
    return time.strftime("%H:%M:%S", time.localtime(ts)) + f".{int(ts % 1 * 1000):03d}"


def _endpoint(ip: str, port: int | None) -> str:
    return f"{ip}:{port}" if port is not None else ip


def format_event(event: Event) -> str:
    """One tshark-like line per event."""
    t = _clock(event.ts)
    if isinstance(event, Flow):
        line = (
            f"{t} {_endpoint(event.src_ip, event.src_port)} -> "
            f"{_endpoint(event.dst_ip, event.dst_port)} {event.proto} {event.tcp_flags or '-'} "
            f"{event.bytes}B"
        )
        if event.dns_query:
            line += f"  dns? {terminal_safe(event.dns_query)} {event.dns_qtype}"
        return line
    if isinstance(event, ArpEvent):
        what = "who-has" if event.op == "request" else "is-at"
        return f"{t} ARP {what} {event.target_ip} {event.sender_ip} ({event.sender_mac})"
    if isinstance(event, DhcpEvent):
        name = f" host={terminal_safe(event.hostname)}" if event.hostname else ""
        offer = f" offer={event.offered_ip}" if event.offered_ip else ""
        return (
            f"{t} DHCP {event.msg_type} from {event.src_ip} client={event.client_mac}{offer}{name}"
        )
    assert isinstance(event, MdnsEvent)  # noqa: S101 - Event is a closed union
    return f"{t} mDNS {event.src_ip} announces {terminal_safe(event.name)}"


def severity_label(score: float) -> str:
    return next(label for floor, label in _SEVERITY_FLOORS if score >= floor)


def format_report(report: IncidentReport) -> str:
    inc, exp = report.incident, report.explanation
    sent = ", ".join(
        f"{d.channel}={d.status}" + (f" ({d.detail})" if d.status != "sent" else "")
        for d in report.deliveries
    )
    lines = [
        f"INCIDENT [{severity_label(inc.score)} {inc.score:.2f}] {inc.id}",
        f"  {terminal_safe(exp.headline)}",
        f"  chain: {' > '.join(inc.chain)}   ({exp.source} text)",
        f"  what:  {terminal_safe(exp.what_happened, 400)}",
        f"  cause: {terminal_safe(exp.likely_cause, 300)}",
        f"  do:    {terminal_safe(exp.suggested_action, 300)}",
        f"  note:  {terminal_safe(exp.confidence_note, 300)}",
    ]
    if sent:
        lines.append(f"  notify: {sent}")
    return "\n".join(lines)


def format_summary(s: RunSummary) -> str:
    text = (
        f"frames={s.frames} flows={s.flows} alerts={s.alerts} incidents={s.incidents} "
        f"parse_errors={s.parse_errors} payload_errors={s.payload_errors} "
        f"late_dropped={s.late_dropped}"
    )
    if s.llm_used or s.llm_rejected or s.llm_errors:
        text += f" llm_used={s.llm_used} llm_rejected={s.llm_rejected} llm_errors={s.llm_errors}"
    return text
