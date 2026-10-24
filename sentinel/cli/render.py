"""Terminal formatting for events and reports. Every network-derived string is escaped."""

import time

from sentinel.contracts.models import (
    ArpEvent,
    DhcpEvent,
    Event,
    Flow,
    IncidentDetail,
    IncidentReport,
    MdnsEvent,
    RunSummary,
    StatusReport,
)
from sentinel.contracts.text import terminal_safe

_DNS_PORT = 53
_KILO = 1024
_KILO = 1024
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


_BADGES = {"CRITICAL": "1;97;41", "HIGH": "1;97;41", "MEDIUM": "1;30;43", "LOW": "1;30;46"}
_TEXT = {"CRITICAL": "1;31", "HIGH": "1;31", "MEDIUM": "33", "LOW": "36"}
_DIM = "2"


def badge(score: float, color: bool) -> str:
    """`[CRITICAL 1.00]`; with colour it is a solid block (white on red for CRITICAL/HIGH) so an
    alert stands out from a screen of traffic lines. Only our own fixed labels are coloured."""
    label = severity_label(score)
    text = f"[{label} {score:.2f}]"
    return f"\x1b[{_BADGES[label]}m {text} \x1b[0m" if color else text


def tint(text: str, score: float, color: bool) -> str:
    """Colour the rest of an alert line to match its severity."""
    return f"\x1b[{_TEXT[severity_label(score)]}m{text}\x1b[0m" if color else text


def dim(text: str, color: bool) -> str:
    """Grey out ordinary traffic so alerts are the brightest thing on screen."""
    return f"\x1b[{_DIM}m{text}\x1b[0m" if color else text


def format_report(report: IncidentReport, color: bool = False) -> str:
    inc, exp = report.incident, report.explanation
    sent = ", ".join(
        f"{d.channel}={d.status}" + (f" ({d.detail})" if d.status != "sent" else "")
        for d in report.deliveries
    )
    lines = [
        f"INCIDENT {badge(inc.score, color)} {tint(inc.id, inc.score, color)}",
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
    if s.truncated_payloads:
        text += f" truncated_payloads={s.truncated_payloads}"
    if s.state_capped:
        text += f" state_capped={s.state_capped}"
    if s.llm_used or s.llm_rejected or s.llm_errors:
        text += f" llm_used={s.llm_used} llm_rejected={s.llm_rejected} llm_errors={s.llm_errors}"
    return text


def matches(event: Event, host: str | None, port: int | None, proto: str | None) -> bool:
    """Traffic-view filter. proto: tcp/udp/icmp/other/dns/arp/dhcp/mdns."""
    if isinstance(event, Flow):
        kind = (
            {event.proto, "dns"}
            if event.dns_query or _DNS_PORT in (event.src_port, event.dst_port)
            else {event.proto}
        )
        ips, ports = {event.src_ip, event.dst_ip}, {event.src_port, event.dst_port}
    elif isinstance(event, ArpEvent):
        kind, ips, ports = {"arp"}, {event.sender_ip, event.target_ip}, set()
    elif isinstance(event, DhcpEvent):
        kind, ips, ports = {"dhcp"}, {event.src_ip}, {67, 68}
    else:
        kind, ips, ports = {"mdns"}, {event.src_ip}, {5353}
    return (
        (host is None or host in ips)
        and (port is None or port in ports)
        and (proto is None or proto in kind)
    )


def format_detail(detail: IncidentDetail, color: bool = False) -> str:
    inc = detail.incident
    lines = [
        f"{inc.id}  {badge(inc.score, color)}  status={inc.status}",
        f"  device: {inc.host_mac}   chain: {' > '.join(inc.chain)}",
        f"  {terminal_safe(inc.summary or '(no summary)')}",
        "  timeline:",
    ]
    for a in detail.alerts:
        evidence = ", ".join(f"{k}={v:g}" for k, v in sorted(a.evidence.items()))
        target = f" -> {a.target_ip}" if a.target_ip else ""
        lines.append(
            f"    {_clock(a.ts)}  {a.detector:<10} {a.technique:<10} sev={a.severity:.2f} "
            f"conf={a.confidence:.2f} from {a.host_ip}{target}"
        )
        lines.append(f"      {terminal_safe(evidence, 300)}")
    return "\n".join(lines)


def format_brief(report: IncidentReport, color: bool = False) -> str:
    inc = report.incident
    sent = " ".join(f"{d.channel}={d.status}" for d in report.deliveries)
    rest = f"{inc.id}  {terminal_safe(report.explanation.headline)}  ({' > '.join(inc.chain)})"
    rest += f"  {sent}" if sent else ""
    return f"{badge(inc.score, color)} {tint(rest, inc.score, color)}"


def _size(n: float) -> str:
    for unit in ("B", "KB", "MB"):
        if n < _KILO:
            return f"{n:.0f} {unit}" if unit != "MB" else f"{n:.1f} {unit}"
        n /= _KILO
    return f"{n:.1f} GB"


def format_status(st: StatusReport) -> str:
    total = sum(st.incidents_by_status.values())
    by_status = ", ".join(f"{n} {k}" for k, n in sorted(st.incidents_by_status.items())) or "none"
    newest = _clock(st.newest_incident_ts) if st.newest_incident_ts else "never"
    if st.notify_enabled:
        missing = [c for c in st.notify_channels if c not in st.channels_with_credentials]
        notify = f"on ({', '.join(st.notify_channels) or 'no channels listed'})"
        notify += f"; missing credentials: {', '.join(missing)}" if missing else ""
    else:
        notify = "off"
    llm = f"on ({st.llm_model or 'no model set'})" if st.llm_enabled else "off (templates)"
    return "\n".join(
        [
            f"database   {st.database} ({_size(st.database_bytes)}), {st.alerts} alerts, "
            f"{st.flows_stored} flows stored",
            f"incidents  {total} total: {by_status}; newest at {newest}",
            f"notify     {notify}",
            f"llm        {llm}",
        ]
    )
