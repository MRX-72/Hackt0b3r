"""Deterministic explanation text. Used when the LLM is off, fails, or is rejected."""

from collections.abc import Callable

from sentinel.contracts.models import ActionId, Explanation, SanitizedIncident, SanitizedStep

# Fixed action catalogue: LLM output may only pick an id from here; the text is ours.
ACTIONS: dict[ActionId, str] = {
    "investigate_device": "Check what this device is running and whether it should be doing this.",
    "disconnect_device": "If you do not recognise this activity, disconnect the device.",
    "reset_credentials": "Check the targeted service's logs and change its passwords if in doubt.",
    "review_dns": "Review which applications on this device make DNS requests and inspect them.",
    "monitor": "Keep watching this device; no immediate action is needed if it is expected.",
}

_WINDOW_LABELS = {10: "10 seconds", 300: "5 minutes", 3600: "1 hour"}
_PORT_NAMES = {21: "FTP", 22: "SSH", 23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC"}

# (headline, what happened, likely cause, action)
Text = tuple[str, str, str, ActionId]


def _n(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:.1f}"


def _within(step: SanitizedStep) -> str:
    seconds = int(step.evidence.get("window_seconds", 0))
    return f" within {_WINDOW_LABELS.get(seconds, f'{seconds} seconds')}" if seconds else ""


def _portscan(host: str, step: SanitizedStep) -> Text:
    e = step.evidence
    hosts = int(e.get("unique_dst_ips", 1))
    where = f"on {step.target_ip}" if step.target_ip and hosts <= 1 else f"across {hosts} hosts"
    failed = round(e.get("failed_ratio", 0) * 100)
    return (
        "Device is probing many network ports",
        f"{host} tried {_n(e.get('unique_dst_ports', 0))} different ports {where}"
        f"{_within(step)}, and {failed}% of the attempts failed.",
        "This may be a port scan looking for open services, or a misbehaving program.",
        "disconnect_device",
    )


def _bruteforce(host: str, step: SanitizedStep) -> Text:
    e = step.evidence
    port = int(e.get("dst_port", 0))
    service = f"{_PORT_NAMES[port]} (port {port})" if port in _PORT_NAMES else f"port {port}"
    target = f" on {step.target_ip}" if step.target_ip else ""
    return (
        "Repeated login attempts against a service",
        f"{host} opened {_n(e.get('attempts', 0))} connections to {service}{target}"
        f"{_within(step)}.",
        "This looks like someone guessing passwords, or a script with a wrong password.",
        "reset_credentials",
    )


def _beaconing(host: str, step: SanitizedStep) -> Text:
    e = step.evidence
    target = step.target_ip or "the same server"
    return (
        "Device contacts one server at fixed intervals",
        f"{host} connected to {target} {_n(e.get('count', 0))} times, about every "
        f"{_n(e.get('mean_interval_seconds', 0))} seconds, with very little variation.",
        "Regular small connections can be malware checking in, or a legitimate sync tool.",
        "investigate_device",
    )


def _dns_tunnel(host: str, step: SanitizedStep) -> Text:
    e = step.evidence
    return (
        "Unusual DNS requests that may hide data",
        f"{host} sent {_n(e.get('dns_queries', 0))} DNS requests{_within(step)} with long, "
        f"random-looking names (about {_n(e.get('dns_mean_length', 0))} characters on average).",
        "This may be data being smuggled through DNS, though some services also look like this.",
        "review_dns",
    )


_UNUSUAL = {
    "bytes_out": "an unusually large amount of data sent out",
    "bytes_in": "an unusually large amount of data received",
    "conns_started": "an unusual number of new connections",
    "attempts": "an unusual number of connection attempts",
    "failed_ratio": "an unusual share of failed connections",
    "unique_dst_ips": "contact with an unusual number of different hosts",
    "unique_dst_ports": "contact with an unusual number of different ports",
    "novel_dsts": "contact with many hosts it had not used before",
    "dns_queries": "an unusual number of DNS requests",
}


def _behavior(host: str, step: SanitizedStep) -> Text:
    e = step.evidence
    ranked = sorted(
        ((v, k.removeprefix("excess_")) for k, v in e.items() if k.startswith("excess_"))
    )
    top = ranked[-1][1] if ranked else ""
    what = _UNUSUAL.get(top, "an unusual mix of traffic")
    value = e.get(f"value_{top}")
    detail = f" ({_n(value)})" if value is not None and top != "failed_ratio" else ""
    return (
        "Traffic unlike this network's usual pattern",
        f"{host} showed {what}{detail}{_within(step)}, compared with what this network normally "
        "does. This comes from a statistical check, not from a known attack pattern.",
        "Unusual does not mean malicious: a backup, an update or a new app can cause this.",
        "investigate_device",
    )


_BUILDERS: dict[str, Callable[[str, SanitizedStep], Text]] = {
    "portscan": _portscan,
    "bruteforce": _bruteforce,
    "beaconing": _beaconing,
    "dns_tunnel": _dns_tunnel,
    "behavior": _behavior,
}


def _generic(host: str, step: SanitizedStep) -> Text:
    return (
        "Unusual network activity",
        f"{host} did something unusual on the network ({step.technique_name}).",
        "The cause is not clear from the network data alone.",
        "investigate_device",
    )


_EARLIER = {
    "portscan": "scanned ports",
    "bruteforce": "tried to guess logins",
    "beaconing": "contacted a server at fixed intervals",
    "dns_tunnel": "sent suspicious DNS lookups",
    "behavior": "behaved unusually",
}


def _earlier_stages(incident: SanitizedIncident, latest: SanitizedStep) -> str:
    """One sentence naming what the device did before the newest step (empty if nothing)."""
    seen = dict.fromkeys(
        _EARLIER.get(s.detector, "did something unusual")
        for s in incident.steps
        if s.detector != latest.detector
    )
    return f" Earlier this device also {', then '.join(seen)}." if seen else ""


def explain_template(incident: SanitizedIncident) -> Explanation:
    """Describe the newest step (steps are in time order) and name the earlier ones."""
    step = incident.steps[-1]
    headline, what, cause, action = _BUILDERS.get(step.detector, _generic)(
        str(incident.host_ip), step
    )
    what += _earlier_stages(incident, step)
    related = len({s.technique for s in incident.steps})
    note = (
        f"Confidence {round(incident.confidence * 100)}%. "
        + (f"{related} related behaviours were seen, which raises concern. " if related > 1 else "")
        + "This is an automatic guess: please verify before acting."
    )
    return Explanation(
        headline=headline, what_happened=what, likely_cause=cause, action_id=action,
        suggested_action=ACTIONS[action], confidence_note=note, source="template",
    )  # fmt: skip
