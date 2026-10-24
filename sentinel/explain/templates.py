"""Deterministic explanation text. Used when the LLM is off, fails, or is rejected."""

from sentinel.contracts.models import ActionId, Explanation, SanitizedIncident, SanitizedStep

# Fixed action catalogue: LLM output may only pick an id from here; the text is ours.
ACTIONS: dict[ActionId, str] = {
    "investigate_device": "Check what this device is running and whether it should be doing this.",
    "disconnect_device": "If you do not recognise this activity, disconnect the device.",
    "reset_credentials": "Check the targeted service's logs and change its passwords if in doubt.",
    "review_dns": "Review which applications on this device make DNS requests and inspect them.",
    "monitor": "Keep watching this device; no immediate action is needed if it is expected.",
}

_DETECTOR_TEXT: dict[str, tuple[str, str, str, ActionId]] = {
    # detector -> (headline, what happened, likely cause, action)
    "portscan": (
        "Device is probing many network ports",
        "{host} tried many different ports or hosts in a short time and most attempts failed.",
        "This may be a port scan looking for open services, or a misbehaving program.",
        "disconnect_device",
    ),
    "bruteforce": (
        "Repeated login attempts against a service",
        "{host} made many connections to the same login service (port {dst_port}).",
        "This looks like someone guessing passwords, or a script with a wrong password.",
        "reset_credentials",
    ),
    "beaconing": (
        "Device contacts one server at fixed intervals",
        "{host} connected to the same server about every {mean_interval_seconds} seconds.",
        "Regular small connections can be malware checking in, or a legitimate sync tool.",
        "investigate_device",
    ),
    "dns_tunnel": (
        "Unusual DNS requests that may hide data",
        "{host} sent many long, random-looking DNS names to one domain.",
        "This may be data being smuggled through DNS, though some services also look like this.",
        "review_dns",
    ),
}
_DEFAULT: tuple[str, str, str, ActionId] = (
    "Unusual network activity",
    "{host} did something unusual on the network.",
    "The cause is not clear from the network data alone.",
    "investigate_device",
)


def _number(value: float) -> str:
    return str(int(value)) if float(value).is_integer() else f"{value:.1f}"


def _strongest(incident: SanitizedIncident) -> SanitizedStep:
    return max(incident.steps, key=lambda s: s.severity * s.confidence)


def explain_template(incident: SanitizedIncident) -> Explanation:
    step = _strongest(incident)
    headline, what, cause, action = _DETECTOR_TEXT.get(step.detector, _DEFAULT)
    values = {k: _number(v) for k, v in step.evidence.items()} | {"host": str(incident.host_ip)}
    chain = len({s.technique for s in incident.steps})
    note = (
        f"Confidence {round(incident.confidence * 100)}%. "
        + (f"{chain} related behaviours were seen, which raises concern. " if chain > 1 else "")
        + "This is an automatic guess: please verify before acting."
    )
    return Explanation(
        headline=headline, what_happened=what.format_map(_Defaulting(values)), likely_cause=cause,
        action_id=action, suggested_action=ACTIONS[action], confidence_note=note, source="template",
    )  # fmt: skip


class _Defaulting(dict[str, str]):
    def __missing__(self, key: str) -> str:
        return "several"
