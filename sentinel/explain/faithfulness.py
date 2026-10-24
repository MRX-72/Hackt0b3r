"""Checks on LLM-written text before it can reach a notification or UI (spec Part 5 s7)."""

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from sentinel.contracts.models import SanitizedIncident

_IPV4 = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
_MAC = re.compile(r"\b(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}\b")
_TECHNIQUE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b")
_NUMBER = re.compile(r"\d+(?:\.\d+)?")
_FORBIDDEN = re.compile(r"[<>\[\]`@|]|https?:|www\.|[\x00-\x08\x0b-\x1f\x7f]", re.IGNORECASE)
# Rounding slack when comparing a number in the text to the evidence.
_ABS_TOLERANCE = 0.06
_REL_TOLERANCE = 0.01


class LlmOutput(BaseModel):
    """The JSON the model must produce. The action text itself comes from our catalogue."""

    model_config = ConfigDict(extra="forbid")

    headline: str = Field(max_length=100)
    what_happened: str = Field(max_length=400)
    likely_cause: str = Field(max_length=300)
    action_id: Literal[
        "investigate_device", "disconnect_device", "reset_credentials", "review_dns", "monitor"
    ]
    confidence_note: str = Field(max_length=300)


def _allowed_numbers(incident: SanitizedIncident) -> list[float]:
    base = [float(len(incident.steps)), incident.severity, incident.confidence, incident.score]
    base += [
        v
        for step in incident.steps
        for v in (step.severity, step.confidence, *step.evidence.values())
    ]
    out = list(base)
    for v in base:
        out += [v * 100, v / 60, v / 3600]
    return out


def _close(x: float, allowed: list[float]) -> bool:
    return any(abs(x - a) <= max(_ABS_TOLERANCE, _REL_TOLERANCE * abs(a)) for a in allowed)


def verify(out: LlmOutput, incident: SanitizedIncident) -> str | None:
    """Return None if the text is faithful to the incident, else the reason it is not."""
    text = " ".join([out.headline, out.what_happened, out.likely_cause, out.confidence_note])
    if _FORBIDDEN.search(text):
        return "markup, link, mention or control character"
    known_ips = {str(incident.host_ip)} | {str(s.target_ip) for s in incident.steps if s.target_ip}
    if any(ip not in known_ips for ip in _IPV4.findall(text)):
        return "unknown IP address"
    if any(m.lower() != incident.host_mac for m in _MAC.findall(text)):
        return "unknown MAC address"
    known = {s.technique for s in incident.steps}
    if any(t not in known for t in _TECHNIQUE.findall(text)):
        return "unknown ATT&CK technique"
    stripped = _TECHNIQUE.sub(" ", _MAC.sub(" ", _IPV4.sub(" ", text)))
    allowed = _allowed_numbers(incident)
    if bad := [n for n in _NUMBER.findall(stripped) if not _close(float(n), allowed)]:
        return f"number not in evidence: {bad[0]}"
    return None
