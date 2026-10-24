"""The single gate between hostile network data and every LLM, notification and UI."""

import math
import re

from raven.contracts.attack import TECHNIQUES
from raven.contracts.models import Alert, Incident, SanitizedIncident, SanitizedStep
from raven.contracts.text import safe_identifier

_TECHNIQUE_ID = re.compile(r"^(T\d{4}(\.\d{3})?|RVN\d{3})$")
_EVIDENCE_KEY = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def sanitize_incident(incident: Incident, alerts: list[Alert]) -> SanitizedIncident:
    """Build the only incident shape downstream consumers may see.

    Free-form strings (detector names, evidence keys) are reduced to safe identifiers; techniques
    must match the ATT&CK ID shape and be known; non-finite numbers are dropped. IPs and MACs are
    already validated by the contracts.
    """
    ordered = sorted(alerts, key=lambda a: a.ts)
    steps = [
        SanitizedStep(
            detector=safe_identifier(a.detector, 32) or "unknown", technique=a.technique,
            technique_name=TECHNIQUES[a.technique][0], ts=a.ts, severity=a.severity,
            confidence=a.confidence, target_ip=a.target_ip,
            evidence={
                k: v for k, v in a.evidence.items() if _EVIDENCE_KEY.match(k) and math.isfinite(v)
            },
        )
        for a in ordered
        if _TECHNIQUE_ID.match(a.technique) and a.technique in TECHNIQUES
    ]  # fmt: skip
    last = ordered[-1]
    return SanitizedIncident(
        incident_id=safe_identifier(incident.id, 80), host_ip=last.host_ip,
        host_mac=incident.host_mac,
        severity=max(a.severity for a in ordered), confidence=max(a.confidence for a in ordered),
        score=incident.score, start_ts=incident.start_ts, end_ts=incident.end_ts, steps=steps,
    )  # fmt: skip
