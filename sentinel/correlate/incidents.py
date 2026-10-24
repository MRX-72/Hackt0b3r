"""Group alerts on one host into incidents and score plausible attack progression."""

from sentinel.contracts.attack import TECHNIQUES
from sentinel.contracts.models import Alert, Incident
from sentinel.contracts.severity import alert_score

# Added to the score for each later stage reached in order (discovery -> credentials -> C2).
_PROGRESSION_BONUS = 0.1


def _score(alerts: list[Alert]) -> float:
    base = max(alert_score(a.severity, a.confidence) for a in alerts)
    stages = [
        TECHNIQUES[a.technique][1]
        for a in sorted(alerts, key=lambda a: a.ts)
        if TECHNIQUES.get(a.technique, ("", 0))[1]  # stage 0 = unusual-only, no progression
    ]
    ordered = sorted(set(stages))
    first_seen = [s for i, s in enumerate(stages) if s not in stages[:i]]
    in_order = first_seen == ordered
    return min(1.0, base + (_PROGRESSION_BONUS * (len(ordered) - 1) if in_order else 0.0))


class Correlator:
    def __init__(self, gap_seconds: float) -> None:
        self._gap = gap_seconds
        self._alerts: dict[str, list[Alert]] = {}  # host_mac -> alerts of the open incident

    def add(self, alert: Alert) -> Incident:
        """Attach the alert to the host's open incident, or start a new one after the gap."""
        current = self._alerts.get(alert.host_mac)
        if current and alert.ts - max(a.ts for a in current) > self._gap:
            current = None
        alerts = [*current, alert] if current else [alert]
        self._alerts[alert.host_mac] = alerts
        ordered = sorted(alerts, key=lambda a: a.ts)
        chain = list(dict.fromkeys(a.technique for a in ordered))
        return Incident(
            id=f"inc-{alert.host_mac.replace(':', '')}-{int(ordered[0].ts)}",
            host_mac=alert.host_mac,
            start_ts=ordered[0].ts, end_ts=ordered[-1].ts, alerts=[a.id for a in ordered],
            chain=chain, score=_score(alerts), status="correlated" if len(alerts) > 1 else "open",
        )  # fmt: skip

    def alerts_of(self, host_mac: str) -> list[Alert]:
        """Alerts of the host's open incident, oldest first."""
        return sorted(self._alerts.get(host_mac, []), key=lambda a: a.ts)
