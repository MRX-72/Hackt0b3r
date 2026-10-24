"""One definition of how alert numbers become the CRITICAL/HIGH/MEDIUM/LOW labels people see."""

# Confidence trims severity but cannot erase it: a perfectly regular beacon is serious even if
# we cannot be sure it is malicious. score = severity * (CONFIDENCE_FLOOR + weight * confidence).
CONFIDENCE_FLOOR = 0.6
CONFIDENCE_WEIGHT = 0.4
LABEL_FLOORS = ((0.80, "critical"), (0.65, "high"), (0.45, "medium"), (0.0, "low"))


def alert_score(severity: float, confidence: float) -> float:
    return severity * (CONFIDENCE_FLOOR + CONFIDENCE_WEIGHT * confidence)


def severity_label(score: float) -> str:
    """Lower-case label for an incident score."""
    return next(label for floor, label in LABEL_FLOORS if score >= floor)
