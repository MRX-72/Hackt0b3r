import pytest

from sentinel.contracts.models import Alert
from sentinel.contracts.severity import alert_score, severity_label
from sentinel.correlate.incidents import Correlator
from tests import scenarios as sc
from tests.test_detect import detect


def labels(packets: list[sc.Packet]) -> list[str]:
    """Label of the incident each attack leaves behind, with default settings."""
    correlator, last = Correlator(600), None
    for alert in detect(packets):
        last = correlator.add(alert)
    return [severity_label(last.score)] if last else []


@pytest.mark.parametrize(
    ("name", "packets"),
    [
        ("port scan", sc.port_scan(100.0, range(1, 401), per_second=400)),
        ("brute force on 22", sc.brute_force(0, 30, interval=0.4)),
        ("brute force on 2222 (default settings)", sc.brute_force(0, 30, interval=0.4, port=2222)),
        ("beacon, one a second", sc.beacon(0, 16, 1.0, jitter=0.002)),
        ("dns tunnel", sc.dns_tunnel(0, 60, per_second=8)),
    ],
)
def test_each_demo_attack_alone_is_critical(name: str, packets: list[sc.Packet]) -> None:
    assert labels(packets) == ["critical"], name


def test_weak_evidence_stays_below_critical() -> None:
    jittery_beacon = sc.beacon(0, 12, 30.0, jitter=0.14, seed=11)
    slow_scan = sc.slow_scan(0, probes_per_minute=4, minutes=60)
    assert labels(jittery_beacon) in ([], ["medium"], ["high"])
    assert labels(slow_scan) != ["critical"]


def test_labels_and_scores_have_sensible_edges() -> None:
    assert [severity_label(s) for s in (1.0, 0.80, 0.79, 0.65, 0.64, 0.45, 0.44, 0.0)] == [
        "critical", "critical", "high", "high", "medium", "medium", "low", "low",
    ]  # fmt: skip
    assert alert_score(1.0, 1.0) == pytest.approx(1.0)
    assert alert_score(0.9, 0.0) == pytest.approx(0.54)  # low confidence trims, never erases


def test_confidence_can_only_lower_a_score_by_a_bounded_amount() -> None:
    alert = Alert(
        id="a", ts=1.0, detector="beaconing", host_mac="aa:bb:cc:dd:ee:01", host_ip="192.168.2.3",
        severity=1.0, confidence=0.5, evidence={}, technique="T1071.001",
    )  # fmt: skip
    assert Correlator(600).add(alert).score == pytest.approx(0.8)
