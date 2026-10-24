import random

import pytest

from raven.config.settings import DetectionSettings, MlSettings
from raven.contracts.models import Alert, Incident
from raven.correlate.incidents import Correlator
from raven.detect.behavior import BehaviorAnomaly
from raven.detect.engine import DetectionEngine
from raven.explain.sanitize import sanitize_incident
from raven.explain.templates import explain_template
from raven.ml.iforest import IsolationForest
from raven.ml.ngram import DEFAULT
from raven.sensor.parse import FrameParser
from tests import scenarios as sc

MAC = "aa:bb:cc:dd:ee:40"


def detect(packets: list[sc.Packet], ml: MlSettings | None = None) -> list[Alert]:
    engine = DetectionEngine(DetectionSettings(ml=ml or MlSettings()))
    parser = FrameParser()
    alerts: list[Alert] = []
    for ts, frame in sorted(packets, key=lambda p: p[0]):
        for event in parser.parse(frame, ts):
            alerts += engine.process(event, ts)
    return alerts + engine.flush()


# ----------------------------------------------------------------------------- n-gram
def test_random_names_are_far_more_surprising_than_ordinary_ones() -> None:
    rnd = random.Random(1)
    random_names = [
        "".join(rnd.choice("abcdefghijklmnopqrstuvwxyz234567") for _ in range(24))
        for _ in range(40)
    ]
    ordinary = ["weatherstation", "mycompany", "printserver", "newsletter", "fileshare", "www"]
    assert min(DEFAULT.surprisal(n) for n in random_names) > 4.8
    assert sum(DEFAULT.surprisal(n) for n in ordinary) / len(ordinary) < 4.0
    assert DEFAULT.surprisal("") == DEFAULT.surprisal("....") or DEFAULT.surprisal("") == 0.0


def test_surprisal_ignores_case_and_scores_each_label() -> None:
    assert DEFAULT.surprisal("Mail.Example") == DEFAULT.surprisal("mail.example")


# ----------------------------------------------------------------------------- forest
def test_forest_scores_outliers_higher_and_is_deterministic() -> None:
    rnd = random.Random(2)
    rows = [[rnd.gauss(10, 2), rnd.gauss(50, 5)] for _ in range(300)]
    forest, again = IsolationForest(seed=4), IsolationForest(seed=4)
    assert forest.score([10.0, 50.0]) == 0.0  # not fitted
    forest.fit(rows)
    again.fit(rows)
    assert forest.score([40.0, 120.0]) > 0.65 > forest.score([10.0, 50.0])
    assert forest.score([40.0, 120.0]) == again.score([40.0, 120.0])


def test_forest_copes_with_constant_columns_and_tiny_samples() -> None:
    forest = IsolationForest(trees=5)
    forest.fit([[1.0, 1.0]])
    assert 0.0 <= forest.score([1.0, 1.0]) <= 1.0
    forest.fit([[2.0, 3.0]] * 10)
    assert 0.0 <= forest.score([9.0, 9.0]) <= 1.0


# ----------------------------------------------------------------------------- ablation
def test_ablation_ngram_catches_a_slow_short_label_tunnel_the_rules_alone_miss() -> None:
    packets = sc.stealth_dns_tunnel(0, 14)
    without = detect(packets, MlSettings(ngram_dns=False, isolation_forest=False))
    with_ngram = detect(packets, MlSettings(isolation_forest=False))
    assert without == []
    assert [a.detector for a in with_ngram] == ["dns_tunnel"]
    assert with_ngram[0].evidence["dns_mean_surprisal"] > 4.8


def baseline(seconds: float = 2400) -> list[sc.Packet]:
    out: list[sc.Packet] = []
    for n, host in enumerate([sc.USER, sc.H41, sc.H42]):
        out += sc.normal_browsing(0, seconds, host, seed=20 + n)
    return out


def test_ablation_forest_catches_a_bulk_upload_that_no_rule_covers() -> None:
    packets = baseline() + sc.bulk_upload(2500, sc.USER, sc.C2, seconds=20)
    rules_only = detect(packets, MlSettings(isolation_forest=False))
    full = detect(packets)
    assert rules_only == []
    sender = next(a for a in full if a.host_mac == MAC)  # the receiving device alerts too
    assert {a.detector for a in full} == {"behavior"} and len(full) == 2
    assert (sender.technique, sender.evidence["value_bytes_out"] > 100_000) == ("RVN001", True)
    assert sender.evidence["excess_bytes_out"] > 100
    assert all(a.severity <= 0.6 for a in full)  # "unusual" alone never reads as a named attack


def test_a_named_attack_suppresses_the_vague_unusual_alert_for_that_device() -> None:
    packets = baseline() + sc.port_scan(2500, range(1, 401), per_second=100)
    assert {a.detector for a in detect(packets)} == {"portscan"}


def test_the_forest_stays_silent_until_it_has_seen_enough_traffic() -> None:
    assert (
        detect(sc.normal_browsing(0, 200) + sc.bulk_upload(250, sc.USER, sc.C2, seconds=20)) == []
    )


def test_ordinary_traffic_alone_does_not_trip_the_forest() -> None:
    assert detect(baseline(3600)) == []


def test_an_unusual_vector_is_not_learned_as_normal() -> None:
    """A long upload must keep alerting rather than teaching the baseline that it is normal."""
    engine = DetectionEngine(DetectionSettings())
    parser = FrameParser()
    for ts, frame in sorted(baseline() + sc.bulk_upload(2500, sc.USER, sc.C2, seconds=60)):
        for event in parser.parse(frame, ts):
            engine.process(event, ts)
    detector = next(d for d in engine._detectors if isinstance(d, BehaviorAnomaly))
    assert max(r[6] for r in detector._normal) < 100_000


# ----------------------------------------------------------------------------- wiring
def alert(detector: str, technique: str, ts: float, sev: float = 0.9) -> Alert:
    evidence = {"value_bytes_out": 250000.0, "excess_bytes_out": 90.0, "window_seconds": 10.0}
    return Alert(
        id=f"{detector}-{ts}", ts=ts, detector=detector, host_mac=MAC, host_ip="192.168.2.40",
        severity=sev, confidence=0.7, evidence=evidence, technique=technique,
    )  # fmt: skip


def test_an_unusual_only_alert_never_adds_attack_progression_bonus() -> None:
    corr = Correlator(600)
    corr.add(alert("behavior", "RVN001", 1.0, 0.5))
    plain = corr.add(alert("portscan", "T1046", 2.0)).score
    solo = Correlator(600).add(alert("portscan", "T1046", 2.0)).score
    assert plain == solo and corr.alerts_of(MAC)[0].technique == "RVN001"


def test_the_sanitizer_accepts_the_statistical_id_and_nothing_made_up() -> None:
    inc = Incident(id="i1", host_mac=MAC, start_ts=1, end_ts=2, alerts=["a"], chain=[], score=0.5)
    ok = sanitize_incident(inc, [alert("behavior", "RVN001", 1.0)])
    assert [s.technique for s in ok.steps] == ["RVN001"]
    for bad in ("RVN999", "RVN1", "rvn001"):
        assert sanitize_incident(inc, [alert("behavior", bad, 1.0)]).steps == []


def test_the_explanation_names_the_most_unusual_thing_without_claiming_an_attack() -> None:
    inc = Incident(id="i1", host_mac=MAC, start_ts=1, end_ts=2, alerts=["a"], chain=[], score=0.5)
    text = explain_template(sanitize_incident(inc, [alert("behavior", "RVN001", 1.0)]))
    assert "unlike this network's usual pattern" in text.headline.lower()
    assert "unusually large amount of data sent out (250000)" in text.what_happened
    assert "not from a known attack pattern" in text.what_happened


def test_ml_settings_are_validated_and_switchable() -> None:
    with pytest.raises(ValueError):
        MlSettings(if_threshold=0.4)
    engine = DetectionEngine(DetectionSettings(ml=MlSettings(isolation_forest=False)))
    assert "behavior" not in {d.name for d in engine._detectors}
