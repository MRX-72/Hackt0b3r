from raven.contracts.models import Alert
from raven.correlate.incidents import Correlator

MAC = "aa:bb:cc:dd:ee:30"


def alert(technique: str, ts: float, mac: str = MAC, detector: str = "portscan") -> Alert:
    return Alert(
        id=f"{detector}-{mac}-{int(ts)}", ts=ts, detector=detector, host_mac=mac,
        host_ip="192.168.2.30", severity=0.8, confidence=0.9, evidence={"x": 1.0},
        technique=technique,
    )  # fmt: skip


def test_alerts_within_gap_join_one_incident_with_ordered_unique_chain() -> None:
    """R-COR-001"""
    c = Correlator(600)
    first = c.add(alert("T1046", 0))
    second = c.add(alert("T1110", 120, detector="bruteforce"))
    third = c.add(alert("T1110", 200, detector="bruteforce"))
    assert first.id == second.id == third.id
    assert third.chain == ["T1046", "T1110"]
    assert third.alerts == [f"portscan-{MAC}-0", f"bruteforce-{MAC}-120", f"bruteforce-{MAC}-200"]
    assert (first.status, second.status) == ("open", "correlated")
    assert (third.start_ts, third.end_ts) == (0, 200)


def test_gap_starts_a_new_incident_and_hosts_are_separate() -> None:
    c = Correlator(600)
    a = c.add(alert("T1046", 0))
    b = c.add(alert("T1046", 1000))
    other = c.add(alert("T1046", 10, mac="aa:bb:cc:dd:ee:31"))
    assert len({a.id, b.id, other.id}) == 3


def test_plausible_progression_scores_higher_than_reverse_order() -> None:
    ordered = Correlator(600)
    ordered.add(alert("T1046", 0))
    ordered_inc = ordered.add(alert("T1071.004", 10, detector="dns_tunnel"))
    reverse = Correlator(600)
    reverse.add(alert("T1071.004", 0, detector="dns_tunnel"))
    reverse_inc = reverse.add(alert("T1046", 10))
    single = Correlator(600).add(alert("T1046", 0))
    assert ordered_inc.score > single.score
    assert reverse_inc.score == single.score
    assert ordered_inc.score <= 1.0
