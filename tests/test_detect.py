import pytest

from sentinel.config.settings import DetectionSettings
from sentinel.contracts.models import Alert
from sentinel.detect.engine import DetectionEngine
from sentinel.sensor.parse import FrameParser
from tests import scenarios as sc


def detect(packets: list[sc.Packet], settings: DetectionSettings | None = None) -> list[Alert]:
    engine = DetectionEngine(settings or DetectionSettings())
    parser = FrameParser()
    alerts: list[Alert] = []
    for ts, frame in sorted(packets, key=lambda p: p[0]):
        for event in parser.parse(frame, ts):
            alerts += engine.process(event, ts)
    return alerts + engine.flush()


def by(alerts: list[Alert], detector: str) -> list[Alert]:
    return [a for a in alerts if a.detector == detector]


def test_fast_port_scan_is_detected_on_the_attacker_only() -> None:
    """R-DET-002"""
    alerts = detect(sc.port_scan(100.0, range(1, 201)))
    [a] = by(alerts, "portscan")
    assert (a.host_mac, a.technique, a.evidence["window_seconds"]) == (
        sc.MAC["attacker"],
        "T1046",
        10.0,
    )
    assert a.evidence["failed_ratio"] > 0.9 and 0.5 < a.severity <= 1.0
    assert not [x for x in alerts if x.host_mac != sc.MAC["attacker"]]


def test_slow_scan_needs_multi_timescale_windows() -> None:
    """R-DET-006: the single short window misses it; the default windows catch it."""
    slow = sc.slow_scan(0, probes_per_minute=4, minutes=60)
    single = DetectionSettings(windows=[10])
    assert by(detect(slow, single), "portscan") == []
    caught = by(detect(slow), "portscan")
    assert caught and caught[0].evidence["window_seconds"] in (300.0, 3600.0)


def test_brute_force_on_ssh_is_not_mistaken_for_a_scan() -> None:
    """R-DET-003"""
    alerts = detect(sc.brute_force(0, 40))
    [a] = by(alerts, "bruteforce")
    assert (a.technique, a.evidence["dst_port"], a.evidence["completed"]) == (
        "T1110",
        22.0,
        a.evidence["attempts"],
    )
    assert by(alerts, "portscan") == []


def test_regular_beacon_is_detected() -> None:
    """R-DET-004"""
    alerts = detect(sc.beacon(0, 20, 30.0, jitter=0.05))
    [a] = by(alerts, "beaconing")
    assert a.technique == "T1071.001" and a.evidence["interval_cv"] < 0.15
    assert a.host_mac == sc.MAC["victim"]


def test_dns_tunnel_is_detected() -> None:
    """R-DET-005"""
    alerts = detect(sc.dns_tunnel(0, 60))
    [a] = by(alerts, "dns_tunnel")
    assert a.technique == "T1071.004" and a.evidence["signals"] >= 3


def test_normal_traffic_never_alerts() -> None:
    """R-DET-007"""
    packets = sc.normal_browsing(0, 1800, sc.USER, 1) + sc.normal_browsing(5, 1800, sc.VICTIM, 2)
    assert detect(packets) == []


@pytest.mark.parametrize(
    ("name", "packets"),
    [
        ("jittery periodic traffic", sc.beacon(0, 20, 30.0, jitter=0.6)),
        ("too few beacons", sc.beacon(0, 8, 30.0)),
        ("half-hourly update check", sc.beacon(0, 6, 1800.0)),
    ],
)  # fmt: skip
def test_near_misses_do_not_alert(name: str, packets: list[sc.Packet]) -> None:
    """R-DET-007"""
    assert detect(packets) == [], name


def test_many_low_entropy_subdomains_alone_do_not_look_like_tunnelling() -> None:
    packets = [p for i in range(60) for p in sc.dns(i * 0.5, sc.USER, f"host{i}.corp.example.com")]
    assert by(detect(packets), "dns_tunnel") == []


def test_cooldown_limits_a_continuous_attack_to_one_alert_per_window() -> None:
    alerts = by(detect(sc.port_scan(0, range(1, 3001), per_second=50)), "portscan")  # 60 s scan
    assert len(alerts) == 1


def test_many_successful_connections_to_many_ports_is_not_a_scan() -> None:
    """Gating on failure ratio: a host that reaches 60 open services is busy, not scanning."""
    packets = sc.port_scan(0, range(1, 61), open_ports=tuple(range(1, 61)))
    assert by(detect(packets), "portscan") == []


def test_repeated_refused_connections_to_ssh_are_not_brute_force() -> None:
    """Each guess completes a connection; a refused service is a different problem."""
    packets = [
        p
        for i in range(40)
        for p in sc.handshake(i * 1.0, sc.ATTACKER, sc.VICTIM, 41000 + i, 22, open_=False)
    ]
    assert by(detect(packets), "bruteforce") == []


def test_a_finished_attack_alerts_once_even_while_it_lingers_in_long_windows() -> None:
    """The 5 min / 1 h windows still contain a past scan; that must not re-alert every cooldown."""
    scan = sc.port_scan(100.0, range(1, 201))
    later_traffic = sc.normal_browsing(120, 4000, sc.USER)
    alerts = detect(scan + later_traffic)
    assert len(by(alerts, "portscan")) == 1


def test_a_beacon_that_stopped_is_not_reported_again_and_one_that_restarts_is() -> None:
    first = sc.beacon(0, 20, 30.0)
    quiet_then_traffic = sc.normal_browsing(700, 3000, sc.USER)
    assert len(by(detect(first + quiet_then_traffic), "beaconing")) == 1
    restarted = sc.beacon(4000, 20, 30.0, seed=5)
    alerts = by(detect(first + quiet_then_traffic + restarted), "beaconing")
    assert len(alerts) == 2


def test_attack_ending_on_a_tick_boundary_is_still_seen_by_the_10s_window() -> None:
    packets = sc.port_scan(100.0, range(1, 201)) + sc.normal_browsing(125, 30, sc.USER)
    alerts = by(detect(packets), "portscan")
    assert alerts[0].evidence["window_seconds"] == 10.0 and alerts[0].ts == 110.0
