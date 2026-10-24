import pytest

from sentinel.config.settings import DetectionSettings
from sentinel.features.windows import HostContext, WindowEngine
from sentinel.sensor.parse import FrameParser
from tests import scenarios as sc

SETTINGS = DetectionSettings()


def run(packets: list[sc.Packet], now: float | None = None) -> tuple[WindowEngine, float]:
    engine = WindowEngine(SETTINGS)
    parser = FrameParser()
    last = 0.0
    for ts, frame in sorted(packets, key=lambda p: p[0]):
        for event in parser.parse(frame, ts):
            engine.observe(event)
        last = ts
    return engine, last if now is None else now


def host(engine: WindowEngine, now: float, mac: str) -> HostContext:
    [ctx] = [c for c in engine.snapshot(now) if c.host_mac == mac]
    return ctx


def test_port_scan_features_in_short_window() -> None:
    """R-FEA-001"""
    engine, now = run(sc.port_scan(100.0, range(1, 101)))
    f = host(engine, now, sc.MAC["attacker"]).features[10]
    assert (f.unique_dst_ports, f.unique_dst_ips, f.attempts) == (100, 1, 100)
    assert f.failed_ratio == pytest.approx(0.98)
    assert f.window_seconds == 10


def test_victim_sees_inbound_bytes_and_no_attempts() -> None:
    engine, now = run(sc.port_scan(100.0, range(1, 101)))
    f = host(engine, now, sc.MAC["victim"]).features[10]
    assert f.bytes_in > f.bytes_out > 0
    assert f.attempts == 0 and f.failed_ratio == 0


def test_normal_browsing_has_one_port_no_failures_and_low_entropy_dns() -> None:
    engine, now = run(sc.normal_browsing(0, 300))
    f = host(engine, now, sc.MAC["user"]).features[300]
    assert f.unique_dst_ports == 1 and f.failed_ratio == 0
    assert f.dns_queries > 5 and f.dns_max_entropy < 3.0
    assert f.share_web + f.share_ssh + f.share_dns + f.share_other == pytest.approx(1.0)


def test_slow_scan_is_invisible_to_10s_but_visible_to_5m_and_1h() -> None:
    engine, now = run(sc.slow_scan(0, probes_per_minute=4, minutes=60))
    f = host(engine, now, sc.MAC["attacker"]).features
    assert f[10].unique_dst_ports <= 1
    assert 18 <= f[300].unique_dst_ports <= 22
    assert f[3600].unique_dst_ports >= 230
    assert f[3600].failed_ratio > 0.95


def test_dns_tunnel_features() -> None:
    engine, now = run(sc.dns_tunnel(0, 60))
    f = host(engine, now, sc.MAC["victim"]).features[300]
    assert f.dns_queries == 60 and f.dns_max_subdomains_per_parent == 60
    assert f.dns_mean_entropy > 3.5 and f.dns_mean_length > 40
    assert f.dns_txt_null_share == 1.0  # every query is TXT


def test_service_attempt_counts_for_brute_force() -> None:
    engine, now = run(sc.brute_force(0, 40))
    ctx = host(engine, now, sc.MAC["attacker"])
    assert ctx.services[300][(sc.VICTIM[1], 22)] == (40, 40)


def test_beacon_timing_regular_vs_jittery() -> None:
    engine, now = run(sc.beacon(0, 20, 30.0))
    [t] = host(engine, now, sc.MAC["victim"]).destinations
    assert (t.dst_ip, t.dst_port, t.count) == (sc.C2[1], 8080, 20)
    assert t.mean_interval_seconds == pytest.approx(30.0) and t.interval_cv < 0.01
    assert t.mean_bytes < 600
    engine, now = run(sc.beacon(0, 20, 30.0, jitter=0.6))
    assert host(engine, now, sc.MAC["victim"]).destinations[0].interval_cv > 0.2


def test_old_state_is_evicted_and_late_events_are_counted() -> None:
    engine, _ = run(sc.port_scan(0.0, range(1, 50)))
    assert engine.snapshot(10_000.0) == []
    assert engine.host_count == 0
    engine, _ = run(sc.port_scan(10_000.0, range(1, 5)))
    parser = FrameParser()
    old = sc.port_scan(0.0, range(1, 3))[0]
    for event in parser.parse(old[1], old[0]):
        engine.observe(event)
    assert engine.late_dropped == 1
