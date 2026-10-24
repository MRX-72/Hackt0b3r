import pytest

from raven.config.settings import DetectionSettings
from raven.features import windows as w
from raven.features.windows import HostContext, WindowEngine, split_name
from raven.sensor.parse import FrameParser
from tests import frames
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


def test_syn_retransmissions_are_one_attempt() -> None:
    engine, now = run(sc.syn_retransmits(0, 15))
    ctx = host(engine, now, sc.MAC["user"])
    assert ctx.services[3600][(sc.VICTIM[1], 22)] == (15, 0)
    assert ctx.features[3600].attempts == 15


def test_a_late_reset_does_not_undo_a_completed_connection() -> None:
    engine, now = run(sc.brute_force_server_resets(0, 20))
    assert host(engine, now, sc.MAC["attacker"]).services[300][(sc.VICTIM[1], 22)] == (20, 20)


def test_a_syn_flood_cannot_grow_state_without_bound_and_still_looks_like_a_scan() -> None:
    packets = [
        (
            100.0 + i / 20000,
            frames.tcp_frame(sc.ATTACKER, sc.VICTIM, 1024 + i % 60000, 1 + i % 9000, frames.SYN),
        )
        for i in range(30_000)
    ]
    engine, now = run(packets)
    ctx = host(engine, now, sc.MAC["attacker"])
    assert ctx.features[10].attempts == 30_000 and ctx.features[10].failed_ratio == 1.0
    assert engine.state_capped > 0
    buckets = engine._hosts[sc.MAC["attacker"]].buckets
    assert all(len(b.attempts) <= w._MAX_ATTEMPTS_PER_BUCKET for b in buckets.values())


def test_two_level_suffixes_group_by_the_registrable_domain() -> None:
    assert split_name("www.bbc.co.uk") == ("www", "bbc.co.uk")
    assert split_name("a.b.example.com") == ("a.b", "example.com")
    assert split_name("example.com") == ("", "example.com")
    assert split_name("bbc.co.uk") == ("", "bbc.co.uk")
