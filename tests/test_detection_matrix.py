"""Detection quality matrix: every attack variant must alert, every benign look-alike must not."""

import random
from collections.abc import Callable

import pytest

from raven.config.settings import DetectionSettings
from raven.contracts.models import Alert
from raven.detect.engine import DetectionEngine
from raven.sensor.parse import FrameParser
from tests import scenarios as sc
from tests.test_detect import detect

Case = tuple[str, Callable[[], list[sc.Packet]], set[str]]


def with_noise(packets: list[sc.Packet]) -> list[sc.Packet]:
    """Attacks happen on a network that is also doing normal things."""
    span = max(ts for ts, _ in packets) + 60
    return (
        packets
        + sc.normal_browsing(0, span, sc.H41, seed=7)
        + sc.normal_browsing(3, span, sc.H42, seed=8)
    )


ATTACKS: list[Case] = [
    ("fast port scan", lambda: sc.port_scan(100.0, range(1, 201)), {"portscan"}),
    ("slow scan 4/min", lambda: sc.slow_scan(0, 4, 60), {"portscan"}),
    ("host sweep of 40 hosts on 445", lambda: sc.horizontal_sweep(100.0), {"portscan"}),
    ("ssh brute force", lambda: sc.brute_force(300.0, 40), {"bruteforce"}),
    (
        "brute force, server resets each login",
        lambda: sc.brute_force_server_resets(300.0, 40),
        {"bruteforce"},
    ),
    (
        "slow brute force 1/10s for 20 min",
        lambda: sc.brute_force(0, 120, interval=10.0),
        {"bruteforce"},
    ),
    ("regular beacon", lambda: sc.beacon(0, 20, 30.0, jitter=0.05), {"beaconing"}),
    ("slow beacon every 5 min", lambda: sc.beacon(0, 12, 300.0, jitter=0.05), {"beaconing"}),
    ("dns tunnel", lambda: sc.dns_tunnel(0, 60), {"dns_tunnel"}),
    ("slow dns tunnel 1 query/5 s", lambda: sc.dns_tunnel(0, 120, per_second=0.2), {"dns_tunnel"}),
]

BENIGN: list[Case] = [
    ("normal browsing", lambda: sc.normal_browsing(0, 3600, sc.USER), set()),
    ("client retrying a dead ssh server", lambda: sc.syn_retransmits(0, 15), set()),
    (
        "three devices polling mail every minute",
        lambda: sc.periodic_polling(0, 30, 60.0, [sc.USER, sc.H41, sc.H42]),
        set(),
    ),
    ("jittery polling", lambda: sc.beacon(0, 20, 30.0, jitter=0.6), set()),
    ("half-hourly update check", lambda: sc.beacon(0, 6, 1800.0), set()),
    (
        "cdn hashed names looked up by three devices",
        lambda: sc.hashed_cdn_dns(0, 30, [sc.USER, sc.H41, sc.H42]),
        set(),
    ),
    (
        "many successful connections to many ports",
        lambda: sc.port_scan(0, range(1, 61), open_ports=tuple(range(1, 61))),
        set(),
    ),
    (
        "regular checks against a refused port",
        lambda: [
            p
            for i in range(20)
            for p in sc.handshake(i * 30.0, sc.USER, sc.MAIL, 48000 + i, 8081, open_=False)
        ],
        set(),
    ),
    (
        "ssh service refusing connections",
        lambda: [
            p
            for i in range(40)
            for p in sc.handshake(i * 1.0, sc.ATTACKER, sc.VICTIM, 41000 + i, 22, open_=False)
        ],
        set(),
    ),
]


@pytest.mark.parametrize(("name", "make", "expected"), ATTACKS, ids=[c[0] for c in ATTACKS])
def test_attack_variants_are_detected_once(
    name: str, make: Callable[[], list[sc.Packet]], expected: set[str]
) -> None:
    """R-DET-002..006"""
    alerts = detect(with_noise(make()))
    assert {a.detector for a in alerts} == expected, name
    assert len(alerts) == len(expected), f"{name}: duplicate alerts {[a.detector for a in alerts]}"
    noisy = {a.host_mac for a in alerts} & {"aa:bb:cc:dd:ee:41", "aa:bb:cc:dd:ee:42"}
    assert not noisy, "alerts landed on the innocent bystanders"


@pytest.mark.parametrize(("name", "make", "expected"), BENIGN, ids=[c[0] for c in BENIGN])
def test_benign_lookalikes_do_not_alert(
    name: str, make: Callable[[], list[sc.Packet]], expected: set[str]
) -> None:
    """R-DET-007"""
    assert detect(with_noise(make())) == [], name


def test_udp_replies_do_not_make_the_server_a_beacon() -> None:
    alerts = detect(with_noise(sc.udp_polling(0, 30, 30.0)))
    assert not [a for a in alerts if a.host_mac == "aa:bb:cc:dd:ee:70"]


def test_trusted_and_allowlisted_sources_stay_quiet() -> None:
    settings = DetectionSettings(trusted_ips=["192.168.2.30"])
    assert detect(sc.port_scan(100.0, range(1, 201)), settings) == []
    listed = DetectionSettings(beacon_allow_destinations=["192.168.2.50/32"])
    assert detect(sc.beacon(0, 20, 30.0), listed) == []
    domains = DetectionSettings(dns_ignore_domains=["badzone.net"])
    assert detect(sc.dns_tunnel(0, 60), domains) == []


@pytest.mark.parametrize(
    ("name", "make", "expected"),
    ATTACKS[:4] + ATTACKS[6:7] + ATTACKS[8:9],
    ids=lambda v: v if isinstance(v, str) else "",
)
def test_duplicated_packets_do_not_change_the_verdict(
    name: str, make: Callable[[], list[sc.Packet]], expected: set[str]
) -> None:
    """A mirror/span port can deliver every packet twice."""
    packets = with_noise(make())
    twice = packets + [(ts + 0.0005, frame) for ts, frame in packets]
    assert {a.detector for a in detect(twice)} == expected, name


def test_the_same_capture_always_gives_the_same_alerts() -> None:
    packets = with_noise(sc.port_scan(100.0, range(1, 201)) + sc.beacon(0, 20, 30.0))
    first = [a.model_dump() for a in detect(packets)]
    assert first == [a.model_dump() for a in detect(list(reversed(packets)))]


@pytest.mark.parametrize("seed", range(12))
def test_random_benign_networks_never_alert(seed: int) -> None:
    """Soak: eight devices browsing, polling shared services and hitting the odd closed port."""
    rnd = random.Random(seed)
    clients = [sc.USER, sc.H41, sc.H42, sc.H43, sc._extra_host(0x44), sc._extra_host(0x45)]
    packets: list[sc.Packet] = []
    for n, client in enumerate(clients):
        packets += sc.normal_browsing(rnd.uniform(0, 5), 2400, client, seed=seed * 10 + n)
    packets += sc.periodic_polling(0, 30, rnd.choice([30.0, 60.0, 90.0]), clients[:4])
    for i in range(rnd.randrange(1, 5)):  # a few refused connections, nothing like a scan
        packets += sc.handshake(
            rnd.uniform(0, 2400),
            rnd.choice(clients),
            sc.VICTIM,
            47000 + i,
            rnd.choice([81, 8081, 2222]),
            open_=False,
        )
    packets += sc.hashed_cdn_dns(0, 15, clients[:4], seconds=1200)
    assert detect(packets) == []


def detect_live(packets: list[sc.Packet]) -> list[Alert]:
    """Like a live run: evaluation only on 10 s ticks plus one idle heartbeat afterwards."""
    engine, parser = (
        DetectionEngine(DetectionSettings(windows=[10], **TEN_SECOND_ONLY)),
        FrameParser(),
    )
    alerts: list[Alert] = []
    last = 0.0
    for ts, frame in sorted(packets, key=lambda p: p[0]):
        for event in parser.parse(frame, ts):
            alerts += engine.process(event, ts)
        last = ts
    return alerts + engine.advance(last + 10)


TEN_SECOND_ONLY = {
    "scan_min_unique_ports": {10: 20},
    "scan_min_unique_hosts": {10: 20},
    "brute_min_attempts": {10: 8},
}
BURSTS: list[tuple[str, Callable[[float], list[sc.Packet]], str]] = [
    ("port scan", lambda t: sc.port_scan(t, range(1, 401), per_second=400), "portscan"),
    ("brute force", lambda t: sc.brute_force(t, 30, interval=0.4), "bruteforce"),
    ("beacon, 1 per second", lambda t: sc.beacon(t, 14, 1.0, jitter=0.002), "beaconing"),
    ("dns tunnel", lambda t: sc.dns_tunnel(t, 60, per_second=8), "dns_tunnel"),
]


@pytest.mark.parametrize("phase", [i * 0.9 for i in range(12)])
@pytest.mark.parametrize(("name", "make", "detector"), BURSTS, ids=[b[0] for b in BURSTS])
def test_short_bursts_are_caught_whatever_the_phase_of_the_10s_grid(
    name: str, make: Callable[[float], list[sc.Packet]], detector: str, phase: float
) -> None:
    """Live ticks fall every 10 s; an attack must not slip between two of them."""
    alerts = detect_live(make(1000.0 + phase))
    assert [a.detector for a in alerts] == [detector], f"{name} at phase {phase}"
