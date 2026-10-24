"""Labelled synthetic traffic (seeded). Each scenario returns (ts, frame) pairs, sorted by ts."""

import random
import struct
from pathlib import Path

from tests import frames as f

Packet = tuple[float, bytes]
GATEWAY = (bytes.fromhex("aabbccddee01"), "192.168.2.1")
VICTIM = (bytes.fromhex("aabbccddee20"), "192.168.2.20")
ATTACKER = (bytes.fromhex("aabbccddee30"), "192.168.2.30")
USER = (bytes.fromhex("aabbccddee40"), "192.168.2.40")
C2 = (bytes.fromhex("aabbccddee50"), "192.168.2.50")
MAC = {"victim": "aa:bb:cc:dd:ee:20", "attacker": "aa:bb:cc:dd:ee:30", "user": "aa:bb:cc:dd:ee:40"}
Host = tuple[bytes, str]


def write_pcap(path: Path, packets: list[Packet]) -> None:
    with path.open("wb") as out:
        out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
        for ts, frame in sorted(packets, key=lambda p: p[0]):
            out.write(struct.pack("<IIII", int(ts), int((ts % 1) * 1e6), len(frame), len(frame)))
            out.write(frame)


def handshake(ts: float, src: Host, dst: Host, sport: int, dport: int, open_: bool = True,
              data: int = 0) -> list[Packet]:  # fmt: skip
    """SYN then SYN-ACK (open) or RST-ACK (closed); open ones complete, sending `data` bytes."""
    syn = (ts, f.tcp_frame(src, dst, sport, dport, f.SYN))
    if not open_:
        return [syn, (ts + 0.001, f.tcp_frame(dst, src, dport, sport, f.RST | f.ACK))]
    out = [syn, (ts + 0.001, f.tcp_frame(dst, src, dport, sport, f.SYN | f.ACK)),
           (ts + 0.002, f.tcp_frame(src, dst, sport, dport, f.ACK))]  # fmt: skip
    if data:
        out.append((ts + 0.01, f.tcp_frame(src, dst, sport, dport, f.PSH | f.ACK, bytes(data))))
    out.append((ts + 0.05, f.tcp_frame(src, dst, sport, dport, f.FIN | f.ACK)))
    return out


def dns(ts: float, src: Host, name: str, qtype: int = 1) -> list[Packet]:
    q = f.udp_frame(src, GATEWAY, 40000 + int(ts) % 1000, 53, f.dns_query(name, qtype))
    r = f.udp_frame(GATEWAY, src, 53, 40000 + int(ts) % 1000, f.dns_query(name, qtype, True))
    return [(ts, q), (ts + 0.01, r)]


NORMAL_SITES = ["example.com", "news.example.org", "cdn.example.net", "mail.example.com"]


def normal_browsing(start: float, seconds: float, src: Host = USER, seed: int = 1) -> list[Packet]:
    rnd = random.Random(seed)
    out: list[Packet] = []
    t = start
    while t < start + seconds:
        site = rnd.choice(NORMAL_SITES)
        out += dns(t, src, site)
        server: Host = (bytes.fromhex("aabbccddee60"), f"192.168.2.{100 + rnd.randrange(5)}")
        out += handshake(t + 0.1, src, server, 50000 + rnd.randrange(1000), 443, data=800)
        t += rnd.uniform(3, 20)
    return out


def port_scan(
    start: float, ports: range, per_second: float = 50, open_ports: tuple[int, ...] = (22, 80)
) -> list[Packet]:
    out: list[Packet] = []
    for i, port in enumerate(ports):
        out += handshake(
            start + i / per_second, ATTACKER, VICTIM, 40000 + i, port, port in open_ports
        )
    return out


def slow_scan(start: float, probes_per_minute: float, minutes: float) -> list[Packet]:
    ports = range(1000, 1000 + int(probes_per_minute * minutes))
    return port_scan(start, ports, per_second=probes_per_minute / 60)


def brute_force(start: float, attempts: int, interval: float = 1.0, port: int = 22) -> list[Packet]:
    out: list[Packet] = []
    for i in range(attempts):
        out += handshake(start + i * interval, ATTACKER, VICTIM, 41000 + i, port, data=120)
    return out


def beacon(
    start: float, count: int, interval: float, jitter: float = 0.0, seed: int = 2
) -> list[Packet]:
    rnd = random.Random(seed)
    out: list[Packet] = []
    t = start
    for i in range(count):
        out += handshake(t, VICTIM, C2, 42000 + i, 8080, data=100)
        t += interval * (1 + rnd.uniform(-jitter, jitter))
    return out


def dns_tunnel(start: float, count: int, per_second: float = 2.0, seed: int = 3) -> list[Packet]:
    rnd = random.Random(seed)
    alphabet = "abcdefghijklmnopqrstuvwxyz234567"
    out: list[Packet] = []
    for i in range(count):
        label = "".join(rnd.choice(alphabet) for _ in range(52))
        out += dns(start + i / per_second, VICTIM, f"{label}.t.badzone.net", 16)
    return out


def _extra_host(n: int) -> Host:
    return (bytes.fromhex(f"aabbccddee{n:02x}"), f"192.168.2.{n}")


H41, H42, H43 = _extra_host(0x41), _extra_host(0x42), _extra_host(0x43)
MAIL = (bytes.fromhex("aabbccddee70"), "192.168.2.70")


def syn_retransmits(
    start: float, attempts: int, port: int = 22, spacing: float = 20.0
) -> list[Packet]:
    """A client retrying a dead server: one SYN per attempt plus retransmits at +1, +3, +7 s."""
    out: list[Packet] = []
    for i in range(attempts):
        t = start + i * spacing
        for offset in (0, 1, 3, 7):
            out.append((t + offset, f.tcp_frame(USER, VICTIM, 45000 + i, port, f.SYN)))
    return out


def brute_force_server_resets(start: float, attempts: int, interval: float = 1.0) -> list[Packet]:
    """Every failed login ends with the server resetting the connection."""
    out: list[Packet] = []
    for i in range(attempts):
        t = start + i * interval
        out += handshake(t, ATTACKER, VICTIM, 41000 + i, 22, data=120)[:-1]
        out.append((t + 0.05, f.tcp_frame(VICTIM, ATTACKER, 22, 41000 + i, f.RST | f.ACK)))
    return out


def horizontal_sweep(
    start: float, hosts: int = 40, port: int = 445, per_second: float = 20
) -> list[Packet]:
    out: list[Packet] = []
    for i in range(hosts):
        target: Host = (bytes.fromhex(f"aabbccddee{0x80 + i:02x}"), f"192.168.2.{100 + i}")
        out += handshake(start + i / per_second, ATTACKER, target, 43000 + i, port, open_=False)
    return out


def periodic_polling(
    start: float,
    count: int,
    interval: float,
    clients: list[Host],
    server: Host = MAIL,
    port: int = 993,
) -> list[Packet]:
    """Mail/chat apps checking a server on a schedule; clients are staggered by a few seconds."""
    out: list[Packet] = []
    for c, client in enumerate(clients):
        for i in range(count):
            out += handshake(
                start + c * 3 + i * interval, client, server, 46000 + i, port, data=200
            )
    return out


def udp_polling(start: float, count: int, interval: float, port: int = 9000) -> list[Packet]:
    """A client polls a UDP service; the server replies from the service port."""
    out: list[Packet] = []
    for i in range(count):
        t = start + i * interval
        out.append((t, f.udp_frame(USER, MAIL, 50000, port, bytes(40))))  # one long-lived socket
        out.append((t + 0.02, f.udp_frame(MAIL, USER, port, 50000, bytes(40))))
    return out


def hashed_cdn_dns(
    start: float, count: int, clients: list[Host], seconds: float = 300.0, seed: int = 4
) -> list[Packet]:
    """Long hex-hash host names under one CDN domain, looked up by each client."""
    rnd = random.Random(seed)
    out: list[Packet] = []
    for client in clients:
        for i in range(count):
            label = "".join(rnd.choice("0123456789abcdef") for _ in range(32))
            out += dns(start + i * seconds / count, client, f"{label}.cdn-assets.example.net")
    return out
