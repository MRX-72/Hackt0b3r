"""Independent frame builders (struct only, no dpkt) so parser tests are not circular."""

import socket
import struct

SRC_MAC = bytes.fromhex("aabbccddee01")
DST_MAC = bytes.fromhex("aabbccddee02")
SRC_IP = "192.168.2.3"
DST_IP = "192.168.2.2"
FIN, SYN, RST, PSH, ACK = 0x01, 0x02, 0x04, 0x08, 0x10


def eth(
    payload: bytes, ethertype: int = 0x0800, src: bytes = SRC_MAC, dst: bytes = DST_MAC
) -> bytes:
    return dst + src + struct.pack("!H", ethertype) + payload


def ipv4(proto: int, payload: bytes, src: str = SRC_IP, dst: str = DST_IP) -> bytes:
    header = struct.pack(
        "!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 1, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )  # fmt: skip
    return header + payload


def ipv6(nxt: int, payload: bytes, src: str = "fe80::1", dst: str = "fe80::2") -> bytes:
    header = struct.pack(
        "!IHBB16s16s", 6 << 28, len(payload), nxt, 64,
        socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst),
    )  # fmt: skip
    return header + payload


def tcp(sport: int, dport: int, flags: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHIIBBHHH", sport, dport, 1, 0, 5 << 4, flags, 1024, 0, 0) + payload


def udp(sport: int, dport: int, payload: bytes = b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp_echo() -> bytes:
    return struct.pack("!BBHHH", 8, 0, 0, 1, 1) + b"ping"


def dns_name(name: str) -> bytes:
    return b"".join(bytes([len(p)]) + p.encode() for p in name.split(".")) + b"\x00"


def dns_query(name: str | bytes, qtype: int = 1, response: bool = False) -> bytes:
    raw = name if isinstance(name, bytes) else dns_name(name)
    flags = 0x8180 if response else 0x0100
    return struct.pack("!HHHHHH", 0x1234, flags, 1, 0, 0, 0) + raw + struct.pack("!HH", qtype, 1)


def mdns_response(name: str, ip: str = SRC_IP) -> bytes:
    answer = dns_name(name) + struct.pack("!HHIH", 1, 0x8001, 120, 4) + socket.inet_aton(ip)
    return struct.pack("!HHHHHH", 0, 0x8400, 0, 1, 0, 0) + answer


def arp(op: int, sha: bytes, spa: str, tha: bytes, tpa: str) -> bytes:
    return (
        struct.pack("!HHBBH", 1, 0x0800, 6, 4, op)
        + sha + socket.inet_aton(spa) + tha + socket.inet_aton(tpa)
    )  # fmt: skip


def dhcp(
    msg_type: int, client_mac: bytes, yiaddr: str | None = None, hostname: bytes = b""
) -> bytes:
    fixed = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s", 2, 1, 6, 0, 0xDEADBEEF, 0, 0,
        bytes(4), socket.inet_aton(yiaddr) if yiaddr else bytes(4), bytes(4), bytes(4),
        client_mac.ljust(16, b"\0"),
        b"", b"",
    )  # fmt: skip
    opts = bytes([53, 1, msg_type])
    if hostname:
        opts += bytes([12, len(hostname)]) + hostname
    return fixed + b"\x63\x82\x53\x63" + opts + b"\xff"


def tcp_syn_frame() -> bytes:
    return eth(ipv4(6, tcp(51234, 22, SYN)))


def valid_frames() -> list[bytes]:
    """One well-formed frame of every kind the parser understands."""
    return [
        tcp_syn_frame(),
        eth(ipv4(6, tcp(80, 51234, SYN | ACK))),
        eth(ipv4(17, udp(40000, 53, dns_query("example.com", 16)))),
        eth(ipv4(1, icmp_echo())),
        eth(ipv6(6, tcp(51234, 443, SYN)), 0x86DD),
        eth(arp(2, SRC_MAC, SRC_IP, DST_MAC, DST_IP), 0x0806),
        eth(ipv4(17, udp(67, 68, dhcp(2, DST_MAC, "192.168.2.50", b"printer")))),
        eth(ipv4(17, udp(5353, 5353, mdns_response("macbook.local")))),
    ]
