from pathlib import Path

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from raven.contracts.models import ArpEvent, DhcpEvent, Flow, MdnsEvent
from raven.sensor.parse import FrameParser
from raven.storage.db import Storage
from tests import frames as f

MAC1 = "aa:bb:cc:dd:ee:01"
MAC2 = "aa:bb:cc:dd:ee:02"


def parse_one(frame: bytes) -> tuple[FrameParser, list[object]]:
    p = FrameParser()
    return p, list(p.parse(frame, 5.0))


def only_flow(frame: bytes) -> Flow:
    p, events = parse_one(frame)
    assert p.parse_errors == 0, p
    [flow] = events
    assert isinstance(flow, Flow)
    return flow


def test_tcp_syn_golden() -> None:
    """R-FLW-001"""
    frame = f.tcp_syn_frame()
    assert only_flow(frame) == Flow(
        ts=5.0, src_ip="192.168.2.3", dst_ip="192.168.2.2", src_mac=MAC1, dst_mac=MAC2,
        proto="tcp", src_port=51234, dst_port=22, bytes=len(frame), packets=1, tcp_flags="S",
    )  # fmt: skip


@pytest.mark.parametrize(
    ("flags", "expected"),
    [(f.SYN | f.ACK, "SA"), (f.RST, "R"), (f.FIN | f.ACK, "FA"), (f.PSH | f.ACK, "PA"), (0, "")],
)
def test_tcp_flag_strings(flags: int, expected: str) -> None:
    assert only_flow(f.eth(f.ipv4(6, f.tcp(1, 2, flags)))).tcp_flags == expected


def test_udp_icmp_and_ipv6() -> None:
    udp = only_flow(f.eth(f.ipv4(17, f.udp(1000, 2000, b"x"))))
    assert (udp.proto, udp.src_port, udp.dst_port, udp.tcp_flags) == ("udp", 1000, 2000, None)
    icmp = only_flow(f.eth(f.ipv4(1, f.icmp_echo())))
    assert (icmp.proto, icmp.src_port, icmp.dst_port) == ("icmp", None, None)
    v6 = only_flow(f.eth(f.ipv6(6, f.tcp(1, 443, f.SYN)), 0x86DD))
    assert (v6.src_ip, v6.dst_ip, v6.dst_port) == ("fe80::1", "fe80::2", 443)


def test_ipv6_extension_header_is_skipped_to_reach_tcp() -> None:
    hop_by_hop = bytes([6, 0, 1, 4, 0, 0, 0, 0])  # next=TCP, len=0 (8 bytes), PadN
    v6 = only_flow(f.eth(f.ipv6(0, hop_by_hop + f.tcp(1, 443, f.SYN)), 0x86DD))
    assert (v6.proto, v6.dst_port) == ("tcp", 443)


def test_dns_query_populates_name_and_type_lowercased() -> None:
    flow = only_flow(f.eth(f.ipv4(17, f.udp(40000, 53, f.dns_query("WWW.Example.com", 16)))))
    assert (flow.dns_query, flow.dns_qtype) == ("www.example.com", "TXT")
    null = only_flow(f.eth(f.ipv4(17, f.udp(40000, 53, f.dns_query("a.b", 10)))))
    assert null.dns_qtype == "NULL"
    unknown = only_flow(f.eth(f.ipv4(17, f.udp(40000, 53, f.dns_query("a.b", 999)))))
    assert unknown.dns_qtype == "TYPE999"


def test_dns_response_has_no_query_fields() -> None:
    flow = only_flow(f.eth(f.ipv4(17, f.udp(53, 40000, f.dns_query("example.com", 1, True)))))
    assert (flow.dns_query, flow.dns_qtype) == (None, None)


def test_bad_dns_keeps_the_flow_and_counts_dns_error() -> None:
    for payload in (f.dns_query("example.com")[:15], f.dns_query(b"\x03a\xff\xfe\x00")):
        p, events = parse_one(f.eth(f.ipv4(17, f.udp(40000, 53, payload))))
        [flow] = events
        assert isinstance(flow, Flow)
        assert (flow.dns_query, p.payload_errors, p.parse_errors) == (None, 1, 0)


def test_dns_compression_loop_is_counted_not_fatal() -> None:
    loop = f.dns_query(b"\xc0\x0c")
    p, events = parse_one(f.eth(f.ipv4(17, f.udp(40000, 53, loop))))
    assert len(events) == 1
    assert p.payload_errors == 1


def test_arp() -> None:
    frame = f.eth(f.arp(2, f.SRC_MAC, f.SRC_IP, f.DST_MAC, f.DST_IP), 0x0806)
    p, [ev] = parse_one(frame)
    assert ev == ArpEvent(
        ts=5.0, op="reply", eth_src_mac=MAC1, sender_mac=MAC1, sender_ip=f.SRC_IP,
        target_mac=MAC2, target_ip=f.DST_IP,
    )  # fmt: skip
    assert p.parse_errors == 0


def test_dhcp_offer_from_server() -> None:
    frame = f.eth(f.ipv4(17, f.udp(67, 68, f.dhcp(2, f.DST_MAC, "192.168.2.50", b"printer"))))
    p, events = parse_one(frame)
    dhcp = next(e for e in events if isinstance(e, DhcpEvent))
    assert (dhcp.msg_type, dhcp.client_mac, dhcp.offered_ip, dhcp.hostname) == (
        "offer", MAC2, "192.168.2.50", "printer",
    )  # fmt: skip
    assert (dhcp.src_mac, dhcp.src_ip) == (MAC1, f.SRC_IP)
    assert p.parse_errors == 0


def test_dhcp_hostname_with_invalid_utf8_is_a_valid_string() -> None:
    frame = f.eth(f.ipv4(17, f.udp(67, 68, f.dhcp(2, f.DST_MAC, hostname=b"pr\xff\x00int"))))
    _, events = parse_one(frame)
    dhcp = next(e for e in events if isinstance(e, DhcpEvent))
    assert dhcp.hostname is not None
    dhcp.hostname.encode("utf-8")


def test_mdns_names() -> None:
    _, events = parse_one(f.eth(f.ipv4(17, f.udp(5353, 5353, f.mdns_response("macbook.local")))))
    assert [e.name for e in events if isinstance(e, MdnsEvent)] == ["macbook.local"]


def test_unknown_ethertype_is_ignored_not_an_error() -> None:
    p, events = parse_one(f.eth(b"\x00" * 30, 0x88CC))
    assert (events, p.ignored, p.parse_errors) == ([], 1, 0)


def test_well_formed_frames_never_count_errors() -> None:
    p = FrameParser()
    for frame in f.valid_frames():
        assert p.parse(frame, 1.0)
    assert (p.frames, p.parse_errors, p.payload_errors, p.ignored) == (
        len(f.valid_frames()),
        0,
        0,
        0,
    )


@pytest.mark.parametrize("frame", f.valid_frames())
def test_every_prefix_of_a_valid_frame_is_survivable_and_malformed_ones_are_counted(
    frame: bytes,
) -> None:
    """R-SAF-006"""
    for cut in range(len(frame)):
        p = FrameParser()
        events = p.parse(frame[:cut], 1.0)
        if cut < 14:
            assert (events, p.parse_errors) == ([], 1)


def test_truncated_tcp_header_counts_a_parse_error() -> None:
    p, events = parse_one(f.eth(f.ipv4(6, f.tcp(1, 2, f.SYN)[:10])))
    assert (events, p.parse_errors) == ([], 1)


@settings(max_examples=500, deadline=None)
@given(st.binary(max_size=400))
def test_fuzz_random_bytes_never_raise(data: bytes) -> None:
    """R-SAF-006"""
    FrameParser().parse(data, 1.0)


@settings(max_examples=500, deadline=None)
@given(
    st.sampled_from(f.valid_frames()),
    st.lists(st.tuples(st.integers(0, 399), st.integers(0, 255)), max_size=6),
)
def test_fuzz_mutated_valid_frames_never_raise(frame: bytes, edits: list[tuple[int, int]]) -> None:
    """R-SAF-006"""
    data = bytearray(frame)
    for index, value in edits:
        if index < len(data):
            data[index] = value
    FrameParser().parse(bytes(data), 1.0)


@pytest.mark.security
def test_hostile_dns_name_flows_into_storage(tmp_path: Path) -> None:
    """Names with control characters and SQL text must survive parse -> SQLite as data."""
    name = "x'); drop table flow;--"
    raw = (
        b"".join(bytes([len(p)]) + p for p in (name.encode(), b"\x01\x02\x1b[31m", b"com"))
        + b"\x00"
    )
    flow = only_flow(f.eth(f.ipv4(17, f.udp(40000, 53, f.dns_query(raw)))))
    assert flow.dns_query is not None
    db = Storage(tmp_path / "p.db")
    db.insert_flows([flow])
    assert db.flows_for_host(MAC1, 0, 10) == [flow]
    db.close()


def test_byte_counts_use_the_wire_length_not_the_snaplen_truncated_length() -> None:
    full = f.eth(f.ipv4(6, f.tcp(1, 2, f.PSH | f.ACK, bytes(1400))))
    truncated = full[:96]
    assert only_flow(truncated).bytes == len(full)
    zero_len = bytearray(full)
    zero_len[16:18] = b"\x00\x00"  # TSO/checksum-offload captures report IP length 0
    assert only_flow(bytes(zero_len)).bytes == len(full)


def test_dns_queries_with_record_types_dpkt_cannot_decode_still_parse() -> None:
    """EDNS (41) and HTTPS (65) records ride along on real queries; only the name matters."""
    payload = f.dns_message(
        "www.example.com",
        [],
        [f.dns_rr("", 41, b"\x00\x0a\x00\x00"), f.dns_rr("x.com", 65, b"\x01\x02")],
        False,
    )
    p, [flow] = parse_one(f.eth(f.ipv4(17, f.udp(40000, 53, payload))))
    assert isinstance(flow, Flow) and flow.dns_query == "www.example.com"
    assert (p.parse_errors, p.payload_errors) == (0, 0)


def test_mdns_responses_with_nsec_records_yield_device_names() -> None:
    """Apple devices announce NSEC (47) records; dpkt rejects the whole packet, we must not."""
    payload = f.dns_message(
        None,
        [
            f.dns_rr("macbook.local", 1, b"\xc0\xa8\x02\x03"),
            f.dns_rr("macbook.local", 47, b"\xc0\x0c\x00\x01\x40"),
        ],
        [],
        True,
    )
    p, events = parse_one(f.eth(f.ipv4(17, f.udp(5353, 5353, payload))))
    assert [e.name for e in events if isinstance(e, MdnsEvent)] == [
        "macbook.local",
        "macbook.local",
    ]
    assert p.payload_errors == 0


def test_dns_answer_with_a_lying_record_length_is_counted_not_fatal() -> None:
    payload = f.dns_message(None, [f.dns_rr("a.local", 1, b"\x01\x02\x03\x04")[:-6]], [], True)
    p, events = parse_one(f.eth(f.ipv4(17, f.udp(5353, 5353, payload))))
    assert len(events) == 1 and isinstance(events[0], Flow) and p.payload_errors == 1


def test_a_payload_cut_off_by_snaplen_is_not_counted_as_garbage() -> None:
    payload = f.dns_message(
        None, [f.dns_rr(f"host{i}.local", 1, b"\x01\x02\x03\x04") for i in range(20)], [], True
    )
    frame = f.eth(f.ipv4(17, f.udp(5353, 5353, payload)))
    p, events = parse_one(frame[:100])
    assert (p.truncated_payloads, p.payload_errors, p.parse_errors) == (1, 0, 0)
    assert len(events) >= 1 and isinstance(events[0], Flow) and events[0].bytes == len(frame)
