"""Ethernet frame -> typed events. Never raises on malformed input; counts what it drops."""

import ipaddress
import struct
from dataclasses import dataclass

import dpkt

from sentinel.contracts.models import (
    ArpEvent,
    DhcpEvent,
    DhcpMsgType,
    Event,
    Flow,
    MdnsEvent,
    Proto,
)

# Errors dpkt raises on short or inconsistent input (its DHCP option loop raises IndexError).
# Anything else is a bug the fuzz tests must find.
_MALFORMED = (dpkt.UnpackError, struct.error, ValueError, IndexError)
_ETHERTYPE_ARP = dpkt.ethernet.ETH_TYPE_ARP
_IP_ETHERTYPES = (dpkt.ethernet.ETH_TYPE_IP, dpkt.ethernet.ETH_TYPE_IP6)
_TCP_FLAG_LETTERS = (
    (dpkt.tcp.TH_FIN, "F"),
    (dpkt.tcp.TH_SYN, "S"),
    (dpkt.tcp.TH_RST, "R"),
    (dpkt.tcp.TH_PUSH, "P"),
    (dpkt.tcp.TH_ACK, "A"),
    (dpkt.tcp.TH_URG, "U"),
    (dpkt.tcp.TH_ECE, "E"),
    (dpkt.tcp.TH_CWR, "C"),
)
_DNS_TYPES = {
    dpkt.dns.DNS_A: "A",
    dpkt.dns.DNS_NS: "NS",
    dpkt.dns.DNS_CNAME: "CNAME",
    dpkt.dns.DNS_PTR: "PTR",
    dpkt.dns.DNS_MX: "MX",
    dpkt.dns.DNS_TXT: "TXT",
    dpkt.dns.DNS_AAAA: "AAAA",
    dpkt.dns.DNS_NULL: "NULL",
    dpkt.dns.DNS_ANY: "ANY",
}
_DHCP_TYPES: dict[int, DhcpMsgType] = {
    dpkt.dhcp.DHCPDISCOVER: "discover",
    dpkt.dhcp.DHCPOFFER: "offer",
    dpkt.dhcp.DHCPREQUEST: "request",
    dpkt.dhcp.DHCPDECLINE: "decline",
    dpkt.dhcp.DHCPACK: "ack",
    dpkt.dhcp.DHCPNAK: "nak",
    dpkt.dhcp.DHCPRELEASE: "release",
    dpkt.dhcp.DHCPINFORM: "inform",
}
_FRAGMENT_PROTOS: dict[int, Proto] = {dpkt.ip.IP_PROTO_TCP: "tcp", dpkt.ip.IP_PROTO_UDP: "udp"}
_DHCP_PORTS = {67, 68}
_ETHERNET_HEADER = 14
_IPV6_HEADER = 40
_DNS_PORT = 53
_MDNS_PORT = 5353
# A multi-record mDNS response can name many hosts; a few suffice to label the sender.
_MDNS_MAX_NAMES = 8


def _mac(raw: bytes) -> str:
    return raw.hex(":")


def _ip(raw: bytes | int) -> str:
    return str(ipaddress.ip_address(raw))


def _tcp_flags(flags: int) -> str:
    return "".join(letter for bit, letter in _TCP_FLAG_LETTERS if flags & bit)


def _l4_protocol(ip: dpkt.ip.IP | dpkt.ip6.IP6) -> tuple[int, bool]:
    """Upper-layer protocol number and whether this is a non-first fragment (no L4 header)."""
    if isinstance(ip, dpkt.ip.IP):
        return ip.p, ip.offset > 0
    chain = ip.all_extension_headers
    later = any(isinstance(h, dpkt.ip6.IP6FragmentHeader) and h.frag_off > 0 for h in chain)
    return (chain[-1].nxt if chain else ip.nxt), later


def _wire_length(ip: dpkt.ip.IP | dpkt.ip6.IP6, captured: int) -> int:
    """Frame size on the wire, from the IP header, so a short snaplen does not shrink byte counts.

    Falls back to the captured size when the header says 0 (segmentation offload) or is smaller
    than what was captured.
    """
    declared = ip.len if isinstance(ip, dpkt.ip.IP) else ip.plen + _IPV6_HEADER
    return max(captured, _ETHERNET_HEADER + declared) if declared else captured


def _text(raw: bytes) -> str:
    return raw.decode("utf-8", errors="replace")


@dataclass
class FrameParser:
    frames: int = 0
    ignored: int = 0
    parse_errors: int = 0
    payload_errors: int = 0

    def parse(self, data: bytes, ts: float) -> list[Event]:
        self.frames += 1
        try:
            eth = dpkt.ethernet.Ethernet(data)
            if eth.type == _ETHERTYPE_ARP:
                return [self._arp(eth, ts)]
            if eth.type in _IP_ETHERTYPES:
                return self._ip(eth, ts, len(data))
        except _MALFORMED:
            self.parse_errors += 1
            return []
        self.ignored += 1
        return []

    @staticmethod
    def _arp(eth: dpkt.ethernet.Ethernet, ts: float) -> ArpEvent:
        arp = eth.data
        if not isinstance(arp, dpkt.arp.ARP) or arp.op not in (
            dpkt.arp.ARP_OP_REQUEST,
            dpkt.arp.ARP_OP_REPLY,
        ):
            raise ValueError("not a valid IPv4-over-Ethernet ARP packet")
        return ArpEvent(
            ts=ts,
            op="request" if arp.op == dpkt.arp.ARP_OP_REQUEST else "reply",
            eth_src_mac=_mac(eth.src),
            sender_mac=_mac(arp.sha),
            sender_ip=_ip(arp.spa),
            target_mac=_mac(arp.tha),
            target_ip=_ip(arp.tpa),
        )

    def _ip(self, eth: dpkt.ethernet.Ethernet, ts: float, length: int) -> list[Event]:
        ip = eth.data
        if not isinstance(ip, dpkt.ip.IP | dpkt.ip6.IP6):
            raise ValueError("ethertype says IP but the packet did not parse")
        proto, later_fragment = _l4_protocol(ip)
        src_port: int | None = None
        dst_port: int | None = None
        flags: str | None = None
        l4 = ip.data
        name: Proto = "other"
        if later_fragment:
            name = _FRAGMENT_PROTOS.get(proto, "other")
        elif proto == dpkt.ip.IP_PROTO_TCP:
            if not isinstance(l4, dpkt.tcp.TCP):
                raise ValueError("truncated TCP header")
            name, src_port, dst_port, flags = "tcp", l4.sport, l4.dport, _tcp_flags(l4.flags)
        elif proto == dpkt.ip.IP_PROTO_UDP:
            if not isinstance(l4, dpkt.udp.UDP):
                raise ValueError("truncated UDP header")
            name, src_port, dst_port = "udp", l4.sport, l4.dport
        elif proto in (dpkt.ip.IP_PROTO_ICMP, dpkt.ip.IP_PROTO_ICMP6):
            name = "icmp"
        flow = Flow(
            ts=ts, src_ip=_ip(ip.src), dst_ip=_ip(ip.dst), src_mac=_mac(eth.src),
            dst_mac=_mac(eth.dst), proto=name, src_port=src_port, dst_port=dst_port,
            bytes=_wire_length(ip, length), packets=1, tcp_flags=flags,
        )  # fmt: skip
        events: list[Event] = [flow]
        if name == "udp" and isinstance(l4, dpkt.udp.UDP):
            events = self._udp_payload(flow, l4, events)
        return events

    def _udp_payload(self, flow: Flow, udp: dpkt.udp.UDP, events: list[Event]) -> list[Event]:
        ports = {udp.sport, udp.dport}
        try:
            if _DNS_PORT in ports:
                return [self._with_query(flow, udp.data)]
            if udp.sport in _DHCP_PORTS and udp.dport in _DHCP_PORTS:
                return [*events, self._dhcp(flow, udp.data)]
            if _MDNS_PORT in ports:
                return [*events, *self._mdns(flow, udp.data)]
        except _MALFORMED:
            self.payload_errors += 1
        return events

    @staticmethod
    def _with_query(flow: Flow, payload: bytes) -> Flow:
        dns = dpkt.dns.DNS(payload)
        if dns.qr == dpkt.dns.DNS_Q and dns.qd:
            question = dns.qd[0]
            qtype = _DNS_TYPES.get(question.type, f"TYPE{question.type}")
            return flow.model_copy(update={"dns_query": question.name.lower(), "dns_qtype": qtype})
        return flow

    @staticmethod
    def _dhcp(flow: Flow, payload: bytes) -> DhcpEvent:
        dhcp = dpkt.dhcp.DHCP(payload)
        options = dict(dhcp.opts)
        raw_type = options.get(dpkt.dhcp.DHCP_OPT_MSGTYPE, b"")
        if len(raw_type) != 1 or raw_type[0] not in _DHCP_TYPES:
            raise ValueError("missing or unknown DHCP message type")
        msg_type = _DHCP_TYPES[raw_type[0]]
        hostname = options.get(dpkt.dhcp.DHCP_OPT_HOSTNAME)
        return DhcpEvent(
            ts=flow.ts, msg_type=msg_type, src_mac=flow.src_mac, src_ip=flow.src_ip,
            client_mac=_mac(dhcp.chaddr[:6]),
            offered_ip=None if dhcp.yiaddr == 0 else _ip(dhcp.yiaddr),
            hostname=None if hostname is None else _text(hostname),
        )  # fmt: skip

    @staticmethod
    def _mdns(flow: Flow, payload: bytes) -> list[MdnsEvent]:
        dns = dpkt.dns.DNS(payload)
        if dns.qr != dpkt.dns.DNS_R:
            return []
        return [
            MdnsEvent(ts=flow.ts, src_mac=flow.src_mac, src_ip=flow.src_ip, name=rr.name)
            for rr in dns.an[:_MDNS_MAX_NAMES]
        ]
