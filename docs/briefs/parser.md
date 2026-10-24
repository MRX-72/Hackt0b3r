# Brief: flow model and packet parser (Stage 1, component 2)

**Purpose:** turn one captured Ethernet frame into zero or more typed events without ever raising on malformed input.

**Inputs/outputs:** `FrameParser.parse(data: bytes, ts: float) -> list[Event]`, `Event = Flow | ArpEvent | DhcpEvent | MdnsEvent` (contracts). Counters on the parser: `frames`, `ignored`, `parse_errors`, `payload_errors`. Library: dpkt (D-010). Ethernet link type only; other link types are the capture/replay components' job.

**Invariants:**
- No exception escapes `parse` for any bytes. Malformed IP/L4/ARP/DHCP -> `parse_errors += 1`, no events. Malformed or truncated DNS/DHCP/mDNS inside a valid UDP packet -> the Flow is still emitted without dns fields or app event, `payload_errors += 1`.
- Well-formed frames never increment error counters. Non-IP/ARP ethertypes -> `ignored`.
- Flow `bytes` is the frame length, `packets` is 1 (aggregation is the window engine's job).
- Network-derived strings (`dns_query`, DHCP hostname, mDNS name) are valid `str`, never raw bytes, and are not sanitised here (the sanitizer owns that). DNS names are lower-cased.
- Only DNS queries (QR=0) populate `dns_query`/`dns_qtype`. DNS over TCP is not parsed (BACKLOG).

**Failure modes:** truncated by snaplen, bad lengths, compression loops, invalid UTF-8 in names, oversize names, ext-header chains. All counted.

**Requirements:** R-FLW-001, R-SAF-006, R-SAF-007 (parser side).

**Tests first:** golden TCP/UDP/ICMP/IPv6 frames built independently with `struct`; flag strings; DNS query/response/qtype; hostile DNS name stored in SQLite; ARP; DHCP offer; mDNS; ignored ethertype; every prefix of every valid frame; hypothesis random bytes and byte-flipped valid frames.

**Out of scope:** pcap reading, link types, flow aggregation, capture filters, sanitisation.
