"""Per-host multi-timescale feature windows built from 10 s buckets (event time)."""

import math
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from itertools import pairwise

from sentinel.config.settings import BUCKET_SECONDS, DetectionSettings
from sentinel.contracts.models import DestinationTiming, Event, Flow, WindowFeatures

# Bounds so a hostile or noisy network cannot grow memory without limit.
_SEEN_DST_CAP = 10_000
_SUBDOMAIN_CAP = 512  # distinct subdomains remembered per parent domain per bucket
_DEST_HISTORY = 128  # connection starts remembered per destination
_PENDING_TTL_SECONDS = 120.0  # how long a SYN waits for its SYN-ACK/RST
# A repeat SYN on the same 4-tuple within this time is a TCP retransmission, not a new attempt.
_RETRANSMIT_SECONDS = 30.0
_PARENT_CAP = 50_000  # distinct DNS parent domains remembered for popularity
# Hard bounds on state a flood (SYN flood, huge scan) could otherwise grow without limit. Hitting
# one is counted in `state_capped`; counts above the cap are far past every detection threshold.
_MAX_ATTEMPTS_PER_BUCKET = 5_000
_MAX_TARGETS_PER_BUCKET = 20_000
_MAX_PENDING = 100_000
_MAX_DESTINATIONS = 50_000
_MAX_UDP_FLOWS_PER_HOST = 20_000
# Common two-level public suffixes, so "bbc.co.uk" is not grouped with every other .co.uk site.
# ponytail: a short built-in list instead of the full Public Suffix List; add entries as needed.
_TWO_LEVEL_SUFFIXES = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp",
    "or.jp", "com.br", "com.cn", "com.hk", "com.sg", "com.tw", "com.mx", "com.tr", "co.kr",
    "co.in", "co.za", "co.il", "com.ar", "com.co",
})  # fmt: skip
_DEST_TTL_SECONDS = 3600.0
_MIN_TIMING_EVENTS = 3  # fewer starts give no meaningful interval statistics
_WEB_PORTS = frozenset({80, 443, 8080, 8443})
_NON_CONNECTION_UDP_PORTS = frozenset({53, 5353})
_TXT, _NULL = "TXT", "NULL"

AttemptKey = tuple[str, int, str, int]


def shannon_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts = Counter(text)
    return -sum(n / len(text) * math.log2(n / len(text)) for n in counts.values())


def split_name(name: str) -> tuple[str, str]:
    """(subdomain part, parent domain): the registrable domain, e.g. ("a.b", "example.co.uk")."""
    labels = name.strip(".").split(".")
    keep = 3 if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES else 2
    return ".".join(labels[:-keep]), ".".join(labels[-keep:])


@dataclass
class _Attempt:
    dst_ip: str
    dst_port: int
    state: int = 0  # 0 unanswered, 1 completed, 2 reset


@dataclass
class _Bucket:
    conns: int = 0
    attempts: list[_Attempt] = field(default_factory=list)
    overflow_attempts: int = 0  # attempts past the cap: counted, assumed unanswered
    targets: set[tuple[str, int]] = field(default_factory=set)
    novel: int = 0
    bytes_out: int = 0
    bytes_in: int = 0
    packets_by_class: Counter[str] = field(default_factory=Counter)
    dns_queries: int = 0
    dns_length_sum: int = 0
    dns_entropy_sum: float = 0.0
    dns_entropy_max: float = 0.0
    dns_txt_null: int = 0
    subdomains: dict[str, set[str]] = field(default_factory=dict)


@dataclass
class _Host:
    mac: str
    ip: str
    last_seen: float
    buckets: dict[int, _Bucket] = field(default_factory=dict)
    seen_dsts: set[str] = field(default_factory=set)
    udp_flows: dict[tuple[str, int, int], float] = field(default_factory=dict)


@dataclass
class _Start:
    ts: float
    bytes: float
    attempt: "_Attempt | None"  # None for UDP, where completion is not observable


@dataclass
class _Dest:
    starts: deque[_Start] = field(default_factory=lambda: deque(maxlen=_DEST_HISTORY))


@dataclass(frozen=True)
class HostContext:
    host_mac: str
    host_ip: str
    now: float
    features: dict[int, WindowFeatures]
    services: dict[int, dict[tuple[str, int], tuple[int, int]]]
    destinations: list[DestinationTiming]
    # window -> (parent domain with the most distinct subdomains, how many hosts query it)
    dns_top: dict[int, tuple[str, int]]


def _service_class(port: int | None) -> str:
    if port in _WEB_PORTS:
        return "web"
    return {22: "ssh", 53: "dns"}.get(port, "other") if port is not None else "other"


class WindowEngine:
    def __init__(self, settings: DetectionSettings) -> None:
        self._windows = settings.windows
        self._horizon = max(settings.windows)
        self._udp_idle = float(
            BUCKET_SECONDS
        )  # a quiet UDP 5-tuple this long starts a new "connection"
        self._hosts: dict[str, _Host] = {}
        self._pending: dict[AttemptKey, tuple[float, _Attempt]] = {}
        self._dests: dict[tuple[str, str, int], _Dest] = {}
        self._dest_hosts: dict[tuple[str, int], dict[str, float]] = {}  # (ip, port) -> mac -> last
        self._parent_hosts: dict[str, dict[str, float]] = {}  # DNS parent -> mac -> last query
        self._latest = 0.0
        self.late_dropped = 0
        self.state_capped = 0

    @property
    def host_count(self) -> int:
        return len(self._hosts)

    def observe(self, event: Event) -> None:
        if not isinstance(event, Flow):
            return
        if event.ts < self._latest - self._horizon:
            self.late_dropped += 1
            return
        self._latest = max(self._latest, event.ts)
        self._outbound(event)
        self._inbound(event)

    def _host(self, mac: str, ip: str, ts: float) -> _Host:
        host = self._hosts.setdefault(mac, _Host(mac, ip, ts))
        host.ip, host.last_seen = ip, max(host.last_seen, ts)
        return host

    def _bucket(self, host: _Host, ts: float) -> _Bucket:
        return host.buckets.setdefault(int(ts // BUCKET_SECONDS), _Bucket())

    def _outbound(self, flow: Flow) -> None:
        host = self._host(flow.src_mac, flow.src_ip, flow.ts)
        bucket = self._bucket(host, flow.ts)
        bucket.bytes_out += flow.bytes
        bucket.packets_by_class[_service_class(flow.dst_port)] += 1
        dest_key = (flow.src_mac, flow.dst_ip, flow.dst_port or 0)
        if dest := self._dests.get(dest_key):
            dest.starts[-1].bytes += flow.bytes
        if flow.dns_query:
            self._dns(bucket, flow.dns_query, flow.dns_qtype)
            self._note_parent(flow.dns_query, host.mac, flow.ts)
        attempt: _Attempt | None = None
        start = False
        if (
            flow.proto == "tcp"
            and flow.tcp_flags
            and "S" in flow.tcp_flags
            and "A" not in flow.tcp_flags
        ):
            assert flow.src_port is not None and flow.dst_port is not None  # noqa: S101 - tcp has ports
            key = (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port)
            known = self._pending.get(key)
            if known and known[1].state == 0 and flow.ts - known[0] < _RETRANSMIT_SECONDS:
                return  # a retransmitted SYN: same attempt, not a new connection
            if (
                len(bucket.attempts) < _MAX_ATTEMPTS_PER_BUCKET
                and len(self._pending) < _MAX_PENDING
            ):
                attempt = _Attempt(flow.dst_ip, flow.dst_port)
                bucket.attempts.append(attempt)
                self._pending[key] = (flow.ts, attempt)
            else:
                bucket.overflow_attempts += 1
                self.state_capped += 1
            start = True
        elif (
            flow.proto == "udp"
            and not {flow.src_port, flow.dst_port} & _NON_CONNECTION_UDP_PORTS
            and (flow.src_port or 0) > (flow.dst_port or 0)  # client -> service, not a reply
        ):
            tuple_key = (flow.dst_ip, flow.src_port or 0, flow.dst_port or 0)
            start = flow.ts - host.udp_flows.get(tuple_key, -math.inf) > self._udp_idle
            if len(host.udp_flows) < _MAX_UDP_FLOWS_PER_HOST or tuple_key in host.udp_flows:
                host.udp_flows[tuple_key] = flow.ts
        if start:
            bucket.conns += 1
            if len(bucket.targets) < _MAX_TARGETS_PER_BUCKET:
                bucket.targets.add((flow.dst_ip, flow.dst_port or 0))
            if flow.dst_ip not in host.seen_dsts and len(host.seen_dsts) < _SEEN_DST_CAP:
                host.seen_dsts.add(flow.dst_ip)
                bucket.novel += 1
            self._track_destination(dest_key, host.mac, _Start(flow.ts, float(flow.bytes), attempt))

    def _inbound(self, flow: Flow) -> None:
        host = self._host(flow.dst_mac, flow.dst_ip, flow.ts)
        self._bucket(host, flow.ts).bytes_in += flow.bytes
        dest = self._dests.get((flow.dst_mac, flow.src_ip, flow.src_port or 0))
        if dest:
            dest.starts[-1].bytes += flow.bytes
        if flow.proto == "tcp" and flow.tcp_flags and flow.src_port and flow.dst_port:
            pending = self._pending.get((flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port))
            # Only the first answer counts: a server resetting a connection it already accepted
            # (common after a failed login) must not turn that completed attempt into a failure.
            if pending and pending[1].state == 0:
                if "R" in flow.tcp_flags:
                    pending[1].state = 2
                elif "S" in flow.tcp_flags and "A" in flow.tcp_flags:
                    pending[1].state = 1

    def _track_destination(self, dest_key: tuple[str, str, int], mac: str, start: _Start) -> None:
        shared_key = (dest_key[1], dest_key[2])
        if dest_key not in self._dests and len(self._dests) >= _MAX_DESTINATIONS:
            self.state_capped += 1
            return
        self._dests.setdefault(dest_key, _Dest()).starts.append(start)
        if shared_key in self._dest_hosts or len(self._dest_hosts) < _MAX_DESTINATIONS:
            self._dest_hosts.setdefault(shared_key, {})[mac] = start.ts

    def _note_parent(self, name: str, mac: str, ts: float) -> None:
        parent = split_name(name)[1]
        if parent in self._parent_hosts or len(self._parent_hosts) < _PARENT_CAP:
            self._parent_hosts.setdefault(parent, {})[mac] = ts

    @staticmethod
    def _dns(bucket: _Bucket, name: str, qtype: str | None) -> None:
        sub, parent = split_name(name)
        entropy = shannon_entropy(sub or name.split(".", 1)[0])
        bucket.dns_queries += 1
        bucket.dns_length_sum += len(name)
        bucket.dns_entropy_sum += entropy
        bucket.dns_entropy_max = max(bucket.dns_entropy_max, entropy)
        bucket.dns_txt_null += qtype in (_TXT, _NULL)
        names = bucket.subdomains.setdefault(parent, set())
        if len(names) < _SUBDOMAIN_CAP:
            names.add(sub or name)

    @staticmethod
    def _last_bucket(now: float) -> int:
        """Newest bucket a window ending at `now` covers; a boundary time ends the bucket before."""
        return math.ceil(now / BUCKET_SECONDS) - 1

    def snapshot(self, now: float) -> list[HostContext]:
        self._evict(now)
        return [self._context(h, now) for h in self._hosts.values()]

    def _evict(self, now: float) -> None:
        oldest = self._last_bucket(now) - self._horizon // BUCKET_SECONDS + 1
        for mac in list(self._hosts):
            host = self._hosts[mac]
            host.buckets = {i: b for i, b in host.buckets.items() if i >= oldest}
            host.udp_flows = {k: t for k, t in host.udp_flows.items() if now - t < self._horizon}
            if not host.buckets:
                del self._hosts[mac]
        self._pending = {
            k: v for k, v in self._pending.items() if now - v[0] < _PENDING_TTL_SECONDS
        }
        self._dests = {
            k: d for k, d in self._dests.items() if now - d.starts[-1].ts < _DEST_TTL_SECONDS
        }
        self._dest_hosts = self._recent(self._dest_hosts, now)
        self._parent_hosts = self._recent(self._parent_hosts, now)

    def _recent[K](self, table: dict[K, dict[str, float]], now: float) -> dict[K, dict[str, float]]:
        """Drop host entries not seen within the longest window, and empty keys."""
        kept = {
            key: {mac: t for mac, t in hosts.items() if now - t < self._horizon}
            for key, hosts in table.items()
        }
        return {key: hosts for key, hosts in kept.items() if hosts}

    def _context(self, host: _Host, now: float) -> HostContext:
        features: dict[int, WindowFeatures] = {}
        services: dict[int, dict[tuple[str, int], tuple[int, int]]] = {}
        dns_top: dict[int, tuple[str, int]] = {}
        for window in self._windows:
            first = self._last_bucket(now) - window // BUCKET_SECONDS + 1
            buckets = [b for i, b in host.buckets.items() if i >= first]
            features[window], services[window], top = self._merge(host, buckets, window, now)
            if top is not None:
                dns_top[window] = (top, len(self._parent_hosts.get(top, {})))
        timings = self._timings(host.mac, now)
        return HostContext(host.mac, host.ip, now, features, services, timings, dns_top)

    @staticmethod
    def _merge(
        host: _Host, buckets: list[_Bucket], window: int, now: float
    ) -> tuple[WindowFeatures, dict[tuple[str, int], tuple[int, int]], str | None]:  # fmt: skip
        attempts = [a for b in buckets for a in b.attempts]
        services: dict[tuple[str, int], tuple[int, int]] = {}
        for a in attempts:
            total, done = services.get((a.dst_ip, a.dst_port), (0, 0))
            services[(a.dst_ip, a.dst_port)] = (total + 1, done + (a.state == 1))
        targets = set().union(*(b.targets for b in buckets)) if buckets else set()
        parents: dict[str, set[str]] = {}
        for b in buckets:
            for parent, subs in b.subdomains.items():
                parents.setdefault(parent, set()).update(subs)
        queries = sum(b.dns_queries for b in buckets)
        classes: Counter[str] = Counter()
        for b in buckets:
            classes.update(b.packets_by_class)
        packets = sum(classes.values())
        total = len(attempts) + sum(b.overflow_attempts for b in buckets)
        done_count = sum(a.state == 1 for a in attempts)
        targets_seen = Counter(a.dst_ip for a in attempts)
        features = WindowFeatures(
            host_mac=host.mac, host_ip=host.ip, window_seconds=window, end_ts=now,
            conns_started=sum(b.conns for b in buckets), attempts=total,
            failed_ratio=(total - done_count) / total if total else 0.0,
            top_target_ip=targets_seen.most_common(1)[0][0] if targets_seen else None,
            unique_dst_ips=len({t[0] for t in targets}),
            unique_dst_ports=len({t[1] for t in targets}),
            novel_dsts=sum(b.novel for b in buckets),
            bytes_out=sum(b.bytes_out for b in buckets), bytes_in=sum(b.bytes_in for b in buckets),
            dns_queries=queries,
            dns_unique_subdomains=sum(len(s) for s in parents.values()),
            dns_max_subdomains_per_parent=max((len(s) for s in parents.values()), default=0),
            dns_mean_entropy=sum(b.dns_entropy_sum for b in buckets) / queries if queries else 0.0,
            dns_max_entropy=max((b.dns_entropy_max for b in buckets), default=0.0),
            dns_mean_length=sum(b.dns_length_sum for b in buckets) / queries if queries else 0.0,
            dns_txt_null_share=sum(b.dns_txt_null for b in buckets) / queries if queries else 0.0,
            share_web=classes["web"] / packets if packets else 0.0,
            share_ssh=classes["ssh"] / packets if packets else 0.0,
            share_dns=classes["dns"] / packets if packets else 0.0,
            share_other=classes["other"] / packets if packets else 0.0,
            hour_of_day=time.localtime(now).tm_hour,
        )  # fmt: skip
        top_parent = max(parents, key=lambda p: len(parents[p]), default=None)
        return features, services, top_parent

    def _timings(self, mac: str, now: float) -> list[DestinationTiming]:
        out: list[DestinationTiming] = []
        for (owner, dst_ip, dst_port), dest in self._dests.items():
            starts = [s for s in dest.starts if now - s.ts < _DEST_TTL_SECONDS]
            if owner != mac or len(starts) < _MIN_TIMING_EVENTS:
                continue
            gaps = [b.ts - a.ts for a, b in pairwise(starts)]
            completed = [s for s in starts if s.attempt is None or s.attempt.state == 1]
            popularity = len(self._dest_hosts.get((dst_ip, dst_port), {}))
            mean = sum(gaps) / len(gaps)
            std = math.sqrt(sum((g - mean) ** 2 for g in gaps) / len(gaps))
            out.append(
                DestinationTiming(
                    dst_ip=dst_ip, dst_port=dst_port, count=len(starts),
                    mean_interval_seconds=mean, interval_cv=std / mean if mean > 0 else math.inf,
                    mean_bytes=sum(s.bytes for s in starts) / len(starts),
                    seconds_since_last=now - starts[-1].ts,
                    completed_ratio=len(completed) / len(starts), popularity=popularity,
                )
            )  # fmt: skip
        return out
