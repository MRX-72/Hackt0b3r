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
    """(subdomain part, parent domain). Parent = last two labels: wrong for co.uk-style TLDs."""
    labels = name.strip(".").split(".")
    return ".".join(labels[:-2]), ".".join(labels[-2:])


@dataclass
class _Attempt:
    dst_ip: str
    dst_port: int
    state: int = 0  # 0 unanswered, 1 completed, 2 reset


@dataclass
class _Bucket:
    conns: int = 0
    attempts: list[_Attempt] = field(default_factory=list)
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
class _Dest:
    starts: deque[list[float]] = field(default_factory=lambda: deque(maxlen=_DEST_HISTORY))


@dataclass(frozen=True)
class HostContext:
    host_mac: str
    host_ip: str
    now: float
    features: dict[int, WindowFeatures]
    services: dict[int, dict[tuple[str, int], tuple[int, int]]]
    destinations: list[DestinationTiming]


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
        self._latest = 0.0
        self.late_dropped = 0

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
            dest.starts[-1][1] += flow.bytes
        if flow.dns_query:
            self._dns(bucket, flow.dns_query, flow.dns_qtype)
        start = False
        if (
            flow.proto == "tcp"
            and flow.tcp_flags
            and "S" in flow.tcp_flags
            and "A" not in flow.tcp_flags
        ):
            assert flow.src_port is not None and flow.dst_port is not None  # noqa: S101 - tcp has ports
            attempt = _Attempt(flow.dst_ip, flow.dst_port)
            bucket.attempts.append(attempt)
            key = (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port)
            self._pending[key] = (flow.ts, attempt)
            start = True
        elif flow.proto == "udp" and not {flow.src_port, flow.dst_port} & _NON_CONNECTION_UDP_PORTS:
            tuple_key = (flow.dst_ip, flow.src_port or 0, flow.dst_port or 0)
            start = flow.ts - host.udp_flows.get(tuple_key, -math.inf) > self._udp_idle
            host.udp_flows[tuple_key] = flow.ts
        if start:
            bucket.conns += 1
            bucket.targets.add((flow.dst_ip, flow.dst_port or 0))
            if flow.dst_ip not in host.seen_dsts and len(host.seen_dsts) < _SEEN_DST_CAP:
                host.seen_dsts.add(flow.dst_ip)
                bucket.novel += 1
            self._dests.setdefault(dest_key, _Dest()).starts.append([flow.ts, float(flow.bytes)])

    def _inbound(self, flow: Flow) -> None:
        host = self._host(flow.dst_mac, flow.dst_ip, flow.ts)
        self._bucket(host, flow.ts).bytes_in += flow.bytes
        dest = self._dests.get((flow.dst_mac, flow.src_ip, flow.src_port or 0))
        if dest:
            dest.starts[-1][1] += flow.bytes
        if flow.proto == "tcp" and flow.tcp_flags and flow.src_port and flow.dst_port:
            pending = self._pending.get((flow.dst_ip, flow.dst_port, flow.src_ip, flow.src_port))
            if pending and "R" in flow.tcp_flags:
                pending[1].state = 2
            elif pending and "S" in flow.tcp_flags and "A" in flow.tcp_flags:
                pending[1].state = 1

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

    def snapshot(self, now: float) -> list[HostContext]:
        self._evict(now)
        return [self._context(h, now) for h in self._hosts.values()]

    def _evict(self, now: float) -> None:
        oldest = int((now - self._horizon) // BUCKET_SECONDS) + 1
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
            k: d for k, d in self._dests.items() if now - d.starts[-1][0] < _DEST_TTL_SECONDS
        }

    def _context(self, host: _Host, now: float) -> HostContext:
        features: dict[int, WindowFeatures] = {}
        services: dict[int, dict[tuple[str, int], tuple[int, int]]] = {}
        for window in self._windows:
            first = int(now // BUCKET_SECONDS) - window // BUCKET_SECONDS + 1
            buckets = [b for i, b in host.buckets.items() if i >= first]
            features[window], services[window] = self._merge(host, buckets, window, now)
        return HostContext(host.mac, host.ip, now, features, services, self._timings(host.mac, now))

    @staticmethod
    def _merge(
        host: _Host, buckets: list[_Bucket], window: int, now: float
    ) -> tuple[WindowFeatures, dict[tuple[str, int], tuple[int, int]]]:  # fmt: skip
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
        done_count = sum(a.state == 1 for a in attempts)
        features = WindowFeatures(
            host_mac=host.mac, host_ip=host.ip, window_seconds=window, end_ts=now,
            conns_started=sum(b.conns for b in buckets), attempts=len(attempts),
            failed_ratio=(len(attempts) - done_count) / len(attempts) if attempts else 0.0,
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
        return features, services

    def _timings(self, mac: str, now: float) -> list[DestinationTiming]:
        out: list[DestinationTiming] = []
        for (owner, dst_ip, dst_port), dest in self._dests.items():
            starts = [s for s in dest.starts if now - s[0] < _DEST_TTL_SECONDS]
            if owner != mac or len(starts) < _MIN_TIMING_EVENTS:
                continue
            gaps = [b[0] - a[0] for a, b in pairwise(starts)]
            mean = sum(gaps) / len(gaps)
            std = math.sqrt(sum((g - mean) ** 2 for g in gaps) / len(gaps))
            out.append(
                DestinationTiming(
                    dst_ip=dst_ip, dst_port=dst_port, count=len(starts),
                    mean_interval_seconds=mean, interval_cv=std / mean if mean > 0 else math.inf,
                    mean_bytes=sum(s[1] for s in starts) / len(starts),
                )
            )  # fmt: skip
        return out
