"""Rule detectors: port scan, brute force, beaconing, DNS tunnelling. Evidence is numeric only."""

from sentinel.config.settings import DetectionSettings
from sentinel.contracts.models import Alert, WindowFeatures
from sentinel.features.windows import HostContext


def _alert(
    ctx: HostContext, detector: str, technique: str, scores: tuple[float, float],
    evidence: dict[str, float],
) -> Alert:  # fmt: skip
    return Alert(
        id=f"{detector}-{ctx.host_mac}-{int(ctx.now)}", ts=ctx.now, detector=detector,
        host_mac=ctx.host_mac, host_ip=ctx.host_ip, severity=min(1.0, scores[0]),
        confidence=min(1.0, scores[1]), evidence=evidence, technique=technique,
    )  # fmt: skip


class PortScan:
    name = "portscan"

    def __init__(self, s: DetectionSettings) -> None:
        self._s = s

    def on_window(self, ctx: HostContext) -> list[Alert]:
        best: tuple[float, WindowFeatures] | None = None
        for window, f in sorted(ctx.features.items()):
            ports = f.unique_dst_ports / self._s.scan_min_unique_ports[window]
            hosts = f.unique_dst_ips / self._s.scan_min_unique_hosts[window]
            excess = max(ports, hosts)
            if excess >= 1 and f.failed_ratio >= self._s.scan_min_failed_ratio:
                best = (excess, f)
                break  # windows ascend: the shortest one that fires shows the attack's pace
        if best is None:
            return []
        excess, f = best
        evidence = {
            "window_seconds": float(f.window_seconds),
            "unique_dst_ports": float(f.unique_dst_ports),
            "unique_dst_ips": float(f.unique_dst_ips), "attempts": float(f.attempts),
            "failed_ratio": f.failed_ratio,
        }  # fmt: skip
        return [_alert(ctx, self.name, "T1046", (0.4 + 0.3 * excess, f.failed_ratio), evidence)]


class BruteForce:
    name = "bruteforce"

    def __init__(self, s: DetectionSettings) -> None:
        self._s = s

    def on_window(self, ctx: HostContext) -> list[Alert]:
        best: tuple[float, int, int, int, int] | None = None  # excess, window, port, attempts, done
        for window, services in sorted(ctx.services.items()):
            for (_, port), (attempts, done) in services.items():
                excess = attempts / self._s.brute_min_attempts[window]
                if (
                    port in self._s.auth_ports and excess >= 1
                    and done / attempts >= self._s.brute_min_completed_ratio
                    and (best is None or (best[1] == window and excess > best[0]))
                ):  # fmt: skip
                    best = (excess, window, port, attempts, done)
            if best is not None:
                break  # shortest window that fires
        if best is None:
            return []
        excess, window, port, attempts, done = best
        evidence = {
            "window_seconds": float(window), "dst_port": float(port), "attempts": float(attempts),
            "completed": float(done),
        }  # fmt: skip
        return [
            _alert(
                ctx, self.name, "T1110", (0.4 + 0.3 * excess, 0.6 + 0.4 * done / attempts), evidence
            )
        ]


class Beaconing:
    name = "beaconing"

    def __init__(self, s: DetectionSettings) -> None:
        self._s = s

    def on_window(self, ctx: HostContext) -> list[Alert]:
        s = self._s
        out = []
        for t in ctx.destinations:
            if (
                t.dst_port not in s.beacon_ignore_ports and t.count >= s.beacon_min_events
                and t.mean_interval_seconds >= s.beacon_min_interval_seconds
                and t.interval_cv <= s.beacon_max_interval_cv
                and t.mean_bytes <= s.beacon_max_mean_bytes
                and t.seconds_since_last <= s.beacon_active_intervals * t.mean_interval_seconds
            ):  # fmt: skip
                evidence = {
                    "dst_port": float(t.dst_port), "count": float(t.count),
                    "mean_interval_seconds": t.mean_interval_seconds,
                    "interval_cv": t.interval_cv, "mean_bytes": t.mean_bytes,
                }  # fmt: skip
                regularity = 1 - t.interval_cv / s.beacon_max_interval_cv
                confidence = 0.5 + 0.5 * min(1.0, t.count / (3 * s.beacon_min_events))
                out.append(
                    _alert(
                        ctx, self.name, "T1071.001", (0.6 + 0.3 * regularity, confidence), evidence
                    )
                )
        return out[:1]  # one alert per host per tick; the evidence names the strongest below


class DnsTunnel:
    name = "dns_tunnel"

    def __init__(self, s: DetectionSettings) -> None:
        self._s = s

    def _signals(self, f: WindowFeatures) -> int:
        s = self._s
        return sum(
            (
                f.dns_mean_entropy >= s.dns_min_entropy,
                f.dns_mean_length >= s.dns_min_mean_length,
                f.dns_max_subdomains_per_parent >= s.dns_min_unique_subdomains,
                f.dns_txt_null_share >= s.dns_min_txt_null_share,
            )
        )

    def on_window(self, ctx: HostContext) -> list[Alert]:
        candidates = [
            (self._signals(f), f)
            for f in ctx.features.values()
            if f.dns_queries >= self._s.dns_min_queries
        ]
        signals, f = max(candidates, key=lambda c: c[0], default=(0, None))
        if f is None or signals < 2:  # noqa: PLR2004 - two independent signals required
            return []
        evidence = {
            "window_seconds": float(f.window_seconds), "dns_queries": float(f.dns_queries),
            "dns_mean_entropy": f.dns_mean_entropy, "dns_mean_length": f.dns_mean_length,
            "dns_max_subdomains_per_parent": float(f.dns_max_subdomains_per_parent),
            "dns_txt_null_share": f.dns_txt_null_share, "signals": float(signals),
        }  # fmt: skip
        return [
            _alert(
                ctx, self.name, "T1071.004", (0.5 + 0.1 * signals, 0.4 + 0.15 * signals), evidence
            )
        ]
