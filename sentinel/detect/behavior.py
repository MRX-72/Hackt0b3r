"""Statistical detector: an Isolation Forest over what each device does in a 10 s window.

It learns "ordinary" from the network's own recent traffic, so it needs a warm-up before it can
say anything, and it reports only "unusual", never a named attack. Vectors it finds unusual are
not added to the baseline, so a long-running oddity cannot teach the forest to ignore it.
"""

from collections import deque

from sentinel.config.settings import MlSettings
from sentinel.contracts.models import Alert, WindowFeatures
from sentinel.features.windows import HostContext
from sentinel.ml.iforest import IsolationForest

TECHNIQUE = "SENT001"  # not an ATT&CK technique: see sentinel.contracts.attack
FEATURES = (
    "conns_started", "attempts", "failed_ratio", "unique_dst_ips", "unique_dst_ports",
    "novel_dsts", "bytes_out", "bytes_in", "dns_queries",
    "share_web", "share_ssh", "share_dns", "share_other",
)  # fmt: skip
# A vector only counts as unusual if one of these beats everything in the baseline by a wide
# margin (more than double, and above a floor that keeps tiny numbers from qualifying).
_FLOORS = {"bytes_out": 100_000.0, "bytes_in": 100_000.0}
_COUNT_FLOOR = 10.0
_COUNTS = ("conns_started", "attempts", "unique_dst_ips", "unique_dst_ports", "novel_dsts",
           "bytes_out", "bytes_in", "dns_queries")  # fmt: skip
_VOLUME = tuple((FEATURES.index(n), _FLOORS.get(n, _COUNT_FLOOR)) for n in _COUNTS)
_REPORTED = 3  # the most unusual features are quoted in the alert


def vector(f: WindowFeatures) -> list[float]:
    return [float(getattr(f, name)) for name in FEATURES]


class BehaviorAnomaly:
    name = "behavior"

    def __init__(self, ml: MlSettings) -> None:
        self._ml = ml
        self._normal: deque[list[float]] = deque(maxlen=ml.if_history)
        self._forest = IsolationForest(
            trees=ml.if_trees, sample_size=ml.if_sample_size, seed=ml.if_seed
        )
        self._fresh = 0  # normal vectors added since the last fit
        self._fitted = False

    def on_window(self, ctx: HostContext) -> list[Alert]:
        f = ctx.features[min(ctx.features)]  # the shortest window is the most responsive
        if f.bytes_out + f.bytes_in + f.conns_started + f.dns_queries == 0:
            return []  # an idle device says nothing about what is normal
        row = vector(f)
        if len(self._normal) < self._ml.if_min_samples:
            self._normal.append(row)
            return []
        if not self._fitted or self._fresh >= self._ml.if_refit_every:
            self._forest.fit(list(self._normal))
            self._fitted, self._fresh = True, 0
        score = self._forest.score(row)
        if score < self._ml.if_threshold or not self._beyond_baseline(row):
            self._normal.append(row)
            self._fresh += 1
            return []
        return [self._alert(ctx, f, row, score)]

    def _beyond_baseline(self, row: list[float]) -> bool:
        """The forest alone over-reports on small, repetitive data (benign random networks made it
        alert), so also require a count or volume far beyond anything in the baseline."""
        return any(row[i] > max(floor, 2 * max(r[i] for r in self._normal)) for i, floor in _VOLUME)

    def _excess(self, index: int, value: float) -> float:
        """How far above the baseline maximum this value is, as a multiple of it (0 if within)."""
        top = max(r[index] for r in self._normal)
        return max(0.0, (value - top) / (top + 1.0))

    def _alert(self, ctx: HostContext, f: WindowFeatures, row: list[float], score: float) -> Alert:
        ranked = sorted(
            (
                (self._excess(i, v), n, v)
                for i, (n, v) in enumerate(zip(FEATURES, row, strict=True))
            ),
            reverse=True,
        )[:_REPORTED]
        evidence = {"window_seconds": float(f.window_seconds), "if_score": score,
                    "baseline_size": float(len(self._normal))}  # fmt: skip
        for excess, name, value in ranked:
            if excess > 0:
                evidence[f"excess_{name}"] = excess
                evidence[f"value_{name}"] = value
        strength = (score - self._ml.if_threshold) / (1.0 - self._ml.if_threshold)
        fullness = len(self._normal) / self._normal.maxlen if self._normal.maxlen else 1.0
        return Alert(
            id=f"{self.name}-{ctx.host_mac}-{int(ctx.now)}", ts=ctx.now, detector=self.name,
            host_mac=ctx.host_mac, host_ip=ctx.host_ip,
            # "unusual" alone never outranks a named attack
            severity=min(0.6, 0.35 + 0.25 * strength),
            confidence=min(0.8, 0.3 + 0.5 * fullness), evidence=evidence, technique=TECHNIQUE,
        )  # fmt: skip
