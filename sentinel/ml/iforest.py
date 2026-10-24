"""Isolation Forest (Liu, Ting, Zhou 2008), pure Python.

Random trees isolate unusual points in fewer splits than ordinary ones; the score is
2^(-average path length / c(n)), near 1 for outliers and below 0.5 for ordinary points. The
feature vectors here have about a dozen numbers and a few hundred rows, so no numeric library
is needed.
"""

import math
import random

_EULER = 0.5772156649

Node = tuple[int, float, "Node", "Node"] | int  # (feature, split, left, right) or leaf size


def _c(n: int) -> float:
    """Average path length of an unsuccessful search in a binary tree of n points."""
    if n <= 1:
        return 0.0
    return 2.0 * (math.log(n - 1) + _EULER) - 2.0 * (n - 1) / n


def _grow(rows: list[list[float]], depth: int, limit: int, rnd: random.Random) -> Node:
    if depth >= limit or len(rows) <= 1:
        return len(rows)
    spread = [
        (i, lo, hi)
        for i in range(len(rows[0]))
        if (lo := min(r[i] for r in rows)) < (hi := max(r[i] for r in rows))
    ]
    if not spread:
        return len(rows)
    feature, lo, hi = rnd.choice(spread)
    split = rnd.uniform(lo, hi)
    left = [r for r in rows if r[feature] < split]
    right = [r for r in rows if r[feature] >= split]
    return (feature, split, _grow(left, depth + 1, limit, rnd), _grow(right, depth + 1, limit, rnd))


def _path(node: Node, row: list[float]) -> float:
    depth = 0.0
    while not isinstance(node, int):
        feature, split, left, right = node
        node = left if row[feature] < split else right
        depth += 1
    return depth + _c(node)


class IsolationForest:
    def __init__(self, trees: int = 100, sample_size: int = 256, seed: int = 0) -> None:
        self._trees, self._sample_size, self._rnd = trees, sample_size, random.Random(seed)  # noqa: S311 - not security
        self._forest: list[Node] = []
        self._norm = 1.0

    def fit(self, rows: list[list[float]]) -> None:
        size = min(self._sample_size, len(rows))
        limit = math.ceil(math.log2(max(size, 2)))
        self._forest = [
            _grow(self._rnd.sample(rows, size), 0, limit, self._rnd) for _ in range(self._trees)
        ]
        self._norm = _c(size) or 1.0

    def score(self, row: list[float]) -> float:
        """0..1, higher = more unusual. 0.0 before the first fit."""
        if not self._forest:
            return 0.0
        mean_path = sum(_path(tree, row) for tree in self._forest) / len(self._forest)
        return float(2.0 ** (-mean_path / self._norm))
