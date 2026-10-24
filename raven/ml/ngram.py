"""Character trigram model of "pronounceable" DNS names.

Trained once on a small seed of ordinary words and service names. A tunnel or DGA name is
random-looking, so each of its character sequences is rare in the seed and its surprisal (average
bits per character) is high. Pure Python, no files, deterministic.
"""

import math
from collections import Counter

from raven.ml.corpus import WORDS

_ORDER = 3
_SMOOTHING = 0.05
_ALPHABET = 38  # a-z, 0-9, "-" and the end marker


class NgramModel:
    def __init__(self, words: list[str]) -> None:
        self._context: Counter[str] = Counter()
        self._grams: Counter[str] = Counter()
        for word in words:
            padded = "^" * (_ORDER - 1) + word + "$"
            for i in range(_ORDER - 1, len(padded)):
                self._grams[padded[i - _ORDER + 1 : i + 1]] += 1
                self._context[padded[i - _ORDER + 1 : i]] += 1

    def surprisal(self, name: str) -> float:
        """Mean bits per character over the dot-separated labels of `name` (0.0 if empty)."""
        bits, chars = 0.0, 0
        for label in name.lower().split("."):
            padded = "^" * (_ORDER - 1) + label + "$"
            for i in range(_ORDER - 1, len(padded)):
                gram, ctx = padded[i - _ORDER + 1 : i + 1], padded[i - _ORDER + 1 : i]
                p = (self._grams[gram] + _SMOOTHING) / (self._context[ctx] + _SMOOTHING * _ALPHABET)
                bits -= math.log2(p)
                chars += 1
        return bits / chars if chars else 0.0


DEFAULT = NgramModel(WORDS)
