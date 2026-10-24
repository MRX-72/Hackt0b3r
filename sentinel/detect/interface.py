"""Detector interface (spec: the one allowed plug-in point for detection logic)."""

from typing import Protocol

from sentinel.contracts.models import Alert
from sentinel.features.windows import HostContext


class Detector(Protocol):
    name: str

    def on_window(self, ctx: HostContext) -> list[Alert]: ...
