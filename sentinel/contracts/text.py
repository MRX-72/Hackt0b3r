"""Handling of network-derived (hostile) strings, shared by every consumer."""

import re

_UNSAFE_NAME = re.compile(r"[^A-Za-z0-9\-.]")
_CONTROL = re.compile("[\x00-\x1f\x7f-\x9f\u2028\u2029\u202a-\u202e\u2066-\u2069]")


def safe_identifier(value: str, max_length: int = 63) -> str:
    """Hostname-style text for LLM/notification/UI: only [A-Za-z0-9-.], truncated."""
    return _UNSAFE_NAME.sub("", value)[:max_length]


def terminal_safe(value: str, max_length: int = 120) -> str:
    """Escape control and bidi characters so a hostile string cannot drive the terminal."""
    escaped = _CONTROL.sub(lambda m: f"\\x{ord(m.group()):02x}", value)
    return escaped if len(escaped) <= max_length else escaped[: max_length - 1] + "…"
