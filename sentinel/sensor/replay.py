"""Frames from pcap/pcapng streams and from a live tcpdump pipe. Ethernet link type only."""

import subprocess
from collections.abc import Iterator
from pathlib import Path
from typing import IO

import dpkt

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
LINKTYPE_ETHERNET = dpkt.pcap.DLT_EN10MB


class CaptureError(Exception):
    pass


def read_frames(stream: IO[bytes]) -> Iterator[tuple[float, bytes]]:
    """Yield (timestamp, frame). Raises CaptureError for unreadable or non-Ethernet captures."""
    try:
        head = stream.peek(4)[:4]  # type: ignore[attr-defined]
        if head == PCAPNG_MAGIC:
            ng = dpkt.pcapng.Reader(stream)
            link = ng.datalink()
            reader: Iterator[tuple[float, bytes]] = iter(ng)
        else:
            pc = dpkt.pcap.Reader(stream)
            link = pc.datalink()
            reader = iter(pc)
        if link != LINKTYPE_ETHERNET:
            raise CaptureError(f"unsupported link type {link}; only Ethernet ({LINKTYPE_ETHERNET})")
        yield from reader
    except (dpkt.UnpackError, ValueError, EOFError) as exc:
        raise CaptureError(f"unreadable capture: {exc}") from exc


def read_pcap(path: Path) -> Iterator[tuple[float, bytes]]:
    with path.open("rb") as stream:
        yield from read_frames(stream)


def tcpdump_argv(interface: str, snaplen: int, bpf: str = "") -> list[str]:
    """Interim live source (needs root); sentineld replaces it. No shell is involved."""
    argv = ["tcpdump", "-i", interface, "-n", "-U", "-s", str(snaplen), "-w", "-"]
    return [*argv, bpf] if bpf else argv


def capture_live(argv: list[str]) -> Iterator[tuple[float, bytes]]:
    """Run a capture command that writes pcap to stdout and yield its frames until it exits."""
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:  # noqa: S603
        assert proc.stdout is not None  # noqa: S101 - PIPE was requested
        try:
            yield from read_frames(proc.stdout)
        finally:
            proc.terminate()
        if proc.stderr is not None and (code := proc.wait()) not in (0, -15):
            raise CaptureError(
                f"capture exited {code}: {proc.stderr.read().decode(errors='replace')[:300]}"
            )
