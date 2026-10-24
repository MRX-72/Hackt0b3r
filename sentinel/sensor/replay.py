"""Frames from pcap/pcapng streams and from a live tcpdump pipe, as Ethernet frames."""

import subprocess
import threading
from collections.abc import Iterator
from pathlib import Path
from typing import IO

import dpkt

PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
LINKTYPE_ETHERNET = dpkt.pcap.DLT_EN10MB
# Link types that carry a bare IP packet after a fixed header (loopback, raw IP). Frames from
# these are wrapped in a synthetic Ethernet header so one parser serves every capture.
_IP_LINKS = {0: 4, 108: 4, 12: 0, 101: 0}  # BSD loopback, OpenBSD loopback, raw IP (macOS, Linux)
_ETHERTYPE = {4: b"\x08\x00", 6: b"\x86\xdd"}
_V4_ADDR = (12, 16, 20)  # source start, source end / destination start, destination end
_V6_ADDR = (8, 24, 40)


class CaptureError(Exception):
    pass


def _pseudo_mac(address: bytes) -> bytes:
    """Locally-administered MAC derived from an IP, so devices stay distinguishable without L2."""
    return b"\x02\x00" + address[-4:]


def _wrap_ip_packet(packet: bytes) -> bytes:
    """Ethernet frame around a bare IP packet; empty (counted as malformed) if it is not one."""
    version = packet[0] >> 4 if packet else 0
    layout = {4: _V4_ADDR, 6: _V6_ADDR}.get(version)
    if layout is None or len(packet) < layout[2] + (layout[2] - layout[1]):
        return b""
    start, middle, end = layout
    src, dst = packet[start:middle], packet[middle:end]
    return _pseudo_mac(dst) + _pseudo_mac(src) + _ETHERTYPE[version] + packet


def read_frames(stream: IO[bytes]) -> Iterator[tuple[float, bytes]]:
    """Yield (timestamp, Ethernet frame). Ethernet, loopback and raw-IP captures are supported."""
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
        if link == LINKTYPE_ETHERNET:
            yield from reader
        elif link in _IP_LINKS:
            skip = _IP_LINKS[link]
            for ts, data in reader:
                yield ts, _wrap_ip_packet(data[skip:])
        else:
            raise CaptureError(
                f"unsupported link type {link}; supported: Ethernet, loopback and raw IP"
            )
    except (dpkt.UnpackError, ValueError, EOFError) as exc:
        raise CaptureError(f"unreadable capture: {exc}") from exc


def read_pcap(path: Path) -> Iterator[tuple[float, bytes]]:
    with path.open("rb") as stream:
        yield from read_frames(stream)


def tcpdump_argv(interface: str, snaplen: int, bpf: str = "") -> list[str]:
    """Interim live source (needs root); sentineld replaces it. No shell is involved."""
    argv = ["tcpdump", "-i", interface, "-n", "-U", "-s", str(snaplen), "-w", "-"]
    return [*argv, bpf] if bpf else argv


def capture_live(
    argv: list[str], duration_seconds: float | None = None
) -> Iterator[tuple[float, bytes]]:
    """Run a capture command that writes pcap to stdout and yield its frames until it exits.

    With `duration_seconds` a timer stops the command even when no packets arrive. A command
    that dies before producing a capture (no permission, bad interface) raises CaptureError
    carrying its own error text.
    """
    with subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as proc:  # noqa: S603
        assert proc.stdout is not None and proc.stderr is not None  # noqa: S101 - PIPEs requested
        stopped = threading.Event()

        def stop() -> None:
            stopped.set()
            proc.terminate()

        timer = threading.Timer(duration_seconds, stop) if duration_seconds else None
        if timer:
            timer.start()
        try:
            yield from read_frames(proc.stdout)
        except CaptureError as exc:
            if stopped.is_set():
                return  # we stopped it before it wrote anything
            proc.terminate()
            proc.wait()
            reason = proc.stderr.read().decode(errors="replace").strip()[:300]
            raise CaptureError(f"capture command failed: {reason or exc}") from None
        finally:
            if timer:
                timer.cancel()
            proc.terminate()
        code = proc.wait()
        if code not in (0, -15):
            reason = proc.stderr.read().decode(errors="replace")[:300]
            raise CaptureError(f"capture exited {code}: {reason}")
