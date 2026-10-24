import io
import sys
from pathlib import Path

import dpkt
import pytest

from sentinel.sensor.parse import FrameParser
from sentinel.sensor.replay import CaptureError, capture_live, read_frames, read_pcap, tcpdump_argv
from tests import scenarios as sc


def test_pcap_roundtrip_preserves_timestamps_and_frames(tmp_path: Path) -> None:
    """R-RPL-001"""
    packets = sc.port_scan(100.25, range(20, 24))
    sc.write_pcap(tmp_path / "a.pcap", packets)
    got = list(read_pcap(tmp_path / "a.pcap"))
    assert [f for _, f in got] == [f for _, f in sorted(packets, key=lambda p: p[0])]
    assert got[0][0] == pytest.approx(100.25, abs=1e-5)


def test_replayed_frames_parse_without_errors(tmp_path: Path) -> None:
    sc.write_pcap(tmp_path / "a.pcap", sc.normal_browsing(0, 60) + sc.dns_tunnel(0, 5))
    parser = FrameParser()
    events = [e for ts, fr in read_pcap(tmp_path / "a.pcap") for e in parser.parse(fr, ts)]
    assert events and parser.parse_errors == 0 and parser.payload_errors == 0


def test_pcapng_is_read(tmp_path: Path) -> None:
    packets = sc.port_scan(10.0, range(20, 22))
    buf = io.BytesIO()
    writer = dpkt.pcapng.Writer(buf)
    for ts, frame in packets:
        writer.writepkt(frame, ts)
    buf.seek(0)
    assert [f for _, f in read_frames(io.BufferedReader(buf))] == [f for _, f in packets]


def test_non_ethernet_link_type_is_rejected_loudly(tmp_path: Path) -> None:
    buf = io.BytesIO()
    dpkt.pcap.Writer(buf, linktype=dpkt.pcap.DLT_NULL).writepkt(b"\x02\x00\x00\x00abcd", 1.0)
    buf.seek(0)
    with pytest.raises(CaptureError, match="link type"):
        list(read_frames(io.BufferedReader(buf)))


def test_garbage_raises_and_torn_tail_is_tolerated(tmp_path: Path) -> None:
    with pytest.raises(CaptureError):
        list(read_frames(io.BufferedReader(io.BytesIO(b"not a pcap at all......"))))
    sc.write_pcap(tmp_path / "t.pcap", sc.port_scan(1.0, range(20, 30)))
    data = (tmp_path / "t.pcap").read_bytes()
    (tmp_path / "t.pcap").write_bytes(data[:-5])
    # A capture killed mid-write is normal: the torn last frame is returned short and the parser
    # counts it, rather than the whole replay failing.
    torn = list(read_pcap(tmp_path / "t.pcap"))
    assert len(torn) == len(sc.port_scan(1.0, range(20, 30)))
    assert len(torn[-1][1]) < len(sc.port_scan(1.0, range(20, 30))[-1][1])


def test_tcpdump_argv_has_no_shell_and_optional_filter() -> None:
    assert tcpdump_argv("bridge100", 384) == [
        "tcpdump",
        "-i",
        "bridge100",
        "-n",
        "-U",
        "-s",
        "384",
        "-w",
        "-",
    ]
    assert tcpdump_argv("en0", 96, "port 22")[-1] == "port 22"


def test_capture_live_streams_from_a_subprocess(tmp_path: Path) -> None:
    sc.write_pcap(tmp_path / "a.pcap", sc.port_scan(1.0, range(20, 25)))
    cmd = [
        sys.executable,
        "-c",
        f"import sys;sys.stdout.buffer.write(open({str(tmp_path / 'a.pcap')!r},'rb').read())",
    ]
    assert len(list(capture_live(cmd))) == len(list(read_pcap(tmp_path / "a.pcap")))


def test_capture_live_reports_a_failing_command() -> None:
    cmd = [sys.executable, "-c", "import sys;sys.stderr.write('permission denied');sys.exit(1)"]
    with pytest.raises(CaptureError):
        list(capture_live(cmd))
