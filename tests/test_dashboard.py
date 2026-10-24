import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path

import pytest

from raven.cli.dashboard import MIN_COLS, MIN_ROWS, Dashboard, visible_length
from raven.contracts.models import Explanation, Flow, Incident, IncidentReport
from tests import scenarios as sc

MAC = "aa:bb:cc:dd:ee:30"


def report(
    incident_id: str, score: float, headline: str = "Device is probing many network ports",
    chain: tuple[str, ...] = ("T1046",), end_ts: float = 100.0,
) -> IncidentReport:  # fmt: skip
    return IncidentReport(
        incident=Incident(
            id=incident_id, host_mac=MAC, start_ts=end_ts, end_ts=end_ts, alerts=["a"],
            chain=list(chain), score=score,
        ),
        explanation=Explanation(
            headline=headline, what_happened="w", likely_cause="c", action_id="monitor",
            suggested_action="s", confidence_note="n", source="template",
        ),
        deliveries=[],
    )  # fmt: skip


def flow(n: int, dns: str | None = None) -> Flow:
    return Flow(
        ts=1000.0 + n, src_ip="127.0.0.1", dst_ip="127.0.0.1", src_mac=MAC, dst_mac=MAC,
        proto="tcp", src_port=40000 + n, dst_port=22, bytes=60, packets=1, tcp_flags="S",
        dns_query=dns,
    )  # fmt: skip


def dash(cols: int = 100, rows: int = 30, **kw: object) -> Dashboard:
    return Dashboard("test", color=False, size=lambda: (cols, rows), keys=False, **kw)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("cols", "rows"), [(80, 24), (120, 40), (60, 10), (MIN_COLS, MIN_ROWS), (200, 60)]
)
def test_the_frame_always_fills_the_window_exactly(cols: int, rows: int) -> None:
    d = dash(cols, rows)
    for i in range(500):
        d.add_event(flow(i))
    for i in range(5):
        d.add_report(report(f"inc-{i}", 0.99, end_ts=100.0 + i))
    frame = d.frame()
    assert len(frame) == rows
    assert all(visible_length(line) <= cols for line in frame)


def test_a_small_terminal_gets_a_message_instead_of_a_broken_layout() -> None:
    frame = dash(30, 5).frame()
    assert len(frame) == 5 and "terminal too small" in frame[0]
    assert all(visible_length(line) <= 30 for line in frame)


def test_critical_alerts_are_pinned_newest_first_and_stay_pinned_through_heavy_traffic() -> None:
    d = dash(100, 24)
    d.add_report(report("inc-old", 0.99, "Old problem", end_ts=100.0))
    d.add_report(report("inc-new", 0.95, "New problem", end_ts=200.0))
    for i in range(3000):  # a flood of traffic scrolls the stream, never the pins
        d.add_event(flow(i))
    frame = d.frame()
    pinned = [line for line in frame if "CRITICAL" in line and "inc-" in line]
    assert [("New problem" in line, "Old problem" in line) for line in pinned] == [
        (True, False),
        (False, True),
    ]
    assert "PINNED: CRITICAL ALERTS (2)" in frame[1]


def test_every_critical_alert_stacks_even_within_one_incident_and_the_counter_follows() -> None:
    """A scan, then logins, then a tunnel from one device are three criticals, not one."""
    d = dash()
    d.add_report(report("inc-a", 0.99, "Port scan", end_ts=100.0))
    assert "CRIT 1 " in d.frame()[0]
    d.add_report(report("inc-a", 1.0, "Repeated logins", chain=("T1046", "T1110"), end_ts=110.0))
    d.add_report(
        report("inc-a", 1.0, "Unusual DNS", chain=("T1046", "T1110", "T1071.004"), end_ts=120.0)
    )
    frame = d.frame()
    pins = [line for line in frame if line.startswith(" CRITICAL")]
    assert [
        next(h for h in ("Unusual DNS", "Repeated logins", "Port scan") if h in line)
        for line in pins
    ] == [
        "Unusual DNS",
        "Repeated logins",
        "Port scan",
    ]  # all three visible, newest first
    assert "PINNED: CRITICAL ALERTS (3)" in frame[1] and "CRIT 3 " in frame[0]


def test_the_pin_list_is_bounded_but_keeps_the_newest() -> None:
    d = dash(100, 30)
    for i in range(700):
        d.add_report(report(f"inc-{i}", 0.99, f"Problem {i}", end_ts=float(i)))
    assert len(d.pinned_summary()) == 500 and "Problem 699" in d.pinned_summary()[0]
    assert "CRIT 700 " in d.frame()[0]  # the counter still counts all of them


def test_only_critical_incidents_are_pinned_but_every_alert_appears_in_the_stream() -> None:
    d = dash()
    d.add_report(report("inc-m", 0.5, "Medium thing"))
    frame = d.frame()
    assert "PINNED: CRITICAL ALERTS (0)" in frame[1] and "none yet" in frame[2]
    assert any("ALERT [MEDIUM 0.50] Medium thing" in line for line in frame)
    assert "MED 1" in frame[0] and "CRIT 0" in frame[0]


def test_many_pins_are_summarised_so_the_traffic_window_keeps_its_share() -> None:
    d = dash(100, 14)  # 11 free lines: at most 5 for pins
    for i in range(9):
        d.add_report(report(f"inc-{i}", 0.99, f"Problem {i}", end_ts=100.0 + i))
    for i in range(50):
        d.add_event(flow(i))
    frame = d.frame()
    assert len(frame) == 14
    assert any("older critical alerts" in line for line in frame)
    assert "Problem 8" in "\n".join(frame) and sum("RECENT TRAFFIC" in line for line in frame) == 1
    assert sum(" -> " in line for line in frame) >= 4  # criticals take priority, traffic keeps 4


def test_the_traffic_window_slides_and_grows_with_the_terminal() -> None:
    d = dash(100, 12)
    for i in range(100):
        d.add_event(flow(i))
    small = [line for line in d.frame() if " -> " in line]
    assert small and f":{40000 + 99} " in small[-1] and f":{40000 + 0} " not in "".join(small)
    taller = Dashboard("t", color=False, size=lambda: (100, 40), keys=False)
    for i in range(100):
        taller.add_event(flow(i))
    assert len([line for line in taller.frame() if " -> " in line]) > len(small)


def test_clearing_pins_and_hiding_traffic() -> None:
    d = dash()
    d.add_report(report("inc-a", 0.99))
    d.add_event(flow(1))
    d.clear_pins()
    assert "(0)" in d.frame()[1]
    quiet = dash(show_traffic=False)
    quiet.add_event(flow(1))
    quiet.add_report(report("inc-a", 0.5, "Medium thing"))
    text = "\n".join(quiet.frame())
    assert " -> " not in text and "traffic hidden" in text and "Medium thing" in text


@pytest.mark.security
def test_hostile_text_cannot_inject_escape_codes_into_the_screen() -> None:
    d = dash()
    d.add_event(flow(1, dns="a\x1b[2J\x1b]0;pwned\x07.example.com"))
    d.add_report(report("inc-x", 0.99, "Headline\x1b[31m with \x1b[2J codes"))
    assert not any("\x1b" in line for line in d.frame())


def test_with_colour_alerts_are_solid_red_badges_and_traffic_is_dim() -> None:
    d = Dashboard("t", color=True, size=lambda: (100, 24), keys=False)
    d.add_event(flow(1))
    d.add_report(report("inc-a", 0.99))
    frame = "\n".join(d.frame())
    assert "\x1b[1;97;41m CRITICAL 0.99 \x1b[0m" in frame and "\x1b[2m" in frame


def test_the_view_opens_the_alternate_screen_and_restores_the_terminal(tmp_path: Path) -> None:
    """End to end in a real pseudo-terminal: run, see pinned alerts, press q, get a summary."""
    pcap = tmp_path / "scan.pcap"
    sc.write_pcap(pcap, sc.port_scan(100.0, range(1, 401), per_second=400))
    config = tmp_path / "c.toml"
    config.write_text(
        f'database = "{tmp_path / "s.db"}"\nsecrets_file = "{tmp_path / "none.env"}"\n'
    )
    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 90, 0, 0))
    command = [sys.executable, "-m", "raven.cli.main", "--config", str(config)]
    proc = subprocess.Popen(  # noqa: S603
        [*command, "replay", str(pcap), "-d"],
        stdin=slave, stdout=slave, stderr=slave, close_fds=True,
    )  # fmt: skip
    os.close(slave)
    seen = b""
    sent_q = False
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline and proc.poll() is None:
        if select.select([master], [], [], 0.2)[0]:
            try:
                seen += os.read(master, 65536)
            except OSError:
                break
        if not sent_q and b"FINISHED" in seen:
            os.write(master, b"q")
            sent_q = True
    proc.wait(timeout=10)
    while select.select([master], [], [], 0.2)[0]:
        try:
            chunk = os.read(master, 65536)
        except OSError:
            break
        if not chunk:
            break
        seen += chunk
    os.close(master)
    text = seen.decode(errors="replace")
    assert proc.returncode == 0 and sent_q
    assert "\x1b[?1049h" in text and "\x1b[?1049l" in text  # entered and left the alternate screen
    assert "PINNED: CRITICAL ALERTS (1)" in text and "Device is probing many network ports" in text
    after_exit = text.split("\x1b[?1049l")[-1]
    assert "CRITICAL" in after_exit and "frames=" in after_exit  # pins survive on the normal screen
