import subprocess
import sys
from pathlib import Path

from raven.contracts.models import Flow
from raven.sensor.parse import FrameParser
from tests import frames as f
from tools.localhost_attacks import dns_query

TOOLS = Path(__file__).resolve().parent.parent / "tools"


def test_attack_script_refuses_non_loopback_targets() -> None:
    script = TOOLS / "localhost_attacks.py"
    for attack in ("scan", "brute", "beacon", "dns", "web"):
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(script), attack, "--host", "192.168.2.1"],
            capture_output=True, text=True, timeout=30, check=False,
        )  # fmt: skip
        assert result.returncode == 2 and "refusing" in result.stderr, attack


def test_the_dns_attack_builds_queries_raven_parses_as_tunnel_candidates() -> None:
    name = "a" * 52 + ".t.badzone.test"
    frame = f.eth(f.ipv4(17, f.udp(40000, 53, dns_query(name, 16))))
    [flow] = FrameParser().parse(frame, 1.0)
    assert isinstance(flow, Flow) and (flow.dns_query, flow.dns_qtype) == (name, "TXT")


def test_presenter_script_narrates_each_step_and_refuses_other_targets() -> None:
    script = TOOLS / "demo_attacks.py"
    ok = subprocess.run(  # noqa: S603
        [sys.executable, str(script), "--auto", "--only", "web", "--scale", "0.05",
         "--countdown", "0", "--settle", "0"],
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert ok.returncode == 0
    assert "Performing NORMAL WEB BROWSING (control) on 127.0.0.1" in ok.stdout
    assert "Raven should report: NOTHING" in ok.stdout
    bad = subprocess.run(  # noqa: S603
        [sys.executable, str(script), "--target", "8.8.8.8", "--auto"],
        capture_output=True, text=True, timeout=30, check=False,
    )  # fmt: skip
    assert bad.returncode == 2 and "refusing" in bad.stderr
    unknown = subprocess.run(  # noqa: S603
        [sys.executable, str(script), "--only", "nuke", "--auto"],
        capture_output=True, text=True, timeout=30, check=False,
    )  # fmt: skip
    assert unknown.returncode == 2 and "unknown attack" in unknown.stderr
