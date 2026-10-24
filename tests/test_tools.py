import subprocess
import sys
from pathlib import Path

from sentinel.contracts.models import Flow
from sentinel.sensor.parse import FrameParser
from tests import frames as f
from tools.localhost_attacks import dns_query

SCRIPT = Path(__file__).resolve().parent.parent / "tools/localhost_scan.py"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603
        [sys.executable, str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )


def test_the_scan_script_refuses_anything_but_loopback() -> None:
    for target in ("192.168.2.1", "8.8.8.8", "10.0.0.5"):
        result = run("--target", target, "--ports", "1-3")
        assert result.returncode == 2 and "refusing" in result.stderr


def test_the_scan_script_probes_loopback_and_sees_its_own_listener() -> None:
    result = run("--ports", "20300-20319", "--open", "20305")
    assert result.returncode == 0 and "probed 20 ports" in result.stdout
    assert "1 open, 19 closed" in result.stdout


def test_attack_script_refuses_non_loopback_targets() -> None:
    script = SCRIPT.parent / "localhost_attacks.py"
    for attack in ("scan", "brute", "beacon", "dns", "web"):
        result = subprocess.run(  # noqa: S603
            [sys.executable, str(script), attack, "--host", "192.168.2.1"],
            capture_output=True, text=True, timeout=30, check=False,
        )  # fmt: skip
        assert result.returncode == 2 and "refusing" in result.stderr, attack


def test_the_dns_attack_builds_queries_sentinel_parses_as_tunnel_candidates() -> None:
    name = "a" * 52 + ".t.badzone.test"
    frame = f.eth(f.ipv4(17, f.udp(40000, 53, dns_query(name, 16))))
    [flow] = FrameParser().parse(frame, 1.0)
    assert isinstance(flow, Flow) and (flow.dns_query, flow.dns_qtype) == (name, "TXT")


def test_presenter_script_narrates_each_step_and_refuses_other_targets() -> None:
    script = SCRIPT.parent / "demo_attacks.py"
    ok = subprocess.run(  # noqa: S603
        [sys.executable, str(script), "--auto", "--only", "web", "--scale", "0.05",
         "--countdown", "0", "--settle", "0"],
        capture_output=True, text=True, timeout=60, check=False,
    )  # fmt: skip
    assert ok.returncode == 0
    assert "Performing NORMAL WEB BROWSING (control) on 127.0.0.1" in ok.stdout
    assert "Sentinel should report: NOTHING" in ok.stdout
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
