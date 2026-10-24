import subprocess
import sys
from pathlib import Path

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
