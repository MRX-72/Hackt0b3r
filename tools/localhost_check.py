"""Run all four attacks against your own loopback with ONLY the 10-second window enabled.

    uv run python tools/localhost_check.py

For each attack it starts `sentinel watch --iface lo0` (no --notify, notifications off), runs
tools/localhost_attacks.py against 127.0.0.1, then reads back what Sentinel stored. A control
run of ordinary web traffic must raise nothing. Prints a markdown table; exit 0 if all pass.
"""

import json
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ATTACK_SCRIPT = ROOT / "tools/localhost_attacks.py"
CONFIG = """database = "{db}"
secrets_file = "{secrets}"

[notify]
enabled = false

[detection]
windows = [10]                      # the 10-second window only
scan_min_unique_ports = {{ 10 = 20 }}
scan_min_unique_hosts = {{ 10 = 20 }}
brute_min_attempts = {{ 10 = 8 }}
auth_ports = [21, 22, 23, 445, 2222, 3389, 5900]   # 2222: fake SSH (ports < 1024 need root)
"""
# name, expected detector (None = must stay silent), seconds to capture
CASES = [
    ("port scan", "portscan", "scan", 20),
    ("brute force", "bruteforce", "brute", 26),
    ("beaconing", "beaconing", "beacon", 30),
    ("dns tunnel", "dns_tunnel", "dns", 22),
    ("control: web browsing", None, "web", 32),
]


@dataclass
class Result:
    name: str
    expected: str | None
    detectors: list[str]
    window: str
    delay: str
    evidence: str
    severity: str
    summary: str

    @property
    def passed(self) -> bool:
        want = [self.expected] if self.expected else []
        return self.detectors == want


def attack_start(stdout: str) -> float:
    """Unix time the attack script printed when it began, or 0."""
    for line in stdout.splitlines():
        if line.startswith("ATTACK_START"):
            return float(line.split()[1])
    return 0.0


def wait_until_capturing(watch: subprocess.Popen[str], timeout: float = 15.0) -> None:
    """Block until sentinel has started tcpdump, so no early attack packets are missed."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        child = subprocess.run(  # noqa: S603
            ["/usr/bin/pgrep", "-P", str(watch.pid), "tcpdump"], capture_output=True, check=False
        )
        if child.returncode == 0:
            time.sleep(1.0)  # tcpdump is up; give it a moment to open the interface
            return
        time.sleep(0.2)
    raise RuntimeError("sentinel did not start tcpdump within 15 s")


def sentinel(config: Path, *args: str) -> subprocess.Popen[str]:
    cmd = [sys.executable, "-m", "sentinel.cli.main", "--config", str(config), "--json", *args]
    return subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)  # noqa: S603


def run_case(workdir: Path, name: str, expected: str | None, attack: str, seconds: int) -> Result:
    secrets = workdir / "none.env"
    config = workdir / f"{attack}.toml"
    config.write_text(CONFIG.format(db=workdir / f"{attack}.db", secrets=secrets))
    watch = sentinel(config, "watch", "--iface", "lo0", "--for", f"{seconds}s")
    wait_until_capturing(watch)
    attack_run = subprocess.run(  # noqa: S603
        [sys.executable, str(ATTACK_SCRIPT), attack], capture_output=True, text=True, check=False
    )
    started = attack_start(attack_run.stdout)
    out, err = watch.communicate(timeout=seconds + 30)
    lines = [json.loads(line) for line in out.splitlines() if line.startswith("{")]
    summary = next((line["summary"] for line in lines if "summary" in line), {})
    alerts: list[dict[str, object]] = []
    for report in (line["report"] for line in lines if "report" in line):
        detail = subprocess.run(  # noqa: S603
            [sys.executable, "-m", "sentinel.cli.main", "--config", str(config), "--json",
             "incident", report["incident"]["id"]],
            capture_output=True, text=True, check=False,
        )  # fmt: skip
        alerts += json.loads(detail.stdout)["alerts"]
    if err.strip():
        print(f"[{name}] stderr: {err.strip()}", file=sys.stderr)
    first = min(alerts, key=lambda a: float(str(a["ts"])), default=None)
    evidence = dict(first["evidence"]) if first else {}  # type: ignore[call-overload]
    window = evidence.get("window_seconds")
    return Result(
        name=name,
        expected=expected,
        detectors=sorted(str(a["detector"]) for a in alerts),
        window=f"{int(window)} s" if window else ("-" if not first else "n/a (not windowed)"),
        delay=f"{float(str(first['ts'])) - started:.1f} s" if first else "-",
        evidence=", ".join(f"{k}={v:g}" for k, v in sorted(evidence.items())),
        severity=f"{float(str(first['severity'])):.2f}" if first else "-",
        summary=f"{summary.get('frames', 0)} frames, {summary.get('alerts', 0)} alerts",
    )


def main() -> int:
    with tempfile.TemporaryDirectory() as tmp:
        results = [run_case(Path(tmp), *case) for case in CASES]
    print("| attack | expected | detected | window | delay | severity | result | evidence |")
    print("|---|---|---|---|---|---|---|---|")
    for r in results:
        verdict = "PASS" if r.passed else "FAIL"
        row = [r.name, r.expected or "nothing", ", ".join(r.detectors) or "nothing", r.window,
               r.delay, r.severity, verdict, r.evidence]  # fmt: skip
        print("| " + " | ".join(row) + " |")
    return 0 if all(r.passed for r in results) else 1


if __name__ == "__main__":
    sys.exit(main())
