"""Presenter script: run the demo attacks one after another with a clear on-screen narration.

Start the monitor in ANOTHER console first, then:

    python tools/demo_attacks.py                 # press Enter between attacks
    python tools/demo_attacks.py --auto          # no key presses, fixed pauses
    python tools/demo_attacks.py --only scan,dns # pick attacks (scan brute beacon dns web)

Everything targets 127.0.0.1 (anything else is refused). Notifications are not involved.
"""

import argparse
import os
import sys
import time
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import localhost_attacks as atk

MONITOR_HINT = "uv run sentinel --config demo-10s.toml watch --iface lo0 -t"
BAR_WIDTH = 28


@dataclass(frozen=True)
class Step:
    key: str
    title: str
    expect: str
    port: int
    count: int
    interval: float = 0.4


STEPS = [
    Step("scan", "PORT SCAN", "a port scan (T1046): many ports, almost all closed", 20000, 400),
    Step("brute", "SSH BRUTE FORCE", "repeated logins (T1110) against port 2222", 2222, 30),
    Step("beacon", "MALWARE BEACONING", "fixed-interval check-ins (T1071.001)", 8080, 16, 1.0),
    Step("dns", "DNS TUNNELLING", "long random DNS names (T1071.004)", 53, 60),
    Step("web", "NORMAL WEB BROWSING (control)", "NOTHING: normal traffic stays quiet", 8765, 60),
]

USE_COLOR = sys.stdout.isatty() and "NO_COLOR" not in os.environ


def paint(text: str, code: str) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if USE_COLOR else text


class Bar:
    """Single-line progress bar on a terminal; a few milestone lines otherwise."""

    def __init__(self) -> None:
        self._last = -1

    def __call__(self, done: int, total: int) -> None:
        if sys.stdout.isatty():
            filled = BAR_WIDTH * done // total
            sys.stdout.write(f"\r      [{'#' * filled}{'.' * (BAR_WIDTH - filled)}] {done}/{total}")
            sys.stdout.flush()
        elif (quarter := 4 * done // total) != self._last:
            self._last = quarter
            print(f"      {done}/{total}", flush=True)

    @staticmethod
    def finish() -> None:
        if sys.stdout.isatty():
            print()


def countdown(seconds: int, label: str) -> None:
    for left in range(seconds, 0, -1):
        if sys.stdout.isatty():
            sys.stdout.write(f"\r      {label} {left:>2}s ")
            sys.stdout.flush()
        time.sleep(1)
    if sys.stdout.isatty() and seconds:
        sys.stdout.write("\r" + " " * 60 + "\r")


def run_step(index: int, total: int, step: Step, args: argparse.Namespace) -> None:
    count = max(1, round(step.count * args.scale))
    print()
    print(paint(f" [{index}/{total}] Performing {step.title} on {args.target}", "1;36"))
    bar = Bar()
    namespace = argparse.Namespace(
        host=args.target, port=step.port, count=count, interval=step.interval, rate=8.0, report=bar
    )
    try:
        summary = getattr(atk, step.key)(namespace)
    except OSError as exc:
        bar.finish()
        print(paint(f"      could not run ({exc}); is port {step.port} already in use?", "31"))
        return
    bar.finish()
    print(f"      done: {summary}")
    print(paint(f"      Sentinel should report: {step.expect}", "33"))


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument("--target", default=atk.LOOPBACK, help="must be a loopback address")
    parser.add_argument("--only", default="", help="comma list: " + ",".join(s.key for s in STEPS))
    parser.add_argument("--auto", action="store_true", help="no key presses; use --settle pauses")
    parser.add_argument("--settle", type=int, default=12, help="seconds to let the monitor report")
    parser.add_argument("--countdown", type=int, default=5, help="seconds before the first attack")
    parser.add_argument("--scale", type=float, default=1.0, help="scale attack sizes (rehearsal)")
    args = parser.parse_args(argv)
    if not atk.is_loopback(args.target):
        print(f"refusing {args.target}: only loopback addresses are allowed", file=sys.stderr)
        return 2
    wanted = [k for k in args.only.split(",") if k]
    unknown = set(wanted) - {s.key for s in STEPS}
    if unknown:
        print(f"unknown attack(s): {', '.join(sorted(unknown))}", file=sys.stderr)
        return 2
    steps = [s for s in STEPS if not wanted or s.key in wanted]
    atk.QUIET = True

    print(paint(" Sentinel demo attacks", "1"), f" target {args.target} (loopback only)")
    print(f" Start the monitor in another console:  {paint(MONITOR_HINT, '1')}")
    if args.auto:
        countdown(args.countdown, "starting in")
    else:
        input(" Press Enter when the monitor is running... ")
    for index, step in enumerate(steps, 1):
        run_step(index, len(steps), step, args)
        if index < len(steps):
            countdown(args.settle, "letting the monitor report:")
            if not args.auto:
                input("      Press Enter for the next attack... ")
    print()
    print(paint(" All attacks finished.", "1"), "Review them with:  uv run sentinel incidents")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
