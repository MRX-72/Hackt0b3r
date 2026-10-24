"""Port scan of your own machine, for trying Sentinel on loopback. Own machine only.

    python tools/localhost_scan.py                       # 400 ports as fast as possible
    python tools/localhost_scan.py --delay 1 --ports 20000-20039   # slow scan, 1 probe a second

It opens a couple of listeners inside the scanned range so the scan sees both open and closed
ports. The target must be a loopback address: anything else is refused.
"""

import argparse
import ipaddress
import socket
import sys
import time

BANNER = "localhost_scan: for scanning YOUR OWN machine's loopback interface only."


def parse_ports(text: str) -> range:
    low, _, high = text.partition("-")
    return range(int(low), int(high or low) + 1)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=BANNER)
    parser.add_argument("--target", default="127.0.0.1")
    parser.add_argument("--ports", default="20000-20399", help="range, e.g. 20000-20399")
    parser.add_argument("--delay", type=float, default=0.0, help="seconds between probes")
    parser.add_argument("--open", default="20080,20443", help="ports to open listeners on")
    args = parser.parse_args(argv)
    print(BANNER)
    if not ipaddress.ip_address(args.target).is_loopback:
        print(f"refusing {args.target}: only loopback addresses are allowed", file=sys.stderr)
        return 2
    listeners = []
    for port in (int(p) for p in args.open.split(",") if p):
        sock = socket.socket()
        sock.bind((args.target, port))
        sock.listen(8)
        listeners.append(sock)
    opened = closed = 0
    started = time.monotonic()
    for port in parse_ports(args.ports):
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex((args.target, port)) == 0:
                opened += 1
            else:
                closed += 1
        time.sleep(args.delay)
    print(f"probed {opened + closed} ports in {time.monotonic() - started:.1f}s: "
          f"{opened} open, {closed} closed")  # fmt: skip
    for sock in listeners:
        sock.close()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
