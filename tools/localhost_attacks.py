"""Attacks against YOUR OWN machine's loopback interface, for trying Sentinel. Own machine only.

    python tools/localhost_attacks.py scan      # port scan: 400 ports in about a second
    python tools/localhost_attacks.py brute     # password guessing against a fake SSH-like service
    python tools/localhost_attacks.py beacon    # check-ins to a fake C2 server, once a second
    python tools/localhost_attacks.py dns       # DNS tunnelling: long random TXT lookups
    python tools/localhost_attacks.py web       # control: ordinary web requests (must NOT alert)

Every target is 127.0.0.1 (anything else is refused). Fake servers run inside the script.
Each command prints `ATTACK_START <unix time>` so detection delay can be measured.
"""

import argparse
import ipaddress
import random
import socket
import struct
import sys
import threading
import time
import urllib.request
from collections.abc import Callable

BANNER = "localhost_attacks: for attacking YOUR OWN machine's loopback interface only."
LOOPBACK = "127.0.0.1"
ALPHABET = "abcdefghijklmnopqrstuvwxyz234567"  # base32, what real DNS tunnels use


def is_loopback(host: str) -> bool:
    return ipaddress.ip_address(host).is_loopback


def serve(port: int, handler: Callable[[socket.socket], object]) -> socket.socket:
    """Start a tiny TCP server in the background; handler(conn) runs per connection."""
    server = socket.socket()
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((LOOPBACK, port))
    server.listen(64)

    def loop() -> None:
        while True:
            try:
                conn, _ = server.accept()
            except OSError:
                return
            threading.Thread(target=handler, args=(conn,), daemon=True).start()

    threading.Thread(target=loop, daemon=True).start()
    return server


def start() -> None:
    print(f"ATTACK_START {time.time():.3f}", flush=True)


def scan(args: argparse.Namespace) -> None:
    listener = serve(args.port + 80, lambda c: c.close())  # one open port inside the range
    start()
    opened = closed = 0
    for port in range(args.port, args.port + 400):
        with socket.socket() as probe:
            probe.settimeout(0.5)
            if probe.connect_ex((LOOPBACK, port)) == 0:
                opened += 1
            else:
                closed += 1
    listener.close()
    print(f"probed 400 ports: {opened} open, {closed} closed")


def brute(args: argparse.Namespace) -> None:
    def fake_ssh(conn: socket.socket) -> None:
        with conn:
            conn.sendall(b"SSH-2.0-FakeSSH\r\n")
            conn.recv(256)
            conn.sendall(b"Permission denied\r\n")

    server = serve(args.port, fake_ssh)
    start()
    for i in range(args.count):
        with socket.create_connection((LOOPBACK, args.port), timeout=2) as sock:
            sock.recv(64)
            sock.sendall(f"root:not-the-password-{i}\r\n".encode())
            sock.recv(64)
        time.sleep(args.interval)
    server.close()
    print(f"made {args.count} failed logins to 127.0.0.1:{args.port}")


def beacon(args: argparse.Namespace) -> None:
    def fake_c2(conn: socket.socket) -> None:
        with conn:
            conn.recv(256)
            conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")

    server = serve(args.port, fake_c2)
    start()
    begin = time.monotonic()
    for i in range(args.count):
        time.sleep(max(0.0, begin + i * args.interval - time.monotonic()))  # no drift
        with socket.create_connection((LOOPBACK, args.port), timeout=2) as sock:
            sock.sendall(b"GET /tick HTTP/1.1\r\nHost: c2.invalid\r\n\r\n")
            sock.recv(128)
    server.close()
    print(f"sent {args.count} check-ins, one every {args.interval}s, to 127.0.0.1:{args.port}")


def dns_query(name: str, qtype: int) -> bytes:
    labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
    return (
        struct.pack("!HHHHHH", random.getrandbits(16), 0x0100, 1, 0, 0, 0)
        + labels
        + b"\x00"
        + (struct.pack("!HH", qtype, 1))
    )


def dns(args: argparse.Namespace) -> None:
    rnd = random.Random(7)
    start()
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        for _ in range(args.count):
            label = "".join(rnd.choice(ALPHABET) for _ in range(52))
            # Nothing listens on port 53 here; the query packets are what Sentinel sees.
            sock.sendto(dns_query(f"{label}.t.badzone.test", 16), (LOOPBACK, 53))
            time.sleep(1 / args.rate)
    print(f"sent {args.count} TXT lookups of 52-character random names to 127.0.0.1:53")


def web(args: argparse.Namespace) -> None:
    server = serve(
        args.port, lambda c: (c.recv(256), c.sendall(b"HTTP/1.0 200 OK\r\n\r\nhello"), c.close())
    )
    rnd = random.Random(3)
    start()
    for _ in range(args.count):
        urllib.request.urlopen(f"http://{LOOPBACK}:{args.port}/", timeout=2).read()
        time.sleep(rnd.uniform(0.1, 0.5))
    server.close()
    print(f"made {args.count} ordinary web requests to 127.0.0.1:{args.port}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=BANNER)
    sub = parser.add_subparsers(dest="attack", required=True)
    for name, fn, port, count in (
        ("scan", scan, 20000, 400), ("brute", brute, 2222, 30), ("beacon", beacon, 8080, 16),
        ("dns", dns, 53, 60), ("web", web, 8765, 60),
    ):  # fmt: skip
        sp = sub.add_parser(name, help=fn.__doc__)
        sp.set_defaults(fn=fn)
        sp.add_argument("--host", default=LOOPBACK)
        sp.add_argument("--port", type=int, default=port, help="port to use (scan: first port)")
        sp.add_argument("--count", type=int, default=count)
        sp.add_argument("--interval", type=float, default=1.0 if name == "beacon" else 0.4)
        sp.add_argument("--rate", type=float, default=8.0, help="dns: queries per second")
    args = parser.parse_args(argv)
    print(BANNER)
    if not is_loopback(args.host):
        print(f"refusing {args.host}: only loopback addresses are allowed", file=sys.stderr)
        return 2
    args.fn(args)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
