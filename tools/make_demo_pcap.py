"""Write a synthetic attack capture for trying Raven without a network.

    uv run python tools/make_demo_pcap.py demo.pcap

It contains normal browsing plus a port scan (t=100 s), SSH brute force (t=300 s), a beacon to
a fake C2 (every 30 s from t=0) and a DNS tunnel (t=700 s), all inside 192.168.2.0/24.
"""

import sys
from pathlib import Path

from tests import scenarios as sc


def main(out: Path) -> None:
    packets = (
        sc.normal_browsing(0, 900, sc.USER)
        + sc.port_scan(100.0, range(1, 201))
        + sc.brute_force(300.0, 40)
        + sc.beacon(0, 20, 30.0, jitter=0.05)
        + sc.dns_tunnel(700.0, 60)
    )
    sc.write_pcap(out, packets)
    print(f"wrote {len(packets)} packets to {out}")


if __name__ == "__main__":
    main(Path(sys.argv[1] if len(sys.argv) > 1 else "demo.pcap"))
