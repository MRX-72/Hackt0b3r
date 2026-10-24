# Brief: multi-timescale windows and features (Stage 1, component 4)

**Purpose:** turn the Flow stream into per-host feature vectors over 10 s / 5 min / 1 h windows (event time), plus per-destination connection timing for beaconing and per-service attempt counts for brute force.

**Inputs/outputs:** `WindowEngine(DetectionSettings).observe(Flow)`, `.snapshot(now) -> list[HostContext]`. `HostContext` = host mac/ip, `features: {window_s: WindowFeatures}`, `services: {window_s: {(dst_ip, dst_port): (attempts, completed)}}`, `destinations: list[DestinationTiming]`. Contracts: `WindowFeatures`, `DestinationTiming`.

**Invariants:**
- State is a ring of 10 s buckets per host; memory is bounded by max window, set caps and a seen-destination cap. Idle hosts and old buckets are evicted.
- A TCP connection attempt is a SYN without ACK, keyed by (host ip/port, target ip/port). SYN-ACK back marks it completed, RST marks it failed; unanswered counts as not completed. `failed_ratio = (attempts - completed) / attempts`.
- Event time only: `now` is what the caller passes to `snapshot`; nothing reads the wall clock (hour_of_day uses the local timezone of the snapshot time).
- DNS stats come only from queries; entropy is on the subdomain part (name minus last two labels), first label when there is none. DNS and mDNS traffic are not connections.
- Events older than the longest window are dropped and counted (`late_dropped`).

**Failure modes:** asymmetric capture (no replies seen) inflates failed_ratio; detectors also gate on target counts. Naive parent domain (last two labels) mishandles `co.uk`-style suffixes.

**Requirements:** R-FEA-001 (R-FEA-002 persistence of snapshots comes with the pipeline).

**Tests first:** `tests/test_windows.py` using scenario traffic through the real parser.

**Out of scope:** detection thresholds, persistence, ML.
