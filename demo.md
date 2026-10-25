# Demo: four attacks against your own machine, caught by the 10-second window

This reproduces a live test of Raven on **your own loopback interface** (`127.0.0.1`). It runs the
four attacks Raven knows (port scan, brute force, beaconing, DNS tunnelling) plus a control
(ordinary web traffic that must raise nothing). Only the **10-second window** is enabled, and
**notifications are off** (no `--notify`, `[notify] enabled = false`), so nothing leaves the machine.

> Safety: every attack script targets `127.0.0.1` only and refuses any other address. Do not point
> them (or adapt them) at machines you do not own.

- [Presenter script (two consoles)](#presenter-script-two-consoles)
- [Results from the reference run](#results-from-the-reference-run)
- [Before you start](#before-you-start)
- [Fastest way: one command](#fastest-way-one-command)
- [Replicate each attack by hand](#replicate-each-attack-by-hand) (two terminals)
- [How each attack trips the 10-second window](#how-each-attack-trips-the-10-second-window)
- [Reading the numbers](#reading-the-numbers)
- [Troubleshooting](#troubleshooting)

---

## Presenter script (two consoles)

For a live presentation use `tools/demo_attacks.py`. It narrates each attack on screen
(`Performing PORT SCAN on 127.0.0.1`, a progress bar, what Raven should report) while your
other console shows the monitor catching it.

```bash
# console 1: the monitor. -d = full-screen view with CRITICAL alerts pinned on top of the
# sliding traffic window (q quits, c clears the pins); -b instead prints one line per incident
uv run raven --config examples/demo-10s.toml watch --iface lo0 -d

# console 2: the attacks
uv run python tools/demo_attacks.py            # press Enter between attacks, to talk
uv run python tools/demo_attacks.py --auto     # hands-off, 12 s between attacks
uv run python tools/demo_attacks.py --only scan,dns     # just some of them
```

Order: port scan, SSH brute force, beaconing, DNS tunnel, then the control. In the reference run
the monitor printed four lines, one per attack, as the same device's incident grew:
`T1046` then `T1046 > T1110` then `... > T1071.001` then `... > T1071.004`, and each line has its
own headline (port probing, repeated logins, fixed-interval contact, unusual DNS); the control
added nothing. Options: `--settle N` (seconds between attacks), `--countdown N` (before the first),
`--scale 0.1` (tiny rehearsal run; too small to trigger detection). Loopback only.

In the `-d` view every CRITICAL alert stacks as its own pinned line (a scan, logins, a beacon and a
DNS tunnel from the one device are four lines, and the `CRIT` counter goes 1, 2, 3, 4). Running the
same attack again within `cooldown_seconds` raises no new alert; `examples/demo-10s.toml` sets it to 15 s so
repeats show up as new pinned lines.

---

## Results from the reference run

Machine: macOS, capturing `lo0` as a normal user (member of `access_bpf`, no `sudo`). Config:
`windows = [10]`, notifications off. Run with `uv run python tools/localhost_check.py`.

| attack | expected | detected | window | alert time after attack start | severity | result |
|---|---|---|---|---|---|---|
| port scan | portscan | portscan | 10 s | 8.9 s | 1.00 | PASS |
| brute force | bruteforce | bruteforce | 10 s | 8.5 s | 1.00 | PASS |
| beaconing | beaconing | beaconing | not windowed (see below) | 12.1 s | 0.90 | PASS |
| DNS tunnel | dns_tunnel | dns_tunnel | 10 s | 1.7 s | 0.80 | PASS |
| control: web browsing | nothing | nothing | - | - | - | PASS |

Evidence Raven recorded for each detection:

| attack | evidence (all numbers from the 10-second window) |
|---|---|
| port scan | 400 attempts, 400 distinct ports, 99.75% failed |
| brute force | 21 connections to port 2222, all 21 completed |
| beaconing | 13 connections to `127.0.0.1:8080`, every 1.0003 s, jitter (CV) 0.0023, about 1 KB per session |
| DNS tunnel | 14 TXT lookups, average name length 67, entropy 4.5 bits/char, 14 distinct subdomains of one domain, 3 of 4 signals |

**Stability.** Port scan, brute force, DNS tunnel and the control were right in every live run
(about 15 each). The beacon was missed in 2 of about 21 live attempts, both times when the attack
began right after `raven watch` was launched (a fixed `sleep`), probably before `tcpdump` had
started capturing, so the first check-ins were never seen. Since the driver waits until `tcpdump`
is actually running, 4 of 4 beacon attempts were caught, and a further 3 full cycles (15 attack
runs, each recorded in parallel) gave the same result live and when replaying the recording.
Short bursts were also tested offline at 12 different phases of the 10-second grid
(`tests/test_detection_matrix.py`): all caught.

**What "alert time" means.** Raven evaluates detectors on a 10-second grid of capture time, so
an attack that has just crossed a threshold is reported at the next grid point: usually within 10
seconds of the threshold being crossed, plus the attack's own duration (the scan itself takes about
1 s; the beacon needs 10 check-ins one second apart, so it cannot be reported before about 10 s).
Individual runs ranged from 1 s to 12 s.

**Beaconing is not a "10-second" detection.** It is judged from the timing of repeated connections
to one destination (at least 10 check-ins with under 15% jitter), not from a window. With one
check-in per second it becomes detectable after about 10 s, which is why it fits this demo.
Real beacons (every 30-300 s) need minutes of observation.

---

## Before you start

```bash
make bootstrap                    # Python 3.13 environment (uv)
id | tr ' ' '\n' | grep access_bpf   # prints a line if you can capture without sudo
```

- If `access_bpf` is missing, either run the watch commands with `sudo .venv/bin/raven ...`
  (then give the database back to yourself afterwards: `sudo chown $USER demo.db*`), or install
  Wireshark's ChmodBPF helper.
- Ports used: TCP 2222 (fake SSH), TCP 8080 (fake C2), TCP 8765 (control web server), TCP
  20000-20399 (scanned range), UDP 53 (destination of the DNS queries; nothing needs to listen).
  Free them if something else uses them.
- Notifications stay off. You can confirm with `raven --config examples/demo-10s.toml status`, which prints
  `notify     off`.

---

## Fastest way: one command

```bash
uv run python tools/localhost_check.py
```

It starts `raven watch --iface lo0` with the 10-second-only config for each attack, runs the
attack, waits for the capture to end, reads the stored incident back, and prints the table above
(about 2.5 minutes). Exit code `0` means all five rows passed.

---

## Replicate each attack by hand

Use two terminals in the project folder. `examples/demo-10s.toml` (included) enables only the 10-second
window and adds port 2222 to the login-service list:

```toml
database = "demo.db"
secrets_file = "secrets.env"

[notify]
enabled = false

[detection]
windows = [10]
scan_min_unique_ports = { 10 = 20 }
scan_min_unique_hosts = { 10 = 20 }
brute_min_attempts = { 10 = 8 }
auth_ports = [21, 22, 23, 445, 2222, 3389, 5900]
```

For **every** attack the pattern is the same. Start the capture first and give it a few seconds:

```bash
# terminal 1
rm -f demo.db*                                  # optional: start from an empty database
uv run raven --config examples/demo-10s.toml watch --iface lo0 --for 30s -b
```

then, once terminal 1 is running, launch the attack:

```bash
# terminal 2
uv run python tools/localhost_attacks.py <scan|brute|beacon|dns|web>
```

Terminal 1 prints the incident when it is detected and a summary line when the 30 seconds are
over. Give the capture time to start before launching the attack: run `uv run raven --version`
once beforehand (so `uv` finishes any rebuild) and wait until `pgrep tcpdump` prints a number
(about 3-5 seconds). An attack that starts before capturing begins can lose its first packets,
which is enough to miss the beacon. Inspect it afterwards with `uv run raven --config examples/demo-10s.toml incidents` and
`... incident <id>`.

### 1. Port scan

```bash
uv run python tools/localhost_attacks.py scan
```

Probes 400 ports (20000-20399) of `127.0.0.1` as fast as possible; one port (20080) has a listener,
so the scan sees 1 open and 399 closed. Expected in terminal 1:

```
[CRITICAL 1.00] inc-02007f000001-...  Device is probing many network ports  (T1046)
```

### 2. Brute force

```bash
uv run python tools/localhost_attacks.py brute
```

A fake SSH-like service listens on port 2222; the script makes 30 failed "logins" 0.4 s apart. (Real
SSH is port 22, which needs root to listen on; that is why 2222 is in `auth_ports` in the demo
config. As root you can run the same attack on 22 with `--port 22`.) Expected:

```
[CRITICAL 1.00] inc-02007f000001-...  Repeated login attempts against a service  (T1110)
```

### 3. Beaconing

```bash
uv run python tools/localhost_attacks.py beacon
```

A fake command-and-control server listens on port 8080; the script checks in once per second, 16
times (drift-free schedule). Expected (about 10-15 s after the attack starts):

```
[CRITICAL 0.90] inc-02007f000001-...  Device contacts one server at fixed intervals  (T1071.001)
```

(The number varies a little with how many check-ins had been seen when the alert fired.)

### 4. DNS tunnel

```bash
uv run python tools/localhost_attacks.py dns
```

Sends 60 TXT lookups (8 per second) for random 52-character names under `t.badzone.test` to
`127.0.0.1:53`. No DNS server is needed: Raven analyses the query packets themselves. Expected:

```
[CRITICAL 1.00] inc-02007f000001-...  Unusual DNS requests that may hide data  (T1071.004)
```

### 5. Control (must stay silent)

```bash
uv run python tools/localhost_attacks.py web
```

60 ordinary HTTP requests at random 0.1-0.5 s intervals to a local web server. Terminal 1 must
print only the summary line (`alerts=0 incidents=0`).

### Look at one result

```bash
uv run raven --config examples/demo-10s.toml incidents
uv run raven --config examples/demo-10s.toml incident inc-02007f000001      # a unique prefix is enough
uv run raven --config examples/demo-10s.toml status                         # confirms: notify off
```

Because every packet is between the machine and itself, Raven sees one "device" (`127.0.0.1`,
stand-in MAC `02:00:7f:00:00:01`); if you run several attacks into the same `demo.db` they merge
into one incident with a chain such as `T1046 > T1110`. Delete `demo.db*` between attacks to see
them separately.

---

## How each attack trips the 10-second window

Defaults used (all in `[detection]`, see `USER_GUIDE.md`):

| attack | rule inside one 10-second window | what the demo produces |
|---|---|---|
| port scan | at least 20 distinct ports (or hosts) **and** at least 60% of connection attempts failed | 400 ports, 99.75% failed |
| brute force | at least 8 connections to one login service, at least 30% of them completed | 21 connections, 100% completed (port 2222) |
| DNS tunnel | at least 10 lookups **and** at least 2 of: entropy 3.5, name length 40, 20 distinct subdomains, 30% TXT/NULL | 14+ lookups, 3-4 signals |
| beaconing | at least 10 accepted connections to one destination, jitter under 15%, still ongoing (not windowed) | 13-16 check-ins, jitter 0.2% |

The "control" row stays silent because it has one port, no failures, irregular timing and ordinary
DNS-free traffic.

---

## Reading the numbers

- **Time to detect** is measured from the attack script's `ATTACK_START` line to the alert's
  capture timestamp. The alert is stamped with the 10-second grid point at which it was evaluated,
  not with the moment you see it on screen.
- **Delay varies run to run** because the attack starts at a random point of the 10-second grid.
- Before the live run, the same behaviour is covered by automated tests: `make check` includes a
  sweep of every attack over 12 phases of the grid.

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `tcpdump: ... /dev/bpf: Permission denied` | You are not in `access_bpf`. Use `sudo .venv/bin/raven ...` for the watch command. |
| `OSError: [Errno 48] Address already in use` from an attack | Another program uses 2222 / 8080 / 8765. Pass `--port N` to the attack. For brute force on another port, add it to `auth_ports`. |
| Nothing detected, summary shows `frames=` near 0 | The capture started after the attack. Start terminal 1 first and wait about 3 seconds. |
| Brute force not detected on a port other than 2222 | The port is not in `auth_ports` in `examples/demo-10s.toml`. |
| `attempt to write a readonly database` afterwards | A `sudo` run left `demo.db` owned by root: `sudo chown $USER demo.db*`. |
| Results differ from the table | Compare with `uv run python tools/localhost_check.py`; it uses exactly the config shown above. Timing columns vary; the PASS/FAIL columns should not.. |
