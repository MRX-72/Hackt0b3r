# Sentinel

Sentinel watches the network traffic of a small office, lab or college network and tells you, in
plain English, when something looks wrong: **port scans, brute-force logins, beaconing (malware
checking in) and DNS tunnelling**. Every detection is kept in a permanent history you can browse in
a local web console or the terminal, and can be pushed to **Slack, Discord or Telegram**.

It runs on one Mac that sits in front of your devices (a gateway). Nothing leaves the machine
except the alerts you switch on. No cloud, no account, no payload inspection.

## Who it is for

- Small teams, schools, labs and home offices with **no security staff**, who want "something is
  scanning our network" without running a SIEM.
- Admins and students learning detection: every detector is a readable rule, and `replay` runs any
  `.pcap` through it offline.
- Not for: enterprise scale, blocking attacks automatically (Sentinel only alerts), or reading
  encrypted content. A switched, encrypted Wi-Fi network only shows you your own traffic, so live
  capture is only meaningful on a gateway (see [Where to run it](#where-to-run-it)).

## What it detects

| Detection | Technique | Catches |
|---|---|---|
| Port / host scan | T1046 | one device probing many ports or hosts, fast or slow (10 s, 5 min and 1 h windows) |
| Brute force | T1110 | many connections to SSH, RDP, SMB, FTP... that mostly complete |
| Beaconing | T1071.001 | a device contacting one server at suspiciously regular intervals |
| DNS tunnelling | T1071.004 | many long, random-looking lookups under one domain; a character n-gram model scores how "random" names look and catches slow tunnels with short names |
| Unusual behaviour | none (statistical) | an Isolation Forest learns your network's normal for ~35 minutes, then flags a device whose traffic volume is far beyond anything seen (for example a bulk upload no rule covers) |

Alerts with the same device are joined into one **incident** (for example scan then brute force)
and given a 0 to 1 severity score. Explanations come from built-in templates, or from a local LLM
(Ollama or llama.cpp) if you enable one; the LLM only writes the wording and never decides
anything.

The two statistical detectors are measured in [docs/ABLATION.md](docs/ABLATION.md) (synthetic
traffic only; their false-alarm rate on a real network is unverified) and can be switched off in
`[detection.ml]`. Not built yet: an autoencoder, per-device peer baselines, automatic blocking and
a background service. See `docs/BACKLOG.md`.

## What is inside

| Part | What it is | Status |
|---|---|---|
| Packet capture | live via `tcpdump`, or replay any `.pcap` | live verified on loopback only; gateway `bridge100` not yet |
| Rule detectors | port scan, brute force, beaconing (timing regularity), DNS tunnelling | tested on synthetic and live loopback attacks |
| DNS n-gram model | character-trigram "random name" score, a 5th DNS signal | built, measured on synthetic data ([ablation](docs/ABLATION.md)) |
| Isolation Forest | learns your network's normal, flags unusual volume | built, measured on synthetic data; real false-alarm rate unverified |
| Incidents | alerts joined per device, ATT&CK chain, 0 to 1 score | built |
| Explanations | plain-English templates; optional local LLM (Ollama, llama.cpp) with fact-checking and template fallback | templates verified; real LLM not yet |
| Notifications | Slack, Discord, Telegram with rate limits, retries, dedupe | tested against fakes; real delivery unverified |
| Web console | live packet monitor, topology, alerts; permanent history with search, CSV and delete | built, checked in headless Chromium |
| Terminal | `watch -d` live dashboard, `history`, `incidents`, `ack`, `status`, `doctor` | built |
| Storage | SQLite in `~/.sentinel`, never pruned history, audit log | built |
| Demo tools | practice `.pcap` and loopback attack scripts (loopback only) | built, see [demo.md](demo.md) |
| Not built | autoencoder, per-device peer baselines, automatic blocking, background service | roadmap |

## Install

You need **macOS** (tested platform; live capture uses the built-in `tcpdump`) and
[uv](https://docs.astral.sh/uv/). uv downloads Python 3.13 for you.

```bash
brew install uv                       # or: curl -LsSf https://astral.sh/uv/install.sh | sh
git clone <this repository> sentinel && cd sentinel
uv tool install .                     # puts `sentinel` on your PATH (~/.local/bin)
sentinel --version
sentinel init                         # creates ~/.sentinel/config.toml and a private secrets.env
sentinel doctor                       # checks everything and says what to fix
```

Upgrade later with `git pull && uv tool install --force .`. Remove with `uv tool uninstall sentinel`.
`pipx install .` works too. Prefer a throwaway try-out? `uv run sentinel ...` inside the checkout
works without installing.

## Try it (no network needed)

```bash
uv run python tools/make_demo_pcap.py demo.pcap    # a synthetic network with one of each attack
sentinel replay demo.pcap                           # run it through the detectors
sentinel ui --replay demo.pcap                      # same, in the web console (opens your browser)
```

## Attack yourself (live demo)

`tools/demo_attacks.py` runs a port scan, SSH brute force, beaconing and a DNS tunnel against
**your own machine** (`127.0.0.1` only; any other target is refused), narrating each step on screen
while Sentinel catches it in another window. Run from the checkout, in two terminals:

```bash
# terminal 1: the monitor. The demo config uses a 10 s window and a 15 s cooldown so every attack
# alerts quickly and can be repeated, and keeps the demo out of your real history (examples/demo.db)
uv run sentinel --config examples/demo-10s.toml ui --iface lo0      # web console, or:
uv run sentinel --config examples/demo-10s.toml watch --iface lo0 -d    # full-screen terminal view

# terminal 2: wait until terminal 1 says it is capturing, then attack
uv run python tools/demo_attacks.py              # press Enter between attacks, to talk
uv run python tools/demo_attacks.py --auto       # hands-off, 12 s between attacks
uv run python tools/demo_attacks.py --only scan,dns   # just some of them (scan brute beacon dns web)
```

Each attack should raise a red `CRITICAL` line within about 10 to 25 seconds (scan: "probing many
network ports", brute force: "repeated login attempts", beacon: "one server at fixed intervals",
DNS: "unusual DNS requests"), and the device's incident grows as the same device does more. The `web`
step is normal browsing as a control and must raise nothing. If capture on `lo0` is refused, run the
monitor with `sudo "$(which sentinel)"` instead. Timings, expected results and manual one-attack
commands: [demo.md](demo.md).

## Use it

```bash
sentinel ui --iface lo0               # web console, live capture of your own machine
sentinel history --label critical     # everything detected so far, from the terminal
sentinel incidents                    # open incidents;  sentinel ack <id>  to acknowledge one
sentinel status                       # database, incidents, notifications, LLM at a glance
```

Live capture on a gateway needs root. Run with the full path so sudo finds it, and it still uses
**your** `~/.sentinel` folder:

```bash
sudo "$(which sentinel)" watch --iface bridge100 -d     # full-screen live dashboard
sudo "$(which sentinel)" ui --iface bridge100           # or the web console
```

- **Web console** (`sentinel ui`): LIVE tab with a packet monitor, packets per second, a network
  topology and an alert stack; HISTORY tab with every anomaly ever detected (filter, search, detail,
  CSV export, delete chosen entries). It only listens on `127.0.0.1` and needs the one-time link it prints.
- **Terminal**: `watch -d` (live dashboard with criticals pinned), `watch -t` (show traffic),
  `replay FILE.pcap`. Every flag is in [USER_GUIDE.md](USER_GUIDE.md).

### Where your data lives

Everything is under **`~/.sentinel/`** (override with `SENTINEL_HOME`), so it is the same wherever
you run the command from:

| File | What |
|---|---|
| `sentinel.db` | the permanent history: every detection (kept until you delete entries; never pruned automatically), incidents, audit log |
| `config.toml` | settings (detection thresholds, interface, notifications, LLM) |
| `secrets.env` | webhook URLs and tokens, mode 600, never printed or logged |

Settings are found in this order: `--config FILE`, `$SENTINEL_CONFIG`, `./config.toml`,
`~/.sentinel/config.toml`. A relative path inside a config file means "next to that file".

**Back up** by copying `sentinel.db` while Sentinel is stopped (or `sqlite3 sentinel.db ".backup copy.db"`).
**Start fresh** by deleting it. Replays are stored too, tagged `replay`; filter them out in History.

### Alerts to Slack, Discord, Telegram

1. Put your keys in `~/.sentinel/secrets.env` (`SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL`,
   `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`). The file must be `chmod 600`.
2. In `config.toml`: `[notify]` `enabled = true`, `channels = ["slack"]`.
3. `sentinel notify test slack` sends one marked test message. Then add `-n` to `watch`, `replay`
   or `ui`, or enable it in config for all runs.

Messages contain only sanitised summaries (device, technique, score, advice), never packet data.
Details, rate limits and the LLM setup: [USER_GUIDE.md](USER_GUIDE.md).

## Where to run it

Sentinel sees what crosses the interface it captures. For a whole network, put it on the Mac that
is the gateway, for example a MacBook sharing its connection through **Internet Sharing**, where
clients appear on `bridge100` (the default interface in the config; confirm with `ifconfig`). On a
normal laptop connected to Wi-Fi it only sees that laptop's own traffic. Real-gateway behaviour,
real Slack/Discord/Telegram delivery and a real local LLM have **not yet been verified on
hardware**; the checklist is in `docs/HUMAN_VERIFICATION.md`.

## Safe to run

- Network-derived text (DNS names, hostnames) is treated as hostile: it is sanitised before any
  notification, LLM or screen, and the console only ever shows it as plain text under a strict
  Content-Security-Policy.
- Sentinel never blocks or changes anything on the network. Capture never stalls the detectors.
- The attack scripts in `tools/` refuse any target except loopback. Use them only on your own machine.

## Develop

```bash
make bootstrap     # uv sync
make check         # format, lint, strict types, tests (90% coverage floor), security tests, dead code, deps
make install       # uv tool install --force .
make build         # wheel + sdist in dist/
```

Layout: `sentinel/` (code; `api/` is the service surface used by both the CLI and the web console),
`tests/`, `tools/` (demo and attack scripts, see [demo.md](demo.md)), `docs/` (spec, decisions,
diagrams, state), `examples/`, `schemas/` (JSON schemas of the data contracts).
