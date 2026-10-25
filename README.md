# Raven

Raven watches the network traffic of a small office, lab or college network and tells you, in
plain English, when something looks wrong: **port scans, brute-force logins, beaconing (malware
checking in), DNS tunnelling and unusual traffic volume**. Every detection is kept in a permanent
history you can browse in a local web UI or the terminal, and can be pushed to **Slack,
Discord or Telegram**.

It runs on one Mac that sits in front of your devices (a gateway). No cloud, no account, no
payload inspection. The only traffic that leaves the machine is the alerts you switch on.

**Contents:**
[Who it is for](#who-it-is-for) ·
[What it detects](#what-it-detects) ·
[Install](#install) ·
[Quick start](#quick-start-5-minutes-no-network-needed) ·
[Command reference](#command-reference) ·
[Live capture](#live-capture) ·
[Web console](#web-console) ·
[Attack yourself](#attack-yourself-live-demo) ·
[Alerts](#alerts-to-slack-discord-telegram) ·
[LLM summaries](#plain-english-summaries-with-a-local-llm-optional) ·
[Configuration and data](#configuration-and-data) ·
[Troubleshooting](#troubleshooting) ·
[Safety](#safety) ·
[Limits](#limits-read-this) ·
[Develop](#develop)

---

## Who it is for

- Small teams, schools, labs and home offices with **no security staff**, who want to know
  "something is scanning our network" without running a SIEM.
- Admins and students learning detection: every rule is readable, and `replay` runs any `.pcap`
  through it offline.
- **Not for:** enterprise scale, blocking attacks automatically (Raven only alerts), or reading
  encrypted content. A switched, encrypted Wi-Fi network only shows you your own traffic, so live
  capture is only meaningful on a gateway (see [Live capture](#live-capture)).

## What it detects

| Detection | Technique | Catches |
|---|---|---|
| Port / host scan | T1046 | one device probing many ports or hosts, fast or slow (10 s, 5 min and 1 h windows) |
| Brute force | T1110 | many connections to SSH, RDP, SMB, FTP... that mostly complete |
| Beaconing | T1071.001 | a device contacting one server at suspiciously regular intervals |
| DNS tunnelling | T1071.004 | many long, random-looking lookups under one domain; a character n-gram model scores how "random" names look, which catches slow tunnels with short names |
| Unusual behaviour | none (statistical) | an Isolation Forest learns your network's normal for about 35 minutes, then flags a device whose traffic volume is far beyond anything seen (for example a bulk upload no rule covers) |

Alerts on the same device are joined into one **incident** (for example scan, then brute force)
with a 0 to 1 score shown as CRITICAL / HIGH / MEDIUM / LOW. Explanations come from built-in
templates, or from a local LLM if you enable one; the LLM only writes wording and never decides
anything.

### What is inside, and how far it is verified

| Part | What it is | Status |
|---|---|---|
| Packet capture | live via `tcpdump`, or replay any `.pcap` | live verified on loopback only; gateway `bridge100` not yet |
| Rule detectors | scan, brute force, beaconing, DNS tunnelling | tested on synthetic and live loopback attacks |
| DNS n-gram model | character-trigram "random name" score, a 5th DNS signal | built, measured on synthetic data ([ablation](docs/ABLATION.md)) |
| Isolation Forest | learns your network's normal, flags unusual volume | built, measured on synthetic data; real false-alarm rate unverified |
| Incidents | alerts joined per device, ATT&CK chain, score | built |
| Explanations | plain-English templates; optional local LLM (Ollama, llama.cpp) with fact-checking and template fallback | templates verified; real LLM not yet |
| Notifications | Slack, Discord, Telegram with rate limits, retries, dedupe | tested against fakes; real delivery unverified |
| Web console | live packet monitor, topology, alerts; permanent history with search, CSV and delete | built, checked in headless Chromium |
| Terminal | `watch -d` live dashboard, `history`, `incidents`, `ack`, `status`, `doctor` | built |
| Storage | SQLite in `~/.raven`, history never pruned automatically, audit log | built |
| Not built | autoencoder, per-device peer baselines, automatic blocking, background service | roadmap |

---

## Install

**Requirements:** macOS (the tested platform; live capture uses the built-in `tcpdump`) and
[uv](https://docs.astral.sh/uv/). uv downloads the right Python (3.13) for you. Nothing else is
required. **Optional:** [Ollama](https://ollama.com) and a model of your choice, only if you want
the alert text written by a local LLM ([setup](#plain-english-summaries-with-a-local-llm-optional)).

```bash
# 1. get uv (skip if you have it)
brew install uv                       # or: curl -LsSf https://astral.sh/uv/install.sh | sh

# 2. get the code
git clone https://github.com/MRX-72/Hackt0b3r.git raven && cd raven

# 3. install the `raven` command
uv tool install .

# 4. set up your folder and check it
raven init                         # creates ~/.raven/config.toml and a private secrets.env
raven doctor                       # checks everything and tells you what to fix
```

If step 4 says `command not found`, run `uv tool update-shell` and open a new terminal.

| I want to... | Command |
|---|---|
| upgrade | `git pull && uv tool install --force .` |
| uninstall the command | `uv tool uninstall raven` |
| try it without installing | `uv sync`, then use `uv run raven ...` inside the checkout |
| install with pipx instead | `pipx install .` |

Uninstalling the command keeps your data in `~/.raven/`; delete that folder to remove it too.

## Quick start (5 minutes, no network needed)

Run these from the checkout. The practice capture is a synthetic network containing one of each attack.

```bash
uv run python tools/make_demo_pcap.py demo.pcap   # make the practice capture
raven replay demo.pcap                          # detectors run, alerts print in the terminal
raven ui --replay demo.pcap                     # same, in the web console (opens your browser)
raven history                                   # everything detected, from the terminal
```

You should see four CRITICAL detections (port scan, brute force, beaconing, DNS tunnel). Replays are
stored too, tagged `replay` and dated 1970 (the practice capture's clock); filter them out in History.

---

## Command reference

`raven <command> [options]`. Add `--help` to any command. Run `raven` alone for examples.

| Command | What it does |
|---|---|
| `init` | create `config.toml` and a private `secrets.env` (never overwrites) |
| `doctor` | check config, credentials, interface and LLM; `--fix` repairs what is safe |
| `status` | one-screen summary: database, incidents, notifications, LLM |
| `replay FILE...` | run `.pcap`/`.pcapng` files through the detectors |
| `watch` | capture live traffic (needs capture permission, see [Live capture](#live-capture)) |
| `ui` | local web console |
| `history` | the permanent anomaly history |
| `devices` | the devices the capture has seen, with traffic and alert totals |
| `deliveries` | stored notification attempts; `--channel`, `--status` filter them |
| `incidents` / `incident ID` | list incidents / show one with its timeline |
| `ack` / `dismiss` / `resolve` `ID...` | change incident status (a unique id prefix is enough) |
| `notify test CHANNEL` | send one marked sample message to `slack`, `discord` or `telegram` |
| `llm test` | list models on your LLM server and summarise a sample incident |
| `config show` | the effective settings (secrets are never shown) |

### Options for every command

| Option | Meaning |
|---|---|
| `--config FILE` | settings file (default: `$RAVEN_CONFIG`, then `./config.toml`, then `~/.raven/config.toml`, else built-in defaults) |
| `--json` | machine-readable output, one JSON object per line |
| `--color auto\|always\|never` | colour (default `auto`: only on a terminal; respects `NO_COLOR`) |
| `--version`, `-h/--help` | version, help |

### `replay` and `watch` (same output options)

| Option | Meaning |
|---|---|
| `-t`, `--show-traffic` | print every packet event as it is processed (`-T`/`--no-traffic` turns it off) |
| `-H`, `--host IP` | with `-t`: only events involving this IP |
| `-p`, `--port N` | with `-t`: only events on this port |
| `--proto P` | with `-t`: only `tcp`, `udp`, `icmp`, `dns`, `arp`, `dhcp` or `mdns` |
| `-b`, `--brief` | one line per incident instead of the full block |
| `-d`, `--dash` | full-screen live view: recent traffic, with every CRITICAL alert pinned on top (`q` quits, `c` clears pins) |
| `-n`, `--notify` | send notifications for new incidents |
| `watch --iface NAME` | interface to capture (default: `[capture] interface`, `bridge100`) |
| `watch --for TIME` | stop after this long, e.g. `90s`, `10m`, `2h` |

### `ui`

| Option | Meaning |
|---|---|
| `--iface NAME` | capture this interface live |
| `--live` | capture on the interface from `config.toml` |
| `--replay FILE...` | play capture files instead of capturing |
| `--speed N` | replay speed multiple (default 20) |
| `--port N` | port to serve on (default 8787) |
| `--no-open` | do not open the browser |
| `-n`, `--notify` | send notifications for new incidents |

With none of `--iface/--live/--replay` it just serves the history.

### `history` and `incidents`

| Option | Meaning |
|---|---|
| `-n`, `--limit N` | how many to show (history 30, incidents 20). **Here `-n` is a count, not `--notify`.** |
| `--label LEVEL` | history: `critical`, `high`, `medium` or `low` |
| `--source S` | history: `live` or `replay` |
| `--since TIME` | only the last `24h`, `7d`, `90m`... |
| `--text WORDS` | history: search headline, addresses, technique or incident id |
| `--min-score 0-1` | incidents: only scores at or above this |
| `-a`, `--all` | incidents: include dismissed and resolved |

Examples: `raven history --label critical --since 7d`, `raven incidents --min-score 0.7`,
`raven ack inc-aabb`, `raven history --json | jq .headline`.

---

## Live capture

Raven sees what crosses the interface it captures. For a whole network, put it on the Mac that
is the **gateway**, for example a MacBook sharing its connection through *Internet Sharing*, where
clients appear on `bridge100` (the default; confirm with `ifconfig`). On a normal laptop on Wi-Fi it
only sees that laptop's own traffic.

```bash
raven watch --iface lo0 -d                          # your own machine, safe to try anywhere
sudo "$(which raven)" watch --iface bridge100 -d    # a gateway; needs capture permission
sudo "$(which raven)" ui --iface bridge100          # or the web console
```

- Capture needs permission to read network devices. On macOS you may not need `sudo` if your user
  is in the `access_bpf` group (check with `id`); otherwise use `sudo` with the **full path** as
  shown, and Raven still uses **your** `~/.raven` folder, not root's.
- Only one live capture may feed a database. A second one refuses to start; stop the first with
  `pkill -f raven`.
- Stop with Ctrl-C (or `q` in the dashboard).

## Web console

`raven ui` prints a link like `http://127.0.0.1:8787/?t=...` and opens it (when started with
`sudo` it only prints the link, and you open it yourself: a browser is never launched as root). The link's token is
needed once; the page only listens on `127.0.0.1`.

- **LIVE tab:** packet monitor (newest first, with a filter box), packets per second, a network
  topology around this host, and an alert stack. Packets from a device that just raised an alert
  show red for a minute.
- **HISTORY tab:** every anomaly ever detected. Filter by severity, time range or source, search,
  click a row for the full explanation and evidence, `EXPORT CSV`, and delete chosen entries
  (tick rows, or open one; a second click confirms; each deletion is recorded in the audit log).
- **NOTIFICATIONS tab:** the three channels with their state (ready, no credentials, not in config), sent / failed / skipped counts for the last 24 hours, a **SEND TEST** button per channel (two clicks; it sends one marked test message to your real workspace), a banner saying whether this run is **armed** (started with `-n`), and every delivery with the alert it was about and why it failed, if it did. Click a row, then **OPEN IN HISTORY**.
- **DEVICES tab:** every device the capture has seen (kept across restarts): addresses, last seen, packets, bytes sent and received, and alert count with the worst severity. Click one to see its recent alerts and give it a name (saved in the database; names never come from network data). Broadcast and multicast addresses are not listed.
- **HEALTH tab:** is capture running and when did the last packet arrive, which detectors and thresholds are active, notification and LLM setup (credentials shown only as set / not set), database size and counts, and the same checks as `raven doctor`, refreshed every few seconds.
- **Theme:** the **DARK / LIGHT** switch in the top bar changes the colours (dark is the default). The choice is remembered in that browser.
- **Keys:** `1` live, `2` history, `3` notifications, `4` devices, `5` health, `/` search or filter, `p` pause the packet table.

## Attack yourself (live demo)

`tools/demo_attacks.py` runs a port scan, SSH brute force, beaconing and a DNS tunnel against
**your own machine** (`127.0.0.1` only; any other target is refused), narrating each step on screen
while Raven catches it in another window. Run from the checkout, in two terminals:

```bash
# terminal 1: the monitor. The demo config uses a 10 s window and a 15 s cooldown so every attack
# alerts quickly and can be repeated, and keeps the demo out of your real history (examples/demo.db)
uv run raven --config examples/demo-10s.toml ui --iface lo0          # web console, or:
uv run raven --config examples/demo-10s.toml watch --iface lo0 -d    # full-screen terminal view

# terminal 2: wait until terminal 1 says it is capturing, then attack
uv run python tools/demo_attacks.py                   # press Enter between attacks, to talk
uv run python tools/demo_attacks.py --auto            # hands-off, 12 s between attacks
uv run python tools/demo_attacks.py --only scan,dns   # pick some (scan brute beacon dns web)
```

Each attack should raise a red `CRITICAL` line within about 10 to 25 seconds (scan: "probing many
network ports", brute force: "repeated login attempts", beacon: "one server at fixed intervals",
DNS: "unusual DNS requests"). The `web` step is normal browsing as a control and must raise nothing.
If capture on `lo0` is refused, run the monitor with `sudo "$(which raven)"`. Timings and
one-attack-at-a-time commands: [demo.md](demo.md).

## Alerts to Slack, Discord, Telegram

1. Put your keys in `~/.raven/secrets.env` (`SLACK_WEBHOOK_URL`, `DISCORD_WEBHOOK_URL`,
   `TELEGRAM_BOT_TOKEN` + `TELEGRAM_CHAT_ID`). Only fill the channels you use. The file must be
   `chmod 600` (`raven doctor --fix` does it).
2. In `config.toml` set `[notify]` `enabled = true` and `channels = ["slack"]` (any of `slack`,
   `discord`, `telegram`).
3. `raven notify test slack` sends one marked test message to your real workspace.
4. Add `-n` to `watch`, `replay` or `ui` to send alerts for real incidents.

Messages contain only sanitised summaries (device, technique, score, advice), never packet data.
Other `[notify]` settings: `min_severity` (default 0.6), `max_per_minute`, retries and a circuit
breaker. Details: [USER_GUIDE.md](USER_GUIDE.md).

## Plain-English summaries with a local LLM (optional)

Raven does **not** ship a model and does not install one for you. Without an LLM it still works
fully: the built-in templates explain every alert. If you want the wording written by a model, you
install a model runner and a model yourself, then point Raven at it. Everything stays on your
machine.

**Step 1. Install Ollama and pull any model** (Ollama is the easiest runner):

```bash
brew install ollama            # or download from https://ollama.com
ollama serve                   # leave this running (or open the Ollama app, which does the same)
ollama pull gemma4:e2b         # any model works; small ones (1B to 8B) are fast enough
ollama list                    # shows the exact model name to use below
```

Any model Ollama can run is fine (for example `llama3.2`, `qwen2.5`, `gemma`). Bigger models write
nicer text but make each alert wait longer; a small model answers in a few seconds.

**Step 2. Tell Raven about it** in `~/.raven/config.toml`:

```toml
[llm]
enabled = true
runtime = "ollama"                   # "ollama", or "openai" for llama.cpp's llama-server / any OpenAI-compatible server
base_url = "http://127.0.0.1:11434"  # llama-server: http://127.0.0.1:8080
model = "gemma4:e2b"                 # exactly the name `ollama list` prints
timeout_seconds = 120                # raise it for big models or the first request after a cold start
```

**Step 3. Check it:**

```bash
raven llm test
```

`source: llm` means the model answered. `source: template (fallback: ...)` means Raven used the
built-in text and tells you why (server not running, wrong model name, a timeout). Nothing breaks
when the model is down: alerts keep flowing with templates. Run `raven doctor` to see whether the
server and model are reachable.

Using llama.cpp instead of Ollama: start `llama-server -m your-model.gguf`, then set
`runtime = "openai"`, `base_url = "http://127.0.0.1:8080"` and any `model` name; if you started it
with `--api-key KEY`, put `LLM_API_KEY=KEY` in `~/.raven/secrets.env`.

How it is used: the model only rewrites the explanation from sanitised fields and never decides
anything. Its output is fact-checked against the evidence and replaced by the template if it
invents a number, address or technique. Each alert waits for the model (a few seconds for a small
one). Runtimes that cannot force JSON output, such as Ollama's MLX runner, are handled
automatically.

## Configuration and data

Everything lives in **`~/.raven/`** (override with `RAVEN_HOME`), the same wherever you run from:

| File | What |
|---|---|
| `raven.db` | the permanent history, incidents, audit log |
| `config.toml` | settings: interface, detection thresholds, statistical detectors, notifications, LLM |
| `secrets.env` | webhook URLs and tokens, mode 600, never printed or logged |

`raven config show` prints the effective settings. A relative path inside a config file means
"next to that file". **Back up** by copying `raven.db` while Raven is stopped; **start fresh**
by deleting it.

The statistical detectors are tuned under `[detection.ml]` (`ngram_dns`, `isolation_forest`,
`if_threshold`); set either to `false` to switch it off. Measurements and limits: [docs/ABLATION.md](docs/ABLATION.md).

## Troubleshooting

| Symptom | Fix |
|---|---|
| `command not found: raven` | `uv tool update-shell`, then open a new terminal (or use `uv run raven`) |
| `configuration error: ... chmod 600` | `chmod 600 ~/.raven/secrets.env` or `raven doctor --fix` |
| `another Raven is already capturing ...` | stop the other one: `pkill -f raven` |
| capture permission denied / no packets | use `sudo "$(which raven)" ...`; check the interface with `ifconfig`; run `raven doctor`; or add your user to `access_bpf` |
| web console port already in use | specify a different port with `raven ui --port 8788` |
| history empty after a restart | you ran from a different `RAVEN_HOME`/config; `raven status` shows which database is used |
| `source: template (fallback: cannot reach the LLM server ...)` | Ollama is not running: start it with `ollama serve` (or open the Ollama app) and run `raven llm test` again |
| `fallback: LLM server returned HTTP 404` or `model not listed` | the `model` in `[llm]` must match `ollama list` exactly, tag included (for example `gemma4:e2b`) |
| `fallback: ... timed out` | raise `timeout_seconds` in `[llm]`; the first request after a cold start loads the model and can take much longer |
| a legitimate device keeps alerting | raise thresholds in `[detection]` or add it to `trusted_ips` |
| too many "unusual traffic" alerts | raise `if_threshold` or set `isolation_forest = false` |
| a repeated attack raises no new alert | the 5-minute cooldown; use `examples/demo-10s.toml` for demos |

More in [USER_GUIDE.md](USER_GUIDE.md#troubleshooting).

## Safety

- Network-derived text (DNS names, hostnames) is treated as hostile: sanitised before any
  notification, LLM or screen, and the console only ever shows it as plain text under a strict
  Content-Security-Policy.
- The console listens on `127.0.0.1` only and needs the per-run token.
- Raven never blocks or changes anything on the network. Capture never stalls the detectors.
- The attack scripts in `tools/` refuse any target except loopback. Use them only on your own machine.
- Secrets live only in `secrets.env` (mode 600) or environment variables.

## Limits (read this)

- Live capture is verified on loopback only. A real gateway (`bridge100`), real Slack/Discord/
  Telegram delivery and a real local LLM are **not yet verified on hardware**; the checklist is
  [docs/HUMAN_VERIFICATION.md](docs/HUMAN_VERIFICATION.md).
- The two statistical detectors are measured on synthetic traffic only; their false-alarm rate on a
  real network is unknown. The Isolation Forest is silent for its first ~35 minutes.
- No automatic blocking, no autoencoder, no background service, and macOS only so far.
- Licensed under the MIT License (see [LICENSE](LICENSE)).

## Develop

```bash
make bootstrap     # uv sync
make check         # format, lint, strict types, tests (90% coverage floor), security tests, dead code, deps
make install       # uv tool install --force .
make build         # wheel + sdist in dist/
make demo          # practice capture with one of each attack, replayed in the terminal
```

`make check` takes about two minutes. Layout: `raven/` (code; `api/` is the service surface used
by both the CLI and the web console), `tests/`, `tools/` (demo and attack scripts), `examples/`
(demo config), `schemas/` (JSON schemas of the data contracts), `spikes/` (hardware checks to run
on the gateway), `docs/` (spec, decisions, diagrams, state, ablation, and `docs/pitch/`: the pitch deck plus `build_deck.js` that regenerates it).

More documentation: [USER_GUIDE.md](USER_GUIDE.md) (every command in depth),
[demo.md](demo.md) (reproduce each attack), [docs/STATE.md](docs/STATE.md) (project status),
[docs/DECISIONS.md](docs/DECISIONS.md) (why things are the way they are).
