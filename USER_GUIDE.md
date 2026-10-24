# Sentinel User Guide

Sentinel watches the traffic crossing one Mac (your gateway), spots scans, password guessing,
malware check-ins and DNS tunnelling, explains each finding in plain English, and can message you
on Slack, Discord or Telegram. This guide covers everything you can do with the command line today.

- [What it does and does not do](#what-it-does-and-does-not-do)
- [Install](#install)
- [Five-minute tour (no network needed)](#five-minute-tour-no-network-needed)
- [How detection works](#how-detection-works)
- [Command reference](#command-reference)
- [Watching traffic](#watching-traffic)
- [Notifications: Slack, Discord, Telegram](#notifications-slack-discord-telegram)
- [Plain-English summaries with a local LLM](#plain-english-summaries-with-a-local-llm)
- [Live capture on the gateway Mac](#live-capture-on-the-gateway-mac)
- [Settings reference](#settings-reference)
- [Scripting with `--json`](#scripting-with---json)
- [Security and privacy](#security-and-privacy)
- [Troubleshooting](#troubleshooting)
- [Current limits](#current-limits)

---

## What it does and does not do

**Does**

- Reads a packet capture (`.pcap` / `.pcapng`) or live traffic and turns it into per-device activity
  summaries over three time scales: 10 seconds, 5 minutes and 1 hour.
- Detects four behaviours: **port scans**, **brute-force logins**, **beaconing** (a device checking in
  with one server at fixed intervals) and **DNS tunnelling**. Related alerts from one device are
  grouped into an **incident** and tagged with MITRE ATT&CK technique IDs.
- Writes a short explanation for each incident, either from built-in templates or from a local
  language model you choose.
- Sends a short, sanitized message to Slack, Discord and/or Telegram when you ask it to.

**Does not**

- Block anything. Sentinel only observes and reports.
- Decrypt traffic or read payloads. It looks at who talked to whom, when, how much, and DNS names.
- Let a language model decide what is an attack. Detection is plain rules; the model only words the
  explanation, and its text is rejected if it invents facts.
- Send anything off your machine unless you turn notifications on and run with `--notify`.

> Status: the pieces above are built and tested against synthetic traffic. Live capture on a real
> gateway, real message delivery and real LLM servers have **not** been exercised yet. Section
> [Current limits](#current-limits) lists what is still missing.

---

## Install

Requirements: macOS, [uv](https://docs.astral.sh/uv/), Python 3.13 (uv fetches it if needed).

```bash
git clone <your repo> sentinel && cd sentinel     # or just cd into the project
make bootstrap                                    # uv sync: creates .venv with Python 3.13
uv run sentinel --version                         # sentinel 0.1.0
```

Two ways to run the command, used interchangeably below:

| Style | Example |
|---|---|
| through uv (no activation) | `uv run sentinel doctor` |
| activate once | `source .venv/bin/activate` then `sentinel doctor` |

For live capture you need root, so use the venv path: `sudo .venv/bin/sentinel watch ...`.

---

## Five-minute tour (no network needed)

1. **Make a practice capture.** This writes a synthetic network containing one of each attack:

   ```bash
   uv run python tools/make_demo_pcap.py demo.pcap
   ```

2. **Check your setup.**

   ```bash
   uv run sentinel doctor
   ```

   The `bridge100` line is allowed to fail on a laptop that is not sharing its connection.

3. **Run detection.**

   ```bash
   uv run sentinel replay demo.pcap
   ```

   You get four detections grouped into two incidents, for example:

   ```
   INCIDENT [CRITICAL 0.99] inc-aabbccddee30-110
     Device is probing many network ports
     chain: T1046   (template text)
     what:  192.168.2.30 tried 200 different ports on 192.168.2.20 within 10 seconds, and 99% of the attempts failed.
     cause: This may be a port scan looking for open services, or a misbehaving program.
     do:    If you do not recognise this activity, disconnect the device.
     note:  Confidence 99%. This is an automatic guess: please verify before acting.
   ...
   frames=1188 flows=1188 alerts=4 incidents=2 parse_errors=0 payload_errors=0 late_dropped=0
   ```

4. **Look at the traffic too.**

   ```bash
   uv run sentinel replay demo.pcap --show-traffic --host 192.168.2.30 | head
   ```

5. **Inspect what was stored.**

   ```bash
   uv run sentinel incidents
   uv run sentinel incident inc-aabbccddee30-110
   ```

6. Delete `sentinel.db` any time to start fresh.

---

## How detection works

Sentinel keeps rolling counters for every device (identified by MAC address) and checks them every
10 seconds of capture time. Using three window lengths is what catches both loud and quiet attackers:
a fast scan shows up in the 10-second window, while a scan that sends four probes a minute is only
visible over 5 minutes or an hour.

| Detector | ATT&CK | Fires when (defaults) | What the alert says |
|---|---|---|---|
| **Port scan** | T1046 | A device touches many different ports (10 s: 20, 5 min: 15, 1 h: 60) *or* many hosts (20 / 15 / 50) and at least 60% of its connection attempts fail. | how many ports/hosts, over which window, % failed, main target |
| **Brute force** | T1110 | 8 / 20 / 60 connections to one login service (SSH 22, Telnet 23, FTP 21, SMB 445, RDP 3389, VNC 5900) in 10 s / 5 min / 1 h, and at least 30% completed (each guess is a real connection). | which service, how many attempts, target |
| **Beaconing** | T1071.001 | 10+ connections to one destination, intervals vary by less than 15%, small payloads (under 600 bytes on average), and the pattern is still going (within 3 intervals). DNS (53) and NTP (123) are ignored. | how often, how many times, destination |
| **DNS tunnel** | T1071.004 | 10+ DNS lookups in the window **and** at least two of: random-looking names (entropy 3.5), long names (40+ characters), 20+ distinct subdomains of one domain, 30%+ TXT/NULL queries. | number of lookups, average name length |

Things worth knowing:

- **One alert per condition.** A scan that goes on for an hour alerts once. When it stops looking
  like a scan (or ages out of the windows) it is forgotten, and if it returns after the 5-minute
  cooldown it alerts again.
- **Incidents.** Alerts about the same device less than 10 minutes apart join one incident. The
  incident's `chain` lists the techniques in the order they appeared, for example
  `T1046 > T1110` (scan, then password guessing). A plausible order raises the score.
- **Severity labels** in the CLI come from the incident score: `CRITICAL` ≥ 0.85, `HIGH` ≥ 0.70,
  `MEDIUM` ≥ 0.50, otherwise `LOW`.
- **Time is the capture's time.** A pcap from last month is analysed as of last month; timestamps in
  output are shown in your local time zone.
- Thresholds live in `config.toml` under `[detection]`; see the
  [settings reference](#settings-reference). A busy but legitimate server may need them raised.

---

## Command reference

```
sentinel [--config FILE] [--json] [--version] <command> ...
```

| Global option | Meaning |
|---|---|
| `--config FILE` | Settings file. Default: `config.toml` in the current directory if it exists, otherwise built-in defaults. |
| `--json` | Print JSON lines instead of text (see [Scripting](#scripting-with---json)). |
| `--version` | Print the version. |

Run `sentinel` with no command to see the help and examples.

**Exit codes:** `0` success; `1` an operational problem (bad config, unreadable capture, delivery
failed, failed health check); `2` command-line usage error.

### `replay` — analyse a capture file

```
sentinel replay PCAP [--show-traffic | --no-traffic] [--host IP] [--port N] [--proto P] [--notify]
```

Runs a `.pcap` or `.pcapng` through the whole pipeline: parse, detect, group, explain, store, and
(optionally) notify. Only Ethernet captures are supported. Replaying a file twice does not duplicate alerts (packet
rows are stored again, and with `--notify` messages are sent again).

| Option | Meaning |
|---|---|
| `--show-traffic` | Print one line per packet event as it is processed. |
| `--no-traffic` | Force the traffic view off, even if `[cli] show_traffic = true`. |
| `--host IP`, `--port N`, `--proto P` | Narrow the **traffic view** (not detection). `P` is one of `tcp udp icmp dns arp dhcp mdns`. |
| `--notify` | Send notifications for new incidents. Needs `[notify] enabled = true` and at least one channel; otherwise a warning explains why nothing was sent. |

Finishes with a summary line:
`frames=… flows=… alerts=… incidents=… parse_errors=… payload_errors=… late_dropped=…`.
`parse_errors` counts malformed packets that were skipped; `payload_errors` counts packets whose
DNS/DHCP content was unreadable (the packet itself still counts as traffic).

### `watch` — capture live traffic

```
sudo .venv/bin/sentinel watch [--iface IFACE] [same options as replay]
```

Runs `tcpdump` on the interface (default `[capture] interface`, normally `bridge100`) and feeds the
same pipeline until you press Ctrl-C. Read [Live capture](#live-capture-on-the-gateway-mac) first.

### `incidents` — list stored incidents

```
sentinel incidents [--limit N]
```

```
inc-aabbccddee20-280  explained  score=0.90  T1071.001 > T1071.004  Unusual DNS requests that may hide data
inc-aabbccddee30-110  explained  score=1.00  T1046 > T1110  Device is probing many network ports
```

Newest first, default 20. `status` is normally `explained`, or `notified` once at least one
message was sent (`open` and `correlated` are short-lived states while an incident is forming).

### `incident ID` — one incident in detail

```
sentinel incident inc-aabbccddee30-110
```

```
inc-aabbccddee30-110  [CRITICAL 1.00]  status=explained
  device: aa:bb:cc:dd:ee:30   chain: T1046 > T1110
  Device is probing many network ports
  timeline:
    05:31:50.000  portscan   T1046      sev=1.00 conf=0.99 from 192.168.2.30 -> 192.168.2.20
      attempts=200, failed_ratio=0.99, unique_dst_ips=1, unique_dst_ports=200, window_seconds=10
    05:35:10.000  bruteforce T1110      sev=0.78 conf=1.00 from 192.168.2.30 -> 192.168.2.20
      attempts=10, completed=10, dst_port=22, window_seconds=10
```

Every number in an explanation can be found in this evidence.

### `notify test CHANNEL`

```
sentinel notify test slack|discord|telegram
```

Sends a clearly marked sample incident (documentation address `192.0.2.10`) to one channel. It
ignores `[notify] enabled` and the severity floor but needs that channel's credentials. Prints
`slack: sent (ok)` or the reason it failed, and exits `1` on failure.

### `llm test`

```
sentinel llm test
```

Needs `[llm] enabled = true`. Lists the models the server reports, asks your model to explain a
sample incident, and says whether the answer was accepted (`source: llm`) or replaced by the
template (`source: template (fallback: …)`, exit `1`). See
[LLM summaries](#plain-english-summaries-with-a-local-llm).

### `config show`

Prints the effective settings as JSON plus which credentials are present (`true`/`false`, never the
values).

### `doctor`

Checks the secrets file (permissions and syntax), which channels have credentials, whether the
capture interface exists, and, if the LLM is enabled, that the server answers and lists your model.
Credentials are optional, so "not set" is reported as OK. Exit `1` if any hard check fails.

---

## Watching traffic

By default Sentinel prints only incidents. To see the packets it is analysing:

```bash
sentinel replay demo.pcap --show-traffic          # once
```

or make it the default in `config.toml`:

```toml
[cli]
show_traffic = true
```

and use `--no-traffic` on a run when you want quiet output again.

Each line is one event, in capture order:

```
05:31:40.000 192.168.2.30:40000 -> 192.168.2.20:1 tcp S 54B
05:31:40.001 192.168.2.20:1 -> 192.168.2.30:40000 tcp RA 54B
05:30:00.000 192.168.2.40:40000 -> 192.168.2.1:53 udp - 76B  dns? news.example.org A
```

`time  source:port -> destination:port  protocol  TCP-flags  size` and, for DNS lookups, the name
and record type. TCP flags: `S` SYN, `A` ACK, `R` reset, `F` FIN, `P` push (`SA` = SYN-ACK, `RA` =
reset). Other events look like:

```
05:30:01.000 ARP who-has 192.168.2.1 192.168.2.40 (aa:bb:cc:dd:ee:40)
05:30:02.000 DHCP offer from 192.168.2.1 client=aa:bb:cc:dd:ee:40 offer=192.168.2.50 host=printer
05:30:03.000 mDNS 192.168.2.40 announces macbook.local
```

**Filters** apply to what is *shown*, never to what is analysed:

```bash
sentinel watch --show-traffic --host 192.168.2.30           # one device
sentinel replay x.pcap --show-traffic --proto dns            # only DNS
sentinel replay x.pcap --show-traffic --host 10.0.0.5 --port 22
```

Names that came from the network (DNS names, DHCP host names) are escaped before printing, so a
hostile name cannot send control codes to your terminal; you will see `\x1b` instead of an escape
character.

---

## Notifications: Slack, Discord, Telegram

### 1. Create credentials

The exact menus change over time; the idea is the same on each service.

**Slack** — an Incoming Webhook posts to one channel.
1. Create (or open) a Slack app for your workspace and enable *Incoming Webhooks*.
2. *Add New Webhook to Workspace*, choose the channel.
3. Copy the URL (`https://hooks.slack.com/services/T…/B…/…`).

**Discord** — a channel webhook.
1. Channel settings → *Integrations* → *Webhooks* → *New Webhook*.
2. Copy the webhook URL.

**Telegram** — a bot plus a chat id.
1. In Telegram, talk to **@BotFather**, send `/newbot`, follow the prompts, copy the bot token
   (`123456:ABC…`).
2. Open a chat with your new bot (or add it to a group) and send it any message.
3. Find the chat id: open `https://api.telegram.org/bot<TOKEN>/getUpdates` in a browser and read
   `"chat":{"id": …}` (group ids are negative numbers).

A webhook URL or bot token lets anyone post as you. Treat them like passwords.

### 2. Put them in `secrets.env`

```
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
TELEGRAM_BOT_TOKEN=123456:ABC...
TELEGRAM_CHAT_ID=123456789
LLM_API_KEY=
```

Fill in only the channels you use. The file must be private (`chmod 600 secrets.env`); Sentinel
refuses to start otherwise. It is listed in `.gitignore`. Environment variables with the same names
override the file.

### 3. Turn channels on in `config.toml`

```toml
[notify]
enabled = true
channels = ["slack", "telegram"]     # any of slack, discord, telegram
min_severity = 0.6                   # ignore incidents below this (0 to 1)
```

### 4. Test, then use

```bash
sentinel notify test slack            # shows "slack: sent (ok)" and a message appears
sentinel replay demo.pcap --notify    # real incidents
```

Nothing is sent unless you pass `--notify` (on `replay` and `watch`).

### What gets sent, and when

- A message per **incident**, not per alert. A second message follows only if a *new* technique
  joins the same incident (for example the scanner starts guessing passwords).
- Messages contain: severity, headline, what happened, likely cause, suggested action, the device
  address, the target address and the ATT&CK technique names. Optionally a link, if
  `link_base_url` is set. No packets, no host names, no DNS names.
- Text is escaped for each service so it cannot ping `@everyone` (Discord mention parsing is
  switched off) or inject links.
- **Reliability:** up to 2 retries with 1 s / 2 s backoff for network errors, HTTP 5xx and 429
  (honouring the service's `retry_after`, capped at 30 s). A 4xx other than 429 (bad webhook) is
  not retried. After 3 consecutive failures a channel is paused for 5 minutes. At most 10 messages
  per channel per minute. A failing channel never interrupts detection; check `sentinel incidents`
  for the `status` and run `sentinel notify test <channel>`.

---

## Plain-English summaries with a local LLM

Without any setup, explanations come from templates (like the examples above). To get
model-written text, run a local model server and point Sentinel at it. Use any model; small
instruction-tuned models (1B–8B parameters) are fine because the input is short and structured.

The model never sees raw network data. It receives a small JSON record: device address, severity,
timeline of detector names, ATT&CK names and numeric evidence. It must answer in a fixed JSON
shape, and its answer is checked before use:

- every number must appear in the evidence (rounding and percent/minute conversions allowed),
- every IP, MAC and technique ID must belong to the incident,
- no links, mentions, markup or control characters,
- the recommended action must be one of five fixed actions (the wording comes from Sentinel).

If the server is down, slow, or the answer fails any check, the template text is used and the run
summary shows `llm_rejected` / `llm_errors`.

### Option A: Ollama

```bash
ollama pull llama3.2            # any model you like
ollama serve                    # if it is not already running
```

```toml
[llm]
enabled = true
runtime = "ollama"
base_url = "http://127.0.0.1:11434"
model = "llama3.2"              # must match a name from `ollama list`
timeout_seconds = 60
```

### Option B: llama.cpp (`llama-server`) or any OpenAI-compatible server

```bash
llama-server -m /path/to/model.gguf --port 8080
```

```toml
[llm]
enabled = true
runtime = "openai"
base_url = "http://127.0.0.1:8080"
model = "my-model"              # llama-server serves what it loaded; any name works
```

If you started the server with `--api-key KEY`, put `LLM_API_KEY=KEY` in `secrets.env`. The same
settings work for LM Studio, vLLM and similar servers.

### Check it

```bash
sentinel llm test
```

```
models: llama3.2:latest
source: llm
Device is scanning many ports
...
```

`source: template (fallback: number not in evidence: 7)` means the model's text was rejected; try
a larger model, a lower `temperature`, or leave the template in place. The templates are good
enough to run without a model.

---

## Live capture on the gateway Mac

Sentinel can only see traffic that crosses the machine it runs on. The intended setup is a Mac that
shares its connection (System Settings → General → Sharing → Internet Sharing) so other devices'
traffic passes through it. macOS normally creates a `bridge100` interface for that.

```bash
ifconfig | grep -A3 bridge100          # confirm the interface exists and its address
sudo .venv/bin/sentinel watch --iface bridge100 --show-traffic
```

Things to know:

- **Root.** Live capture runs `tcpdump`, which needs root. In this version the whole program runs as
  root while you use `watch` (a separate privileged capture process is planned). If your database
  path is relative, root will create it in the current directory; use a separate settings file for
  live runs so you do not end up with a root-owned database:

  ```toml
  # live.toml
  database = "/Users/you/sentinel-live.db"
  ```
  ```bash
  sudo .venv/bin/sentinel --config live.toml watch --iface bridge100
  ```
- **Snap length.** `[capture] snaplen = 384` keeps the first 384 bytes of each packet so long DNS
  names survive. That means up to ~300 bytes of payload per packet pass through memory, but Sentinel
  stores only header-level summaries and DNS names, never payloads.
- **Not verified.** `bridge100`, client-to-client reachability under Internet Sharing and capture
  speed have not been tested on real hardware. `docs/HUMAN_VERIFICATION.md` lists the checks.
- Stop with Ctrl-C; the run ends with the usual summary line.

---

## Settings reference

All settings are optional; unknown keys are rejected so typos do not pass silently.

```toml
database = "sentinel.db"        # SQLite file (relative to where you run the command)
secrets_file = "secrets.env"    # must be chmod 600
gateway_ips = []                # reserved for upcoming gateway-aware detectors

[cli]
show_traffic = false

[capture]
interface = "bridge100"
snaplen = 384                   # 96-65535 bytes per packet
bpf = ""                        # optional tcpdump filter, e.g. "not port 22"

[notify]
enabled = false
channels = []                   # "slack", "discord", "telegram"
min_severity = 0.6              # 0-1
retries = 2                     # 0-5
timeout_seconds = 10.0
breaker_failures = 3
breaker_cooloff_seconds = 300.0
max_per_minute = 10
# link_base_url = "http://127.0.0.1:8080/incidents"   # appended with /<incident id> in messages

[llm]
enabled = false
runtime = "ollama"              # or "openai" for llama.cpp and other OpenAI-compatible servers
base_url = "http://127.0.0.1:11434"
model = ""
timeout_seconds = 60.0
temperature = 0.2

[detection]
windows = [10, 300, 3600]       # seconds; multiples of 10; each needs thresholds below
cooldown_seconds = 300          # same detector + device cannot re-alert sooner than this
incident_gap_seconds = 600      # alerts further apart than this start a new incident
scan_min_unique_ports = { 10 = 20, 300 = 15, 3600 = 60 }
scan_min_unique_hosts = { 10 = 20, 300 = 15, 3600 = 50 }
scan_min_failed_ratio = 0.6
auth_ports = [21, 22, 23, 445, 3389, 5900]
brute_min_attempts = { 10 = 8, 300 = 20, 3600 = 60 }
brute_min_completed_ratio = 0.3
beacon_min_events = 10
beacon_max_interval_cv = 0.15   # jitter allowed: std-dev / mean of the gaps
beacon_min_interval_seconds = 1.0
beacon_max_mean_bytes = 600.0
beacon_active_intervals = 3.0   # a beacon silent for this many intervals is considered over
beacon_ignore_ports = [53, 123]
dns_min_queries = 10
dns_min_entropy = 3.5
dns_min_mean_length = 40.0
dns_min_unique_subdomains = 20
dns_min_txt_null_share = 0.3
```

Tuning tips:

- Too many alerts from a legitimate device (a backup server, a vulnerability scanner you run)?
  Raise the matching thresholds, or add its port to `beacon_ignore_ports`.
- To check what the long windows add, run the same capture with `windows = [10]` and compare.
  A slow scan will vanish from the results, which is exactly why the longer windows exist. If you
  remove a window you must keep the three threshold tables consistent with it.

---

## Scripting with `--json`

With `--json` every command prints one JSON object per line. `replay` and `watch` print three
kinds of lines, each wrapped in a single key:

```json
{"event": {"type": "Flow", "ts": 100.0, "src_ip": "192.168.2.30", "dst_port": 22, "...": "..."}}
{"report": {"incident": {"id": "inc-…", "chain": ["T1046"], "score": 0.99}, "explanation": {"...": "..."}, "deliveries": []}}
{"summary": {"frames": 1188, "alerts": 4, "incidents": 2, "...": "..."}}
```

Examples (with [jq](https://jqlang.github.io/jq/)):

```bash
# only incident headlines
sentinel --json replay demo.pcap | jq -r 'select(.report) | .report.explanation.headline'

# fail a script if anything critical was found
sentinel --json replay capture.pcap | jq -e 'select(.report and .report.incident.score >= 0.85)' >/dev/null && echo "ALERT"

# all stored incidents as a table
sentinel --json incidents | jq -r '[.id, .status, .score] | @tsv'
```

JSON Schemas for every payload are in `schemas/` (`IncidentReport.json`, `RunSummary.json`, …).

---

## Security and privacy

- **Local first.** The only outbound traffic is the notifications you enable and the LLM server you
  configure (normally on `127.0.0.1`). There is no telemetry.
- **Secrets** live in `secrets.env` (mode 600, git-ignored), are never printed, never written to the
  database, and never appear in error messages. `sentinel config show` reports only present/absent.
- **Hostile input.** DNS names and host names come from the network and may be crafted. They are
  parsed defensively (malformed packets are counted and skipped), stored only as data, escaped when
  shown in your terminal, and never passed to a language model or a chat message. The only text
  that reaches the model or chat services is a record built from validated addresses, fixed
  technique names and numbers.
- **What is stored** in `sentinel.db`: one row per packet event (addresses, ports, sizes, TCP
  flags, DNS query names), alerts, incidents, an audit log and notification outcomes. No packet
  contents. The database can contain sensitive browsing metadata (DNS names): protect the file,
  and tell the people on your network that you monitor it. Only monitor networks you own or
  administer.

---

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `configuration error: … chmod 600 secrets.env` | The secrets file is readable by others. Run `chmod 600 secrets.env`. |
| `configuration error: … extra inputs are not permitted` | A key in `config.toml` is misspelled or in the wrong section. The message names it. |
| `configuration error: … has no threshold for window(s) [600]` | You added a window without adding it to each threshold table. |
| `error: unsupported link type …; only Ethernet` | The capture is not Ethernet (for example loopback or Wi-Fi monitor mode). Capture on an Ethernet-type interface such as the bridge. |
| `error: unreadable capture` | Not a pcap/pcapng file, or the header is damaged. |
| `warning: --notify has no effect` | Set `[notify] enabled = true` and list channels. |
| `notify test` prints `skipped (no credentials configured)` | That channel's keys are missing from `secrets.env`. |
| `slack: failed (HTTP 404)` / `no_service` | The webhook was revoked or mistyped. Not retried. |
| `telegram: failed (HTTP 400)` | Wrong `TELEGRAM_CHAT_ID`, or you never sent the bot a message. |
| `skipped (circuit open …)` | Three failures in a row; the channel is paused 5 minutes. Fix the cause and test again. |
| `llm test` says `cannot reach the LLM server` | Server not running or wrong `base_url`/`runtime`. |
| `source: template (fallback: …)` | The model's reply was rejected; see the reason in parentheses. |
| `doctor`: `interface bridge100: not found` | Internet Sharing is off or uses another name. Run `ifconfig` and set `[capture] interface`. |
| `sqlite3.OperationalError: attempt to write a readonly database` | A previous `sudo watch` created a root-owned `sentinel.db`. `sudo chown $USER sentinel.db*`, or use a separate database path for live runs. |
| Slow scan not detected | Make sure `windows` still includes 300 and 3600, and that the probes are failing (closed ports). |
| A legitimate device keeps alerting | Raise the relevant thresholds in `[detection]`. |

---

## Current limits

Be aware of these before relying on Sentinel:

- **Detectors present:** scan, brute force, beaconing, DNS tunnelling. *Not yet:* rogue DHCP server,
  ARP spoofing, canary tripwires, per-device learned baselines, comparison with similar devices.
- **Not yet built:** background daemon with privilege separation, HTTP API and web interface,
  device inventory and naming, monitoring modes (Learning/Strict/…), firewall-rule proposals,
  packet browser, rule editor, natural-language `ask`. The command line is the only interface; the
  code is arranged so a web interface can be added later without changing the core.
- **Beaconing** is judged by timing regularity only. A legitimate sync tool with a fixed schedule
  can look like malware; the message wording says "may be".
- **UDP port scans** are not detected (success or failure is not visible without replies).
- **DNS over TCP** is not parsed; the "parent domain" is simply the last two labels, which is wrong for
  names such as `example.co.uk`.
- **The database grows** with every packet event and is not pruned automatically. Delete
  `sentinel.db` to reset.
- **Never tested against real hardware or real services:** live capture, Slack/Discord/Telegram
  delivery, Ollama and llama.cpp. If something differs from this guide, it is a bug worth
  reporting; the checklist is in `docs/HUMAN_VERIFICATION.md`.

For design background see `docs/WHAT_WE_ARE_BUILDING.md`, the decisions in `docs/DECISIONS.md`
and project status in `docs/STATE.md`.
