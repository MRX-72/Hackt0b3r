# PART 3: BASE BUILD SPECIFICATION


A local, zero-config, explainable network anomaly detector for colleges, small offices and small teams with no security staff. Built for a 10-hour hackathon on three MacBooks. Nothing leaves the lab.

**Build notes:** Build this in the phase order in section 14. Get each phase working end to end before starting the next. Prefer simple, deterministic code over cleverness. Where this spec says "verify", test it on the real machine before building on it. Keep a `NOTES.md` of anything that deviated from this spec.

---

## 1. Goals and non-goals

### Goals
- Passive capture of traffic crossing one gateway Mac, no agents on other machines.
- Automatic device inventory with device-type guessing and a "new/unknown device" alert.
- Per-device baselines plus peer-group comparison, so detection works even on day one.
- Detect small-org threats: port scans, SSH/service brute force, DNS tunneling, beaconing, rogue DHCP/ARP anomalies, crypto-miner-like traffic, device-type behavior change.
- Correlate alerts into incidents (attack chains) tagged with MITRE ATT&CK techniques.
- Plain-English alert text from a local small LLM fed **only structured, sanitized features**.
- Alert budget: the admin sees the top few things, not hundreds.
- Approval-gated response suggestions (dry run only, never auto-applied).
- Built-in purple-team panel that runs scripted attacks against the lab and reports measured results.

### Non-goals
- Deep packet inspection, TLS decryption, payload analysis.
- Enterprise scale, cloud dashboards, multi-tenant anything.
- Auto-blocking or any action that changes network state without human approval.
- Claiming "100x better". Report measured numbers instead.

---

## 2. Hardware and network topology

Three MacBooks and a phone hotspot.

| Role | Machine | Runs |
|---|---|---|
| Gateway / Brain | Mac C | Internet Sharing (creates the private network), packet capture, feature extraction, detectors, correlation, local LLM (Ollama), API server, dashboard, fake C2 server, DNS server for tunneling tests |
| Victim / normal user | Mac A | Joins the private network. Runs baseline browsing traffic generator and a few test services (SSH with throwaway account, simple web server, canary service) |
| Attacker | Mac B | Joins the private network. Runs the scripted attacks from section 10 |

### Network setup
- Mac C creates a private network via System Settings -> General -> Sharing -> Internet Sharing. Share from an uplink (USB tethering from the phone) to Wi-Fi, **or** run a closed network with no uplink. A closed lab network is the recommended demo setup. Download all tools and models beforehand.
- Mac A and Mac B join Mac C's Wi-Fi network. All their traffic crosses Mac C.
- The shared network bridge is usually `bridge100`. **Verify** with `ifconfig`.
- Typical client addresses are in 192.168.2.0/24. **Verify.**

### Things to verify before building anything (first 30 minutes)
1. Internet Sharing starts and A and B receive IPs.
2. A and B can ping each other through the gateway. Internet Sharing may isolate clients. If A-to-B traffic does not flow, fall back to: victim services run on Mac C itself, B attacks Mac C, and A generates normal baseline traffic.
3. A port scan from B is visible in `sudo tcpdump -i bridge100`.
4. Capture permissions: packet capture needs `sudo`.

### Fallback
Record a pcap of a full attack run and build a **replay mode** (section 5) so the whole pipeline and dashboard work without a live network.

---

## 3. Tech stack

- **Language:** Python 3.11+ for sensor, features, detectors, API.
- **Capture:** Scapy (or `tcpdump` piped into a parser). Keep it flow-level.
- **Storage:** SQLite (single file) for flows, devices, alerts, incidents.
- **API:** FastAPI + Uvicorn, with a WebSocket or SSE endpoint for live updates.
- **Detection:** scikit-learn (Isolation Forest), NumPy, pandas, plus rule-based detectors.
- **Local LLM:** Ollama running a small instruction model (Gemma E2B class, or any small model that supports JSON output). Confirm what is installed with `ollama list`. Make the model name a config value.
- **Dashboard:** a single-page web UI served by FastAPI. Plain HTML + vanilla JS or a light framework, with Chart.js or similar for charts. Optimize for readability on a projector.
- **Config:** one `config.yaml`.

---

## 4. Repository layout

```
raven/
  README.md
  NOTES.md
  config.yaml
  requirements.txt
  raven/
    __init__.py
    config.py
    db.py                  # SQLite schema + helpers
    sensor/
      capture.py           # live capture on bridge interface
      replay.py            # replay from pcap
      parse.py             # packet -> flow record
    features/
      windows.py           # multi-timescale rolling windows
      extract.py           # per-host feature vectors
    inventory/
      devices.py           # device table, MAC vendor lookup, DHCP/mDNS names
      fingerprint.py       # device-type classifier (rules + behavior)
    detect/
      rules.py             # scan, brute force, beaconing, DNS tunnel, rogue DHCP, ARP
      baseline.py          # per-device baseline (Isolation Forest / z-scores)
      peers.py             # peer-group comparison
      canary.py            # tripwire contacts
    correlate/
      incidents.py         # chain alerts into incidents
      attack_map.py        # technique tags
    explain/
      sanitize.py          # structured-only inputs to the LLM
      llm.py               # Ollama client, JSON schema output
      templates.py         # deterministic fallback text if LLM fails
    respond/
      suggest.py           # dry-run response suggestions
    budget/
      ranker.py            # alert budget + daily digest
    api/
      server.py            # FastAPI app, REST + live stream
    web/
      index.html
      app.js
      style.css
  labtools/
    baseline_traffic.py    # runs on Mac A
    canary_service.py      # fake internal service
    fake_c2.py             # fake C2 / beacon receiver on Mac C
    dns_server.py          # simple DNS server for tunneling test
    attacks/
      portscan.py
      ssh_bruteforce.py    # against throwaway local test account only
      beacon.py
      dns_tunnel.py
      slow_scan.py         # low-and-slow variant
  eval/
    run_eval.py            # purple-team runner, writes results
    labels.json            # ground truth: attack windows
    results/
  tests/
```

---

## 5. Sensor and flow record

### Capture
- Capture on the gateway bridge interface (configurable, default `bridge100`).
- Run with `sudo`. Document this in the README.
- Do not store payloads. Store only metadata.

### Flow record (what the sensor emits)
```json
{
  "ts": 1730000000.123,
  "src_ip": "192.168.2.3",
  "dst_ip": "192.168.2.2",
  "src_mac": "aa:bb:cc:dd:ee:ff",
  "dst_mac": "aa:bb:cc:dd:ee:00",
  "proto": "tcp",
  "src_port": 51234,
  "dst_port": 22,
  "bytes": 1200,
  "packets": 8,
  "tcp_flags": "S",
  "dns_query": null,
  "dns_qtype": null
}
```
Also capture, as separate event types: DHCP offers/requests (to find rogue DHCP servers and hostnames), ARP replies (for ARP anomaly checks), mDNS names (for device naming).

### Replay mode
`replay.py` reads a pcap file and pushes flow records through the same pipeline at original or accelerated speed. This is the demo safety net. Build it in Phase 1.

---

## 6. Feature extraction

Maintain rolling windows per host at **three timescales: 10 seconds, 5 minutes, 1 hour**. The multi-timescale design is what catches low-and-slow attackers that evade a single short window.

Per host, per window:
- connections started, unique destination IPs, unique destination ports
- failed or reset connection ratio (SYN without completion, RST)
- bytes in, bytes out, out/in ratio
- new destinations never seen before for this host (novelty rate)
- DNS queries per window, unique domains, mean and max Shannon entropy of query names, mean query-name length, TXT/NULL query share
- inter-arrival regularity of connections to the same destination (for beaconing: low variance of intervals)
- share of traffic by service class (web, ssh, dns, other)
- hour-of-day

Compute features in `features/extract.py` and persist snapshots to SQLite every 10 seconds.

---

## 7. Device inventory and fingerprinting

### Inventory
- Key devices by MAC. Track IP history, first seen, last seen.
- Enrich with: MAC vendor (OUI lookup, bundle a small OUI table so it works offline), DHCP hostname, mDNS name.
- Alert on: new device appears, device changes IP unexpectedly, MAC seen with multiple IPs, IP seen with multiple MACs.

### Device type guess
Classify each device as one of: `laptop`, `phone`, `printer`, `server`, `iot`, `unknown`, using:
1. Vendor and hostname hints (rules).
2. Behavior profile: typical ports used, service mix, traffic volume.

Always store a **confidence** and let the admin correct the label in the UI. Corrected labels override guesses.

### Behavior-change alert
If a device behaves unlike its type (printer making SSH connections, phone scanning ports), raise an alert. This is a headline demo feature.

---

## 8. Detection

Use layered detectors. Every detector emits an alert in the schema in section 9.

### 8.1 Rule detectors (deterministic, fast)
- **Port scan:** one source touching many distinct ports or hosts within a window, mostly failed or reset. Evaluate at all three timescales.
- **Brute force:** many connection attempts to one service (SSH 22, RDP 3389, etc.) from one source in a short window, with repeated short sessions.
- **Beaconing:** regular-interval connections to one destination (low variance of inter-arrival times), small payloads.
- **DNS tunneling:** high-entropy, long query names, high TXT/NULL share, high unique-subdomain rate to one parent domain.
- **Rogue DHCP:** DHCP offers from a host that is not the known gateway.
- **ARP anomaly:** repeated gratuitous ARP replies or a MAC claiming the gateway IP.
- **Miner-like traffic:** long-lived steady connection to an unusual destination with a characteristic small bidirectional pattern. Treat as low confidence.

### 8.2 Baseline detector (per device)
- After a learning period (configurable, default short for demo, for example 10 minutes of replay or live traffic; document that real use wants a day), fit an Isolation Forest or z-score model per device on its own feature vectors.
- Score new windows. Output anomaly score plus the **top contributing features** (needed for explanations).
- Learning mode: no alerts from this detector until the baseline is ready, but rule detectors and canary alerts stay active.

### 8.3 Peer-group detector
- Group devices by type (and optionally by role). For each window, compare a device's features to the group median and spread (robust z-score using median and MAD).
- Flag devices far from their peers. This works on day one, before any personal baseline exists.
- Require at least 3 peers in the group to run, otherwise skip and log it.

### 8.4 Canary tripwires
- A fake internal service (on a chosen IP/port) that nothing legitimate should contact. Any contact is a high-confidence alert.
- Optionally use canary hits as trusted labels to calibrate thresholds.

### 8.5 Low-and-slow handling
The slow scan test sends a few probes per minute over an extended period. The 10-second window misses it. The 5-minute and 1-hour windows should catch it. The eval must include a naive single-window detector as a comparison.

---

## 9. Alert and incident schemas

### Alert
```json
{
  "id": "uuid",
  "ts": 1730000000.0,
  "detector": "portscan",
  "host_mac": "aa:bb:cc:dd:ee:ff",
  "host_ip": "192.168.2.3",
  "severity": 0.0,
  "confidence": 0.0,
  "evidence": {
    "unique_ports_10s": 412,
    "baseline_unique_ports_10s": 8,
    "failed_ratio": 0.97
  },
  "technique": "T1046"
}
```
`severity` and `confidence` are numbers from 0 to 1. `evidence` holds numeric features only (no raw strings from the network).

### Incident
```json
{
  "id": "uuid",
  "host_mac": "aa:bb:cc:dd:ee:ff",
  "start_ts": 0,
  "end_ts": 0,
  "alerts": ["alert-id-1", "alert-id-2"],
  "chain": ["T1046", "T1110", "T1071.004"],
  "score": 0.0,
  "summary": null,
  "suggested_actions": []
}
```

### ATT&CK tags (starting set; verify IDs against the current ATT&CK matrix before using in the UI)
- Port scan: T1046 (Network Service Discovery)
- Brute force: T1110 (Brute Force)
- DNS tunneling: T1071.004 (Application Layer Protocol: DNS)
- Beaconing / C2 over web: T1071.001 (Web Protocols)
- Exfiltration over C2: T1041
- ARP spoofing: T1557.002 (ARP Cache Poisoning)

### Correlation
- Group alerts by host (and by attacker-to-victim pair) within a time gap (configurable, default 10 minutes).
- Order by time to form the chain. Increase incident score when stages progress in a plausible order (discovery -> credential access -> command and control).
- Produce incidents, not just alert lists.

---

## 10. Lab attack scripts (own machines only)

All scripts live in `labtools/attacks/`. They must:
- Accept an explicit target IP and refuse to run unless that IP is inside the configured lab subnet (hard check in code).
- Print a banner saying they are for the owner's own lab only.
- Never target public addresses or any machine you do not own.

Scripts:
1. `portscan.py`: fast scan of many ports on the victim.
2. `slow_scan.py`: a few probes per minute over a long period (evasion test).
3. `ssh_bruteforce.py`: repeated failed logins against a throwaway local test account on Mac A. No real credentials, no wordlists of real passwords needed, a short list of obviously fake passwords is fine.
4. `beacon.py`: periodic small requests to `fake_c2.py` on Mac C at a regular interval with small jitter.
5. `dns_tunnel.py`: sends high-entropy long subdomain queries to `dns_server.py` on Mac C.
6. Optional: ARP anomaly simulation, only if it can be done without breaking connectivity. Skip if risky.

`baseline_traffic.py` on Mac A generates normal-looking traffic (page fetches, DNS lookups, occasional SSH) so baselines and false-positive measurement are meaningful.

---

## 11. LLM explanation layer

### Principles
- The LLM writes text. It makes **no decisions**. Detection and scoring are done by code.
- Input is **only structured, sanitized data**: detector name, numeric evidence, device type, ATT&CK technique name, and a whitelist of safe string fields (device type label, hostname truncated and stripped to `[A-Za-z0-9-.]`, max length).
- Never pass raw DNS names, HTTP headers, or any attacker-controllable string. Network data can contain prompt-injection text. This is a deliberate security property to demo.
- Use JSON-schema-constrained output where the runtime supports it. Validate the output and drop anything off-schema.
- If the model fails, times out or returns invalid output, fall back to `templates.py`, which produces deterministic text from the same fields. The system must work with the LLM turned off.

### Output schema
```json
{
  "headline": "string, under 100 chars",
  "what_happened": "string, plain English, 1-2 sentences",
  "likely_cause": "string, with hedged wording",
  "suggested_action": "string",
  "confidence_note": "string"
}
```

### Style rules for the prompt
- Write for a non-expert admin.
- State uncertainty. Use "may", "looks like".
- No legal or definitive claims. Suggest verifying.
- Short.

### Injection demo
Include a test where a poisoned hostname or DNS name containing text such as "ignore previous instructions" is present in traffic. Show that the sanitizer strips it and the output is unaffected.

---

## 12. Alert budget and response

### Budget
- Config: max alerts shown per day (default 5) and per hour.
- Rank incidents by `score = severity x confidence x asset_weight`, with a recency boost.
- Everything beyond the budget goes to a collapsed "lower priority" list and a daily digest. Nothing is deleted.
- Track and display alerts raised vs alerts shown to demonstrate noise reduction.

### Response suggestions (dry run only)
- For high-score incidents, generate a suggested action, for example the exact firewall rule or "isolate this device from the Wi-Fi" instructions.
- Show as a **dry run** with an **Approve** button that logs the decision. The hackathon version does not execute changes on the network. It displays the command the admin would run.
- Never auto-apply anything.

---

## 13. Dashboard

Single page, projector-friendly, large type. Panels:
1. **Incident feed:** top incidents within budget, each with headline, plain-English summary, ATT&CK chain, affected device, confidence, and timeline.
2. **Device inventory:** table with name, vendor, type guess, confidence, first/last seen, status. Edit button to correct the type.
3. **Live traffic view:** per-device activity chart over the three windows.
4. **Noise meter:** alerts raised vs shown.
5. **Purple-team panel:** buttons to launch each attack, plus a results table (time to detect, detected yes/no, false positives).
6. **Mode indicator:** Live or Replay, and Learning or Detecting.

Live updates through WebSocket or SSE. Show a clear "nothing left this machine" indicator (the system makes no external network calls; verify this).

---

## 14. Build order (10-hour plan)

| Phase | Hours | Deliverable |
|---|---|---|
| 0. Lab check | 0-0.5 | Topology verified (section 2), packets visible on bridge, repo scaffold, config |
| 1. Sensor | 0.5-2 | Live capture -> flow records -> SQLite. **Replay mode working.** Record a reference pcap |
| 2. Features + inventory | 2-3.5 | Multi-timescale features, device table, OUI lookup, new-device alert |
| 3. Detection | 3.5-5.5 | Rule detectors, baseline model, peer-group, canary. Attack scripts run and trigger alerts |
| 4. Correlation + explanation | 5.5-7 | Incidents, ATT&CK tags, sanitizer, LLM with fallback templates, alert budget |
| 5. Dashboard | 7-8.5 | Incident feed, inventory, purple-team panel |
| 6. Eval + hardening | 8.5-9.5 | Run eval, record numbers, fix top false positives, injection demo |
| 7. Demo prep | 9.5-10 | Rehearse, record backup video, pre-load model, confirm replay fallback |

If time runs short, cut in this order: miner detection, ARP simulation, device-type correction UI, response suggestions. Never cut replay mode or the eval.

---

## 15. Evaluation (produces the numbers for the pitch)

`eval/run_eval.py`:
- Runs each attack from `labtools/attacks/` against the victim while logging exact start and end timestamps to `eval/labels.json`.
- Compares detector output to those labels.
- Reports per attack type: detected (yes/no), **time to detect**, and which detector fired.
- Reports **false positives per hour** on a baseline-only period of normal traffic.
- Compares three configurations side by side: (a) rules only, single 10-second window; (b) rules with multi-timescale windows; (c) full system. Show that (a) misses the slow scan and (b)/(c) catch it.
- Reports alert reduction from the budget (raised vs shown).
- Writes `eval/results/results.json` and a readable table for the dashboard and slides.

Be honest. Report misses and false positives. Do not train on a public dataset and quote its accuracy as the headline.

---

## 16. Safety, ethics and demo rules

- Attack only machines you own, on the closed lab network. Enforce a subnet allowlist in every attack script.
- Use throwaway accounts and test services only.
- Store metadata only, no payloads.
- No external network calls from the running system. The LLM runs locally.
- The tool is a **prioritization assistant**, not a replacement for a firewall or IDS. Say so in the pitch.
- Device-type guesses and anomaly scores are probabilistic. Show confidence everywhere.
- Keep the response layer approval-gated, dry run only.

---

## 17. Acceptance criteria

The build is done when all of these pass:
1. From a cold start, the system captures live traffic from Mac A and Mac B through Mac C and populates the device inventory automatically.
2. Replay mode runs the full pipeline from a pcap with no network.
3. Each scripted attack (scan, slow scan, brute force, beacon, DNS tunnel) produces an alert, and attacks from one source correlate into one incident with ATT&CK tags.
4. The slow scan is caught by the multi-timescale configuration and missed by the single-window baseline.
5. A new unknown device on the network triggers a new-device alert.
6. Incident text is produced by the LLM from sanitized structured input, and falls back to templates when the LLM is disabled.
7. The poisoned-hostname test does not change the LLM output.
8. The dashboard shows the incident feed, inventory and purple-team panel, and the eval table is generated from real runs.
9. False positives per hour on normal traffic are measured and reported.
10. No attack script runs against an address outside the lab subnet.

---

## 18. Pitch (for the final slide)

"Network security for places with no security team. It installs in minutes, learns what is normal for every device, compares each device with its peers, and tells you in plain English what to do. It tests itself against real attacks and reports its own misses. Nothing leaves your network."

---

## 19. Open items to verify on the real machines

- Internet Sharing interface name and subnet.
- Whether clients on Internet Sharing can reach each other.
- Which Ollama model is installed and whether it supports constrained JSON output.
- Current MITRE ATT&CK technique IDs used in the UI.
- CPU headroom on Mac C when capture, models and dashboard run together. If tight, run the LLM only for incidents that pass the budget filter.

---
