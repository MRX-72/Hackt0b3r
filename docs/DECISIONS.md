# DECISIONS
Format: context, decision, rationale.

## D-001 Python 3.13
Context: default python3 is 3.15.0 and onnxruntime has no cp315 wheel (FACTS). Spec asks 3.11+.
Decision: pin 3.13 (`.python-version`, `requires-python = ">=3.13,<3.14"`); recreate venv with uv. The pre-existing `.venv` (3.15, cactus-needle) was accidentally replaced by `uv sync` on 2026-10-24; cactus-needle 3.2.8 was reinstalled into `.venv-needle` (3.15). Other packages from the old venv (hf CLI etc.) were not restored.
Reason: keeps ONNX available for P0/P1 models; 3.13.15 already installed.

## D-002 Package layout
Context: Parts 3/4/5 list overlapping trees.
Decision: top-level package `raven/` with subpackages exactly as in diagram 05, plus `contracts`. Part 5 wins on overlaps: `ml/` holds iforest, peers, periodicity, streaming, dns_model, ensemble; `detect/` holds the Detector interface and rule detectors, no model code. `explain/` = sanitize, templates, llm client; `nlp/` = embed, rag, guard, ask, faithfulness. Enforcement (`enforce/`) and detection rules (`rules/`) are separate packages so a detection-rule typo cannot touch enforcement. `pipeline/` wires components; `evalharness` is the package for eval code (name avoids clashing with Python's `eval`). Packages are added to diagram 05 in the same commit as their code.
Reason: Part 1 says union with Part 5 winning; architecture test needs one module list.

## D-003 Architecture test source of truth
Decision: `tests/test_architecture.py` parses `A --> B` edges in `docs/diagrams/05-module-dependencies.mmd` (A may import B). Unlisted imports fail.
Reason: Part 2 requires the diagram to be authoritative and enforced.

## D-004 Diagram validation
Decision: use `termaid` (installed) for validation; mmdc is unusable here (no Chrome). Record in NOTES.md that termaid is a weaker check.
Reason: user instruction; spec requires saying which diagrams could not be validated with the official tool.

## D-005 Work in a git repo
Decision: `git init` in the project folder. Personal project, so no PR workflow. `.venv/` ignored.

## D-006 Dependency: pydantic
Context: contracts need validation (numeric-only evidence, MAC/IP shapes, score ranges) and the spec mandates pydantic for config.
Decision: runtime dependency `pydantic>=2`. Replaces hand-written validation and JSON Schema export that the standard library lacks.

## D-007 Contracts grow with components
Decision: `raven/contracts/models.py` holds only shapes a built component uses (Flow, Alert, Incident, AuditEntry). Other shapes (window features, device, rules, notifications, socket messages, registry entries) are added in the commit of the component that first needs them, with schema regeneration (`make schemas`).
Reason: no speculative code; Gate 0 asked for contracts first, and this keeps them used.

## D-008 Storage choices
Decision: stdlib `sqlite3`, STRICT tables, one connection per `Storage` (caller serialises; asyncio use will wrap it), autocommit connection with explicit `BEGIN IMMEDIATE`. No FKs from flow/alert to device because events can precede inventory. Retention days live in config (later); `prune` takes cutoffs.
Reason: no ORM needed; atomic migrations need autocommit mode.

## D-009 Gate 0 gap closure
Decision: coverage floor 90% (`--cov-fail-under`); `make check` runs `pytest -m security` as its own step so the security group cannot silently become empty (pytest exits non-zero when nothing is selected).

## D-010 Dependency: dpkt
Context: parser needs Ethernet/IP/TCP/UDP/ICMP/ARP/DHCP/DNS decoding; hand-rolled DNS name compression and DHCP options are error-prone.
Decision: dpkt 1.9.8 (pure Python, wheel resolves on 3.13), mypy `ignore_missing_imports` for it (no stubs). It raises IndexError on malformed DHCP options and UnicodeDecodeError on non-UTF-8 DNS names, so the parser catches `(UnpackError, struct.error, ValueError, IndexError)`; fuzzing (80k extra examples run ad hoc, 1k in the suite) found no other exception types.
Reason: smaller and better-tested than our own decoder; Scapy is far heavier and slower.

## D-011 Snaplen conflicts with DNS tunnel detection
Context: spec suggests snaplen ~96, but a 255-byte DNS name needs about 340 bytes of frame; truncated DNS fails to parse (counted in `payload_errors`) and the long names are exactly the tunnel signal.
Decision: the daemon component must default snaplen to cover DNS (proposal: 384) and document that payload bytes up to that length can be written to the ring buffer, or capture DNS with a separate larger-snaplen filter. Not decided yet; revisit in component 11. LABEL: ASSUMED that 384 is acceptable privacy-wise; needs the human's call.

## D-012 Parser input is Ethernet frames only
Decision: `FrameParser` takes Ethernet frames. Link-type handling (pcap header, `bridge100` is expected to be EN10MB, ASSUMED) belongs to replay/capture, which reject other link types loudly.

## D-013 CLI first, GUI last (user decision, 2026-10-24)
Context: user wants only a CLI for now; the GUI is built at the very end.
Decision: Stage 2 item 5 (GUI) moves after item 12 and before Stage 3 polish. Until then every user-facing capability is reachable through the CLI (including packets view as `raven packets live|show`, `capture export`, modes, enforce proposals, notify test, `ask`). Design rules so a GUI can be embedded later without refactoring:
1. All behavior lives behind one service surface in `api/` (typed request/response models from `contracts/`, no formatting, no printing). REST/WebSocket are thin adapters over it; the CLI is a client of that surface and only formats output (human text or `--json`).
2. `cli/` never imports core logic (already enforced by diagram 05: cli -> contracts, config only), so the GUI is just another client of the same surface.
3. Every list/detail response is a contract model with stable JSON Schema in `schemas/`; a GUI binds to those.
4. A live event stream (incidents, alerts, status, drop counters) exists in the API from the start, because the CLI needs `--follow` and the GUI needs the same feed.
5. No presentation strings in core: severity labels, colors and wording are produced by the client; untrusted strings stay data (the GUI will render with textContent per spec).
Reason: keeps the GUI a pure client; P0 acceptance items about the GUI (R-GUI-001, GUI parts of R-PKT-001) are deferred, not dropped.

## D-014 Priority order changed by the user (2026-10-24)
Decision: build the detection engine first, then notifiers (Slack, Discord, Telegram), then a pluggable local LLM summariser, with a CLI that can show or hide network traffic. Order: config+secrets -> replay -> windows/features -> detectors+engine -> correlation -> sanitizer+templates -> notifiers -> LLM runtimes -> pipeline/service -> CLI. The remaining Stage 1 items (event bus, baseline/peers ML, enforcement validator, daemon, registry, API server) follow. Spec's "core before surround" is overridden for notify and LLM by the user's explicit instruction; detection stays first.

## D-015 CLI talks to a service facade, not to the pipeline
Decision: add `api/service.py` (`RavenService`, in-process facade; the HTTP server is later another adapter over it). `cli --> api` is added to diagram 05; `cli` must not import `pipeline` or detection modules directly. The CLI runs the service in-process for now.
Reason: the HTTP API server does not exist yet but the CLI must work; a GUI later calls the same facade or its HTTP adapter (D-013).

## D-016 Config is TOML; secrets in a gitignored 0600 file
Decision: `config.toml` (stdlib `tomllib`, no PyYAML dependency) validated by pydantic. Secrets (webhook URLs, bot token, optional LLM API key) are read from `secrets.env` (KEY=VALUE, gitignored, must be mode 0600 or the loader refuses) with environment variables taking precedence. Config holds no secrets and logs/API redact them.
Reason: user asked for keys in a file I create; spec forbids secrets in config.yaml and the repo. Keychain stays a backlog option. Spec said config.yaml; TOML avoids a dependency.

## D-017 Faithfulness checks live in explain/
Decision: `explain/faithfulness.py` (not `nlp/`), because `nlp -> explain` in diagram 05 and the explanation path needs the checks. Amends D-002.

## D-018 Notifier transport and LLM runtimes use stdlib urllib
Decision: no HTTP dependency. A `Transport` callable (url, body, headers) -> (status, body) is injected; the default uses `urllib.request` with a timeout, and tests use fakes. LLM adapters: `ollama` (native `/api/chat`, `format` = JSON schema) and `openai` (any OpenAI-compatible server, including llama.cpp `llama-server`, via `/v1/chat/completions` with `response_format`). Any model name can be configured.

## D-019 Detection hardening pass (after an adversarial matrix, 2026-10-24)
Context: `tests/test_detection_matrix.py` (attack variants, benign look-alikes, duplicated packets, 12-seed benign soak) exposed real flaws in the first detectors.
Fixed: SYN retransmissions counted as new attempts; a server RST after an accepted connection turned it into a failure (hid brute force); servers' UDP replies counted as connections (false beacons); beacons on refused ports; brute-force logins also reported as beacons; shared services (mail polling, CDN hashed names) flagged; 600-byte beacon limit was far below a TLS handshake; byte counts shrank with snaplen (now from the IP length); unbounded state under floods (caps + `state_capped`); `.co.uk`-style names grouped together.
Added knobs: `trusted_ips`, `beacon_allow_destinations`, `dns_ignore_domains`, `beacon_popular_hosts`, `dns_popular_hosts`, `beacon_min_completed_ratio`.
Not fixed (inherent, documented): one device on a fixed schedule to an unshared server looks like a beacon; one device resolving many long hashed CDN names looks like a tunnel; UDP/ICMP scans unseen; evaluation waits for the next packet.
Decision: detection is NOT "flawless", so per the user's condition no new detectors were added in this pass.

## D-020 Flows are not stored by default
Decision: `[storage] store_flows = false`. Detection runs in memory; storing every packet cost disk and privacy for no current consumer. Retention (`flow_retention_days`, `alert_retention_days`) is applied hourly during `watch` only, because pruning by capture time would delete replayed historic captures.

## D-028 Security audit and hardening (user request, 2026-10-25)
Method (reproduce with `make audit`: `bandit -ll` on raven/ and tools/ with B608 and B310 skipped for the reasons in the Makefile, then `pip-audit` on the runtime pins; on 2026-10-25 it printed `No known vulnerabilities found`): read the trust boundaries (HTTP transport, tcpdump launch, config and secrets loading, storage, the console server, file creation under `sudo`), tried to break them, ran `bandit` (only the known fixed-fragment SQL warnings remain, each justified) and `pip-audit` on the runtime dependencies (none known). Each fix is its own commit with a regression test. Fixed: redirects were followed and re-sent the `Authorization` header to another host (proven with a local two-server test); replies were read unbounded (now 4 MiB cap); databases were created with the umask default (now 0600, existing ones tightened, never created through a dangling symlink, and tightened only through an fstat of a single-link regular file, never through a link); `init` wrote `secrets.env` then chmod-ed it (now created private in one step); as root a `./config.toml` planted by another user was honoured (now only root- or invoking-user-owned, not group/world-writable files); interface names and BPF filters beginning with `-` reached tcpdump as options (now refused); the console accepted requests with a foreign `Origin` (now refused), had no socket timeout (30 s), unlimited event streams (cap 16) and an unbounded pending-event list (cap 5000, drops counted); test messages could be spammed (one per channel per 5 s); a root `raven ui` launched a browser as root (no longer); the LLM API key could be sent over plain http to a non-local host (refused); webhooks could be plain http and Telegram values could contain URL characters (now validated, and rejected secrets are not echoed in the error). Not fixed, by decision: the Slack and Telegram credentials from `wh.md` remain in the history of commit "Web console ..." (rewriting history again is the owner's call; rotating the keys is the real fix); the console token appears in the URL it prints and passes to the browser; a local user who has the token can use the console (by design).

D-028 follow-up (code review of the hardening series): a malformed credential is now a `SecretsError` (so `doctor` and `config show` still work), an unusable database is reported as one line instead of a traceback (CLI and console), validators use `fullmatch` and webhooks need a host, a config skipped by root is announced, file tightening goes through `fstat`/`fchmod`, a refused interface fails before the capture lock or database exist, `init` sets exact modes, the console retries a refused stream and shows dropped events, and a connection leak when opening a bad database was closed.

## D-027 Console tabs: notifications, devices, health (user request, 2026-10-25)
Notifications: the existing `notification_delivery` table is now read by the console; migration 007 adds `headline` and `label` so a row keeps what was sent (the incident summary changes as it grows); the pipeline passes them through a hook. Test sends go through `Notifier.test`, are not logged as deliveries (no incident to hang them on) but are audited, and are limited to channels with credentials. Devices: the `device`/`device_ip` tables from the first schema are now populated by the pipeline (migration 006 adds packet and byte totals), flushed every 2000 flows, every 10 s on a live tick, and at the end of a run; at most 2000 distinct MACs per flush; multicast/broadcast MACs and group IPs are skipped; the admin name goes in `type_label_admin`, sanitised, 40 characters, audited. Health: a secret-free `RavenService.console_info`, `Hub.health`, a fresh read-only Storage per request and the `doctor` checks cached for 10 s (the checks touch the network and the LLM). New JSON endpoints are cookie- and Host-checked like the rest; the three POST actions (history delete, device name, test send) also need the `X-Raven` header and validated bodies of at most 16 KB. `tabs.js` holds the three tabs and is covered by the no-HTML-sinks test. Known limit: a device is a MAC, so devices behind a router appear as one device (the router).

## D-026 N-gram DNS model and Isolation Forest (user request, 2026-10-25)
Both implemented in pure Python (no numpy/sklearn: no new dependency; vectors are ~13 numbers). `ml/ngram.py`: character-trigram surprisal over a small built-in seed, a 5th signal in the DNS tunnelling rule (still needs two signals). `ml/iforest.py` + `detect/behavior.py`: forest over the 10 s per-device vector, learns the network's own recent normal, warm-up 200 active windows, anomalous vectors not learned, only alerts when a count/volume is >2x the baseline maximum (a plain forest false-alarmed on benign synthetic networks), suppressed while a named attack is active on the device, severity capped at 0.6. Reports technique `RVN001`, which is not ATT&CK, has no attack-chain stage (stage 0; correlator and sanitizer updated). Enabled by default because the ablation (docs/ABLATION.md) shows each catches something the rules miss with zero false alarms on the benign suite; real-network false-alarm rate is UNKNOWN (H-12) and both can be switched off in `[detection.ml]`. Diagram 05: `ml --> features` replaced by `features --> ml` (features calls the n-gram model; ml imports only contracts/config). Autoencoder is still not built.

## D-025 Deleting history entries (user request, 2026-10-25)
Supersedes the "DELETE blocked" part of D-023. Migration 004 drops the delete trigger on `anomaly_log` (the update trigger stays). The only delete path is `Storage.delete_anomalies(ids)`, which removes the chosen ids and writes one `audit_log` row listing them; the web console exposes it as `POST /api/history/delete` (validated `HistoryDelete`, 1..500 positive ids, 16 KB body cap) behind the same cookie and Host checks plus a required `X-Raven: 1` header (blocks cross-site requests). The UI needs two clicks to delete. Deleting a history entry does not touch the incident or alert tables.

## D-024 Packaging and persistent data (user request, 2026-10-25)
Decision: all user data lives in one per-user folder, `$RAVEN_HOME` or `~/.raven` (under `sudo`, the invoking user's, via `SUDO_USER`), instead of the working directory: `raven.db`, `config.toml`, `secrets.env`. Config is found via `--config`, `$RAVEN_CONFIG`, `./config.toml`, `<home>/config.toml`; relative paths inside a config mean "next to that file". The folder is created 0700; under root the DB files and folder are chowned to `SUDO_UID/GID` so a later non-root `ui`/`history` can open them (unit-tested, not yet run under real sudo).
Why: the old default `raven.db` in the cwd meant history vanished depending on where the command was run and root runs left root-owned files.
Cleanup: removed 12 empty placeholder packages (no code; diagram 05 keeps the planned modules), `tools/localhost_scan.py` (superseded by `localhost_attacks.py scan`), the stage briefs, NOTES.md, the repo `config.toml` (duplicate of the shipped template), the pitch deck build tooling (the two .pptx files are kept) and tracked editor session files. `spikes/` is kept: H-01 and H-04 in HUMAN_VERIFICATION still depend on them. The one-file brief was removed once `docs/spec/` held its split parts.
Found while testing the built wheel: the `secrets.env` template was git-ignored, hence missing from clones and wheels; it is now `secrets.env.template`. Install: `uv tool install .`.

## D-023 Local web console (user request, 2026-10-25)
Context: D-013 deferred the GUI; the user asked for a minimal, sharp "security console" with moving packets and a permanent anomaly history.
Decision: `raven ui` serves a vendored, dependency-free single-page console from `raven/api/` (stdlib `http.server`, SSE, canvas): LIVE (network view with packets in flight, alert stack, packet table, rate chart) and HISTORY (filters, search, detail, CSV). Security per spec: 127.0.0.1 only, per-run token trade for a SameSite=Strict HttpOnly cookie, Host-header check, strict CSP (no inline script/style, no CDN), textContent only (a test forbids HTML sinks), CSV formula neutralising, validated query model.
History lives in a new append-only `anomaly_log` table (migration 003; UPDATE/DELETE blocked by triggers; retention never touches it), written by the pipeline for every report with source live/replay, so it survives restarts and pruning. `raven history` shows the same data in the terminal.
Threading: capture runs in its own thread; HTTP threads open their own read connections (WAL), so the UI never shares a SQLite connection.

## D-022 Live watch heartbeat, stoppable capture, phase-tested bursts
Found by the four-attack localhost test: a beacon was missed when the 10 s evaluation grid fell badly (the "still active" check was shorter than the grid) and live evaluation waited for the next packet. Fixes: beacon staleness is `max(3 intervals, 10 s)`; `watch` reads capture in a thread and ticks detectors every second (`DetectionEngine.advance`); `capture_live` honours a stop event and duration without packets. `test_short_bursts_are_caught_whatever_the_phase_of_the_10s_grid` sweeps 12 grid phases for each attack.

## D-021 Loopback and raw-IP captures (found by the first real localhost test)
Context: `tcpdump -i lo0` is link type NULL, which the Ethernet-only reader rejected.
Decision: loopback (0, 108) and raw-IP (12, 101) captures are wrapped in a synthetic Ethernet frame with stand-in MACs derived from the IPs (`02:00` + 4 address bytes). Same-host traffic on lo0 is therefore one device. DNS/mDNS names are read by a small name walker (dpkt refuses whole messages containing NSEC/HTTPS/RRSIG records). Payloads cut short by snaplen are counted as `truncated_payloads`, not `payload_errors`. `capture_live --for` now uses a timer so it stops on a silent link, and a failing capture command reports its own error text.
