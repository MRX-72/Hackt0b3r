# DECISIONS
Format: context, decision, reason.

## D-001 Python 3.13
Context: default python3 is 3.15.0 and onnxruntime has no cp315 wheel (FACTS). Spec asks 3.11+.
Decision: pin 3.13 (`.python-version`, `requires-python = ">=3.13,<3.14"`); recreate venv with uv. The pre-existing `.venv` (3.15, cactus-needle) was accidentally replaced by `uv sync` on 2026-10-24; cactus-needle 3.2.8 was reinstalled into `.venv-needle` (3.15). Other packages from the old venv (hf CLI etc.) were not restored.
Reason: keeps ONNX available for P0/P1 models; 3.13.15 already installed.

## D-002 Package layout
Context: Parts 3/4/5 list overlapping trees.
Decision: top-level package `sentinel/` with subpackages exactly as in diagram 05, plus `contracts`. Part 5 wins on overlaps: `ml/` holds iforest, peers, periodicity, streaming, dns_model, ensemble; `detect/` holds the Detector interface and rule detectors, no model code. `explain/` = sanitize, templates, llm client; `nlp/` = embed, rag, guard, ask, faithfulness. Enforcement (`enforce/`) and detection rules (`rules/`) are separate packages so a detection-rule typo cannot touch enforcement. `pipeline/` wires components; `evalharness` is the package for eval code (name avoids clashing with Python's `eval`). Packages are added to diagram 05 in the same commit as their code.
Reason: Part 1 says union with Part 5 winning; architecture test needs one module list.

## D-003 Architecture test source of truth
Decision: `tests/test_architecture.py` parses `A --> B` edges in `docs/diagrams/05-module-dependencies.mmd` (A may import B). Unlisted imports fail.
Reason: Part 2 requires the diagram to be authoritative and enforced.

## D-004 Diagram validation
Decision: use `termaid` (installed) for validation; mmdc is unusable here (no Chrome). Record in NOTES.md that termaid is a weaker check.
Reason: user instruction; spec requires saying which diagrams could not be validated with the official tool.

## D-005 Work in a git repo
Decision: `git init` in /Users/mrx/Hacktober. Personal project, so no PR workflow. `.venv/` ignored.

## D-006 Dependency: pydantic
Context: contracts need validation (numeric-only evidence, MAC/IP shapes, score ranges) and the spec mandates pydantic for config.
Decision: runtime dependency `pydantic>=2`. Replaces hand-written validation and JSON Schema export that the standard library lacks.

## D-007 Contracts grow with components
Decision: `sentinel/contracts/models.py` holds only shapes a built component uses (Flow, Alert, Incident, AuditEntry). Other shapes (window features, device, rules, notifications, socket messages, registry entries) are added in the commit of the component that first needs them, with schema regeneration (`make schemas`).
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
Decision: Stage 2 item 5 (GUI) moves after item 12 and before Stage 3 polish. Until then every user-facing capability is reachable through the CLI (including packets view as `sentinel packets live|show`, `capture export`, modes, enforce proposals, notify test, `ask`). Design rules so a GUI can be embedded later without refactoring:
1. All behavior lives behind one service surface in `api/` (typed request/response models from `contracts/`, no formatting, no printing). REST/WebSocket are thin adapters over it; the CLI is a client of that surface and only formats output (human text or `--json`).
2. `cli/` never imports core logic (already enforced by diagram 05: cli -> contracts, config only), so the GUI is just another client of the same surface.
3. Every list/detail response is a contract model with stable JSON Schema in `schemas/`; a GUI binds to those.
4. A live event stream (incidents, alerts, status, drop counters) exists in the API from the start, because the CLI needs `--follow` and the GUI needs the same feed.
5. No presentation strings in core: severity labels, colors and wording are produced by the client; untrusted strings stay data (the GUI will render with textContent per spec).
Reason: keeps the GUI a pure client; P0 acceptance items about the GUI (R-GUI-001, GUI parts of R-PKT-001) are deferred, not dropped.

## D-014 Priority order changed by the user (2026-10-24)
Decision: build the detection engine first, then notifiers (Slack, Discord, Telegram), then a pluggable local LLM summariser, with a CLI that can show or hide network traffic. Order: config+secrets -> replay -> windows/features -> detectors+engine -> correlation -> sanitizer+templates -> notifiers -> LLM runtimes -> pipeline/service -> CLI. The remaining Stage 1 items (event bus, baseline/peers ML, enforcement validator, daemon, registry, API server) follow. Spec's "core before surround" is overridden for notify and LLM by the user's explicit instruction; detection stays first.

## D-015 CLI talks to a service facade, not to the pipeline
Decision: add `api/service.py` (`SentinelService`, in-process facade; the HTTP server is later another adapter over it). `cli --> api` is added to diagram 05; `cli` must not import `pipeline` or detection modules directly. The CLI runs the service in-process for now.
Reason: the HTTP API server does not exist yet but the CLI must work; a GUI later calls the same facade or its HTTP adapter (D-013).

## D-016 Config is TOML; secrets in a gitignored 0600 file
Decision: `config.toml` (stdlib `tomllib`, no PyYAML dependency) validated by pydantic. Secrets (webhook URLs, bot token, optional LLM API key) are read from `secrets.env` (KEY=VALUE, gitignored, must be mode 0600 or the loader refuses) with environment variables taking precedence. Config holds no secrets and logs/API redact them.
Reason: user asked for keys in a file I create; spec forbids secrets in config.yaml and the repo. Keychain stays a backlog option. Spec said config.yaml; TOML avoids a dependency.

## D-017 Faithfulness checks live in explain/
Decision: `explain/faithfulness.py` (not `nlp/`), because `nlp -> explain` in diagram 05 and the explanation path needs the checks. Amends D-002.

## D-018 Notifier transport and LLM runtimes use stdlib urllib
Decision: no HTTP dependency. A `Transport` callable (url, body, headers) -> (status, body) is injected; the default uses `urllib.request` with a timeout, and tests use fakes. LLM adapters: `ollama` (native `/api/chat`, `format` = JSON schema) and `openai` (any OpenAI-compatible server, including llama.cpp `llama-server`, via `/v1/chat/completions` with `response_format`). Any model name can be configured.
