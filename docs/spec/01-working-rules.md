# PART 2: WORKING RULES AND BUILD ORDER (read first when starting work)


You are building Small-Network Sentinel. Read Part 1 (precedence), then Parts 3, 4 and 5 (what to build), then follow this part for **how** to work:

1. Part 3 (Base Specification): base
2. Part 4 (V2 Addendum): overrides Part 3
3. Part 5 (Model Roster): overrides both on anything about models

If parts conflict, follow the precedence in Part 1. If a conflict or ambiguity affects design, record the decision in `docs/DECISIONS.md` (one short entry: context, decision, reason) and continue. Do not stop to ask unless you are truly blocked.

**Work order is fixed: design docs, then core, then everything around the core, then polish.** Do not start a stage until the previous stage's gate passes.

---

## Stage 0: Design documents (before any product code)

Produce these first. They are the source of truth, and code must match them.

### 0.1 Mermaid diagrams (`docs/diagrams/*.mmd`)

Use as many `.mmd` files as needed, one concern per file, each with a title comment. Minimum set:

| File | Content |
|---|---|
| `01-system-context.mmd` | Actors (admin, devices, attacker lab), Sentinel, external services (Slack/Telegram/Discord, optional API model). Show what crosses the trust boundary. |
| `02-network-topology.mmd` | Gateway Mac, victim Mac, attacker Mac, bridge interface, private network, optional uplink. |
| `03-process-architecture.mmd` | `sentineld` (root) vs `sentinel-api` (unprivileged), Unix socket, CLI, GUI, privilege boundary. |
| `04-data-flow-cascade.mmd` | Packets to flows to windows to detectors to ensemble to correlation to explanation to notify/UI. Mark which stages are deterministic, ML, or LLM. |
| `05-module-dependencies.mmd` | Module graph with **allowed dependency direction**. This is enforced by a test (see 1.4). |
| `06-data-model.mmd` | ER diagram of the SQLite schema. |
| `07-detection-sequence.mmd` | Sequence: a port scan from one host through to an incident and a notification. |
| `08-incident-lifecycle.mmd` | State diagram: open, correlated, explained, notified, acknowledged, dismissed, resolved. |
| `09-enforcement-approval.mmd` | Sequence + guards: proposal, validation (safelist, lockout, TTL, blast radius), dry run, approval, apply, expiry, revoke. |
| `10-notification-flow.mmd` | Routing, dedupe, rate limit, retry, circuit breaker, sanitization step. |
| `11-model-registry.mmd` | Roles, runtimes, load/unload, RAM cap, fallbacks. |
| `12-build-order.mmd` | DAG of components showing core (hard) vs surround, and the order you will build them. |

Add more diagrams if a component is complex enough to need one. Every diagram must **render**. Validate with `npx @mermaid-js/mermaid-cli` (`mmdc -i file.mmd -o /dev/null`) if available. If you cannot validate a diagram, say which ones in `NOTES.md` instead of claiming they render.

### 0.2 What we are building (`docs/WHAT_WE_ARE_BUILDING.md`)

A single plain-language document, readable by a judge or a new teammate in ten minutes:
- the problem and the target users (small teams, colleges, offices),
- what the product does and, equally important, **what it deliberately does not do**,
- the architecture in prose, referencing each diagram by filename,
- the core components and why they are hard,
- the safety properties (privilege separation, approval-gated enforcement, sanitized LLM and notification input, local-first),
- the model roster and each model's single job,
- the build order and the definition of done,
- known risks and what is unverified.

### 0.3 Feasibility spikes (only for real unknowns)

Some facts decide the whole design and cannot be assumed: whether packet capture works on the bridge interface, whether clients on Internet Sharing can reach each other, how a pf anchor behaves next to Internet Sharing, and whether the chosen runtimes install cleanly.

- You cannot test the Mac network from a sandbox. Write small, clearly named spike scripts in `spikes/` that the **human runs on the gateway Mac**, each printing a pass/fail line, and list them in `docs/HUMAN_VERIFICATION.md` with exact commands and what to report back.
- Design so the core works without the answers: everything must run from a pcap replay and synthetic fixtures. Hardware-dependent facts only affect configuration.
- When a spike's finding is recorded in `docs/DECISIONS.md`, **delete the spike**. `spikes/` must be empty or absent at release.

### Gate 0
- All diagrams exist and are consistent with each other and with the specs.
- `WHAT_WE_ARE_BUILDING.md` is complete.
- `docs/HUMAN_VERIFICATION.md` lists every hardware-dependent assumption.
- Create the empty project skeleton with tooling only: package layout from the spec, `pyproject.toml`, formatter and linter config, type checker config, test runner, dead-code check, a Makefile with `make check`. No product logic yet.

---

## Stage 1: Core (the hard, load-bearing components, built first)

Build **only** these, in this order, each fully finished before the next. They are the components where mistakes are expensive or the project fails without them.

| # | Component | Why it is core |
|---|---|---|
| 1 | **Storage layer** (SQLite WAL, migrations, schema from diagram 06, retention) | Everything depends on it. |
| 2 | **Flow model and packet parser** (safe against malformed input, fuzz-tested) | Attack surface, and the base of all detection. |
| 3 | **Replay source** (pcap to flows through the real pipeline) | Makes everything testable without the network. |
| 4 | **Multi-timescale window and feature engine** (10 s, 5 min, 1 h) | The basis of detection, including low-and-slow. |
| 5 | **Event bus with backpressure and drop accounting** | Capture must never block. |
| 6 | **Detector interface + core detectors**: port scan, brute force, beaconing (periodicity), DNS (entropy rules + n-gram model) | The product's detection value. |
| 7 | **Baseline and peer-group scoring** (Isolation Forest, robust z-scores) | The "zero-config, works on day one" claim. |
| 8 | **Correlation engine** (alerts to incidents, ATT&CK tags) | Turns alerts into stories. |
| 9 | **Input sanitizer** (the single function that decides what any LLM, notification or UI may see) | The central security property. |
| 10 | **Enforcement validator** (safelist, lockout protection, TTL, blast radius) and pf rule renderer, **dry-run only** | Safety critical: this is what keeps a mistake from cutting off the admin. |
| 11 | **Privilege-separated daemon**: capture into the pipeline and a 0600 Unix socket protocol | The root boundary. |
| 12 | **Model registry** (checksums, RAM cap, lazy load, fallbacks) with the explanation path (LLM + faithfulness check + template fallback) | Needed before any model feature. |
| 13 | **API skeleton** (token auth, REST + live stream) exposing incidents, devices and status | The spine for CLI and GUI. |

### Definition of done for each core component
1. It matches the diagrams. If the design had to change, update the diagram and `WHAT_WE_ARE_BUILDING.md` in the **same commit**.
2. It has tests that would fail if the component were wrong: unit tests with synthetic fixtures, plus a replay-based test where relevant. Parsers and the display-filter-style input handlers have fuzz or property tests.
3. `make check` passes (format, lint, types, tests, dead-code scan, dependency-direction test).
4. It is used by something. Core components are wired into the pipeline as they land, and an end-to-end replay test grows with each one. Nothing is built "for later".
5. One commit per component, message states what and why.

### Gate 1 (core complete)
Run the whole pipeline end to end on a recorded or synthetic attack pcap and show, with no GUI, no CLI polish and no notifications:
- the replay produces alerts for scan, slow scan, brute force, beacon and DNS tunnel,
- alerts correlate into incidents with ATT&CK tags,
- the slow scan is missed by a single short window and caught by the multi-timescale config (this is a test, not a claim),
- sanitized explanation text is produced, and the template fallback works when the model is disabled,
- an enforcement proposal passes or fails validation correctly, including safelist and lockout cases,
- poisoned hostnames cannot reach LLM input.

Write the results to `docs/GATE1.md`, then continue to Stage 2 unless the gate failed. If it failed, fix the core. Do not build around a broken core.

---

## Stage 2: Everything around the core

Only now build, in this order, each against the same definition of done:

1. **CLI** (`sentinel`), including `doctor`, `status`, `incidents`, `devices`, `replay`, `eval`.
2. **Device inventory and fingerprinting** and the new-device / behavior-change alerts.
3. **Monitoring modes** (config bundles, audited switching, auto-expiry for scoped modes).
4. **Notifications**: one channel first (Discord or Slack webhook), then the others, with routing, dedupe, rate limiting, retry, circuit breaker, secrets from env/Keychain, and sanitized content.
5. **GUI**: Overview, Incidents, Devices, Modes, Purple-team first; then Packets, Rules, Notifications, Models, Audit. Untrusted strings rendered as text only, strict CSP, vendored assets, no CDN.
6. **Packets view**: list, detail, hex, display-filter parser, conversations, pcap export, click-through from incidents.
7. **Detection rule engine** (YAML, validation, test mode, defaults, versioning).
8. **Embeddings**: incident dedupe, "similar past incidents", runbook RAG.
9. **`sentinel ask`** (Needle 2 with the read-only allowlist, guard model, validation).
10. **Additional models** from the roster (device-type classifier, learned ranker, char-CNN, forecaster), each added only if its ablation justifies it.
11. **Enforcement apply path** (real pf anchor with TTL and rollback), only after the human has confirmed the pf spike in `HUMAN_VERIFICATION.md`.
12. **Purple-team runner and eval** (attack scripts with the lab-subnet hard check, ablation table, LLM/embedding/Needle benchmarks, injection suite).

After each item: `make check` green, diagrams and docs updated if the design moved.

### Gate 2
All P0 acceptance criteria across Parts 3, 4 and 5 pass. Record results in `docs/GATE2.md`, including which criteria **could not be verified without the human's hardware**.

---

## Stage 3: Polish and release prep

- Remove anything unused. Run the dead-code scan and delete what it finds.
- Re-read each diagram against the code and fix drift.
- README: install, `sentinel doctor`, run replay, run live, run the demo, run the eval.
- `MODELS.md` with source, license and checksum for every model.
- Final `make check`, then a clean-checkout install test.

---

## Code quality rules (apply to every line)

The goal is a small, correct, readable codebase that a judge can audit. **Slop is a defect.**

**Do not write:**
- placeholder or stub code, `pass` bodies, "TODO: implement later" for something the spec requires. If it isn't built yet, it isn't in the repo.
- unused functions, classes, parameters, imports, config keys, dependencies, files or feature flags.
- speculative abstraction: no base classes, plugin systems, factories or generic layers until there are at least two real implementations that need them. (The detector and enforcement-backend interfaces are the specified exceptions.)
- dead branches and defensive code for states that cannot occur. Validate at trust boundaries (network input, API input, config, model output) and trust internal invariants.
- commented-out code. Delete it; git remembers.
- duplicated logic. Extract it the second time it appears.
- broad `except Exception: pass`, silent failure, or swallowed errors. Fail loudly or handle specifically, and count and log degradations.
- magic numbers. Thresholds and limits live in config with defaults and a comment on why.
- vague names, giant functions, deep nesting. Prefer small functions with one job and clear names.
- gratuitous dependencies. Every dependency must be justified in `docs/DECISIONS.md` (what it replaces, why the standard library or an existing dependency is not enough).
- comments that restate the code. Comment **why**, not what.
- claims in docs, logs or UI that the code does not back up.

**Do write:**
- type hints throughout, checked in `make check`.
- tests alongside each component, named for the behavior they prove.
- explicit units in names (`window_seconds`, `bytes_out`).
- deterministic code where possible (seeded randomness, injectable clock) so tests don't flake.
- structured errors with actionable messages, especially in `sentinel doctor`.

**Enforced by `make check` (create these in Gate 0):**
- formatter + linter (for example ruff), strict type check (for example mypy/pyright),
- tests with a coverage report (aim for meaningful coverage of the core, not a vanity number),
- dead-code scan (for example vulture) with an empty allowlist unless justified in a comment,
- unused-dependency check,
- an **architecture test** that parses imports and fails if the dependency direction in `05-module-dependencies.mmd` is violated (for example, `ml/` must not import `api/`; nothing but `explain/sanitize` output may reach `explain/llm`),
- a **security test group**: hostname/DNS-name XSS inertness, prompt-injection path, notification sanitization, enforcement safelist/lockout, parser fuzz.

---

## Working agreements

- **Commit small and often.** One logical change per commit, with the trailers your environment specifies.
- **Keep `NOTES.md`** as a short running log: what was built, what deviated from the specs and why, what is unverified.
- **Never claim hardware results you didn't observe.** Anything that needs the three Macs goes on `docs/HUMAN_VERIFICATION.md` with exact commands. Say "not verified on hardware" where true.
- **Safety stays on:** attack scripts hard-check the lab subnet, enforcement stays dry-run and approval-gated, and secrets never appear in the repo, logs or API responses.
- **When time is short, cut surround, never core.** Order of cuts: extra notification channels, additional models, Forensics/Maintenance modes, rule versioning, forecaster. Never cut: replay mode, the sanitizer, the enforcement validator, the eval.
- **Report progress in the diff, not in chat essays.** At each gate, write the gate document, then continue.

---

## Start here

1. Read Parts 1, 3, 4, 5 and 6. Do the Part 6 Stage 0 setup: split the spec into `docs/spec/`, create `CLAUDE.md`, `docs/REQUIREMENTS.csv`, `docs/FACTS.md`, `docs/STATE.md`, and the `contracts/` module plan.
2. Create `docs/diagrams/` and write all diagrams from 0.1, validating them.
3. Write `docs/WHAT_WE_ARE_BUILDING.md`.
4. Write `docs/HUMAN_VERIFICATION.md` and the spike scripts.
5. Build the tooling skeleton and `make check`.
6. Pass Gate 0, then begin Stage 1 with component 1.

---
