# What we are building

Status labels: statements about the real network or hardware are ASSUMED until `docs/HUMAN_VERIFICATION.md` items are reported back.

## Problem and users
Small teams, colleges and offices have no security staff. Commercial tools assume one. Raven is a network anomaly detector that runs on one MacBook acting as the gateway, learns what each device normally does, and tells an admin in plain English what to look at.

## What it does
Passively captures traffic crossing the gateway, builds flows and multi-timescale features, detects scans, brute force, beaconing and DNS tunneling, scores devices against their own baseline and their peers, correlates alerts into incidents tagged with ATT&CK techniques, explains incidents in plain text, notifies the admin on one opt-in channel, and proposes firewall rules for human approval. It tests itself with scripted attacks against a closed lab and reports its own misses.

## What it deliberately does not do
- No TLS decryption, payload analysis or DPI. Default capture is headers only.
- No automatic blocking. Enforcement is dry-run, human-approved, TTL-bound.
- No LLM decisions. LLMs only write explanation text from sanitized structured fields.
- No cloud dashboards, multi-tenant, or enterprise scale. It is a prioritization assistant, not an IPS.
- A switched, encrypted Wi-Fi network shows only your own traffic; the gateway topology is what makes capture meaningful.

## Architecture (diagrams in `docs/diagrams/`)
- Context and trust boundary: `01-system-context.mmd`. Lab layout: `02-network-topology.mmd`.
- Two processes: `ravend` (root: capture, ring buffer, approved pf changes) and `raven-api` (unprivileged: everything else), joined by a 0600 Unix socket: `03-process-architecture.mmd`.
- Data path packets → flows → windows → detectors → ensemble → incidents → sanitizer → explanation: `04-data-flow-cascade.mmd`, example in `07-detection-sequence.mmd`, incident states in `08-incident-lifecycle.mmd`.
- Import direction between modules, enforced by a test: `05-module-dependencies.mmd`.
- Storage: `06-data-model.mmd`. Enforcement guards: `09-enforcement-approval.mmd`. Notifications: `10-notification-flow.mmd`. Models: `11-model-registry.mmd`. Order of work: `12-build-order.mmd`.

## Core components and why they are hard
Storage (everything depends on it); the packet parser (hostile input, must never crash); replay (makes all of it testable offline); multi-timescale windows (catches low-and-slow attackers a single window misses); the event bus (capture must never block); detectors and baselines (false positives matter more than headline accuracy); correlation; the sanitizer (the one gate between hostile network strings and any LLM, notification or UI); the enforcement validator (stops a mistake from locking out the admin); the privilege boundary; the model registry; the API.

## Safety properties
Privilege separation; approval-gated enforcement with safelist, lockout protection, TTL, blast radius, audit and revoke; sanitized LLM and notification input with faithfulness checks and template fallback; local-first, with notifications as the only opt-in external traffic and off in Air-gapped and Replay modes; secrets only in env/Keychain.

## Model roster
Each model has one job and ships enabled only if the ablation table justifies it. P0: Isolation Forest and robust-z peers (anomaly), periodicity analysis (beaconing), char n-gram + logistic regression plus entropy rules (DNS), an embedding model (incident dedupe), a tool-calling model for `raven ask`, and a small LLM for explanations. Model names, sizes and licenses in the spec are UNVERIFIED (see `FACTS.md`). P1/P2 models are listed in `docs/spec/04-models.md`.

## Build order and definition of done
Stage 0 design and skeleton → Stage 1 core, 13 components in order, each with a brief, failing tests first, `make check` green, wired in, one commit → Gate 1 (end-to-end replay) → Stage 2 surround → Gate 2 → polish. A component is done when it matches the diagrams, has tests that can fail (negative cases included), passes `make check`, and is used by something.

## Known risks and unverified items
Python 3.13 is pinned because onnxruntime has no 3.15 wheel (D-001). Whether Internet Sharing isolates clients, the bridge name, pf anchor behavior beside Internet Sharing, capture throughput, Ollama/Gemma availability and Needle packaging are all UNKNOWN or ASSUMED. The core is designed to run from pcap replay and synthetic fixtures so none of these block it.
