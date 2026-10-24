# STATE
Last updated: 2026-10-24

## Stage
Stage 1, reordered by the user (D-014): detection engine, notifiers, LLM summaries and a CLI first. Gate 1 not formally run.

## Scope
CLI only; GUI last as a client of the service facade (D-013, D-015).

## Done (see git log)
- Stage 0, storage, parser, config + secrets, replay/live capture source (tcpdump pipe), window features, rule detectors (port scan, brute force, beaconing, DNS tunnel) with engine, correlation, sanitizer, templates, faithfulness checks, Ollama + OpenAI-compatible (llama.cpp) clients, Slack/Discord/Telegram notifiers with retry, rate limit, breaker and dedupe, pipeline, service facade, CLI (`replay`, `watch`, `incidents`, `notify test`, `llm test`, `doctor`, `--show-traffic/--no-traffic`, `--json`).

## Refinement pass (after first CLI)
Alerts carry a validated `target_ip` (schema migration 002 tested on a v1 database); templates quote evidence, window and service names; traffic filters (`--host/--port/--proto`); `incident <id>` timeline; `config show`; `--version`; help examples; warning when `--notify` is a no-op; closed output pipes (`| head`) handled; `tools/make_demo_pcap.py`; `USER_GUIDE.md` (every command example was run).

## CLI day-to-day pass
`init`, `status`, `ack/dismiss/resolve` (id prefixes, audit log), `incidents --since/--min-score/--all`, `replay` with several files, `--brief`, short flags, `watch --for`, `doctor --fix` (and doctor works with broken secrets perms), colour on TTY.

## Not built yet
Rogue DHCP/ARP/canary detectors, Isolation Forest + peers, DNS n-gram model, event bus with drop accounting, enforcement validator/pf renderer, sentineld daemon, model registry, HTTP API server, device inventory, modes, packets view, rule engine, embeddings, `ask`, eval/purple-team, GUI.

## Process deviations (honest list)
- Component briefs exist only for storage, parser and features; later components were specified in DECISIONS and tests instead.
- Mutation checks were done for storage, parser and detectors, not for notifiers/faithfulness/CLI.
- Diagrams 03/04/12 not updated for the service facade and net package (05 is).

## Unverified on real hardware / services
Live capture on bridge100 (H-03, H-09), real Slack/Discord/Telegram delivery (H-10), real Ollama/llama-server (H-06, H-11), snaplen choice (D-011).

## Last make check
Green: 233 tests, 18 in the security group, coverage 97.7%, mypy strict, ruff, vulture, deptry, architecture test.
