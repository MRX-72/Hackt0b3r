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
