.PHONY: bootstrap install check test trace schemas build demo
bootstrap:
	uv sync --python 3.13

install:
	uv tool install --force --python 3.13 .

build:
	uv build

demo:
	uv run python tools/make_demo_pcap.py demo.pcap
	uv run sentinel replay demo.pcap --brief

check:
	uv run ruff format --check .
	uv run ruff check .
	uv run mypy
	uv run pytest
	uv run pytest -m security --no-cov
	uv run vulture
	uv run deptry .

test:
	uv run pytest

trace:
	uv run python tools/trace.py

schemas:
	uv run python -m sentinel.contracts.schemas
