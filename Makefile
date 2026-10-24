.PHONY: bootstrap install check test trace schemas build demo audit
bootstrap:
	uv sync --python 3.13

install:
	uv tool install --force --python 3.13 .

build:
	uv build

demo:
	uv run python tools/make_demo_pcap.py demo.pcap
	uv run sentinel replay demo.pcap --brief

audit:
	# B608: the SQL strings are built from fixed fragments (each is justified next to its noqa)
	# B310: tools/ only fetches from 127.0.0.1
	uvx bandit -q -r sentinel tools -ll -s B608,B310
	uv export --no-dev --no-hashes -q | grep '==' > .audit-requirements.txt
	uvx pip-audit -r .audit-requirements.txt --no-deps --disable-pip; rc=$$?; rm -f .audit-requirements.txt; exit $$rc

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
