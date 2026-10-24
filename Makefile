.PHONY: bootstrap check test trace schemas
bootstrap:
	uv sync --python 3.13

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
