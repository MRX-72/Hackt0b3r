.PHONY: bootstrap check test trace
bootstrap:
	uv sync --python 3.13

check:
	uv run ruff format --check .
	uv run ruff check .
	uv run mypy
	uv run pytest
	uv run vulture
	uv run deptry .

test:
	uv run pytest

trace:
	uv run python tools/trace.py
