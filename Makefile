.PHONY: install format lint typecheck test test-cov ci clean help

PY ?= python
PIP ?= pip

help:
	@echo "GuardMCP G0 — Repository Foundation"
	@echo "  make install    — install project + dev deps"
	@echo "  make format     — ruff format"
	@echo "  make lint       — ruff check"
	@echo "  make typecheck  — mypy"
	@echo "  make test       — pytest"
	@echo "  make test-cov   — pytest with coverage"
	@echo "  make ci         — format, lint, typecheck, test (CI gate)"
	@echo "  make clean      — remove caches"

install:
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"
	$(PY) -m pip install -e ./packages/guardmcp-core

format:
	ruff format .

lint:
	ruff check .

typecheck:
	mypy packages

test:
	pytest

test-cov:
	pytest --cov --cov-report=term-missing

ci: format lint typecheck test
	@echo "CI gate passed"

clean:
	rm -rf .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml htmlcov
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
