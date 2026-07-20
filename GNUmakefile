.PHONY: setup lint format test clean run

setup:
	python3 -m venv .venv
	.venv/bin/pip install --upgrade pip
	.venv/bin/pip install -e ".[dev]"

format:
	.venv/bin/black src/ tests/
	.venv/bin/isort src/ tests/

lint:
	.venv/bin/black --check src/ tests/
	.venv/bin/isort --check-only src/ tests/
	.venv/bin/flake8 src/ tests/
	.venv/bin/mypy src/

test:
	.venv/bin/pytest

run:
	.venv/bin/python -m idp.app

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	rm -rf .venv .mypy_cache .pytest_cache