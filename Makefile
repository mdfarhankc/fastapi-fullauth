.PHONY: install test lint format check fix clean build docs

# Install dependencies
install:
	uv sync --dev --extra sqlalchemy --extra sqlmodel --extra oauth --extra redis

# Run tests
test:
	uv run pytest tests/ -x --tb=short

# Run tests with verbose output
test-v:
	uv run pytest tests/ -v

# Run a specific test file
# Usage: make test-file FILE=test_auth
test-file:
	uv run pytest tests/$(FILE).py -x --tb=short -v

# Lint check (no changes)
lint:
	uv run ruff check .

# Format check (no changes)
format-check:
	uv run ruff format --check .

# Fix lint issues
fix:
	uv run ruff check --fix .

# Format code
format:
	uv run ruff format .

# Run all checks (format + lint + tests) — run before committing
check: format-check lint test

# Fix all issues then verify
fix-all: format fix test

# Build package
build:
	uv build

# Serve docs locally
docs:
	uv run mkdocs serve

# Build docs
docs-build:
	uv run mkdocs build

# Run example apps
run-sqlmodel:
	uv run uvicorn examples.sqlmodel_app.main:app --reload

run-sqlalchemy:
	uv run uvicorn examples.sqlalchemy_app.main:app --reload

# Clean build artifacts
clean:
	rm -rf dist/ build/ *.egg-info .pytest_cache .ruff_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
