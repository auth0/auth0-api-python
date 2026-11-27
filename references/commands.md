# Commands

The install, CI test, and lint commands match `.github/workflows/test.yml` (Poetry and Python versions are set there). `poetry install`, `poetry run pytest`, and `poetry build` also appear in `CONTRIBUTING.md`. The rest are local conveniences that no CI step runs.

```bash
# Install dependencies (CI runs this only on a venv cache miss)
poetry install --no-interaction --no-root
# Install the package (CI runs this every time)
poetry install --no-interaction

# Run all unit tests (CI command)
poetry run pytest -v --cov=src --cov-report=term-missing --cov-report=xml

# Run all unit tests (short form, pyproject addopts already adds --cov=src)
poetry run pytest

# Fast loop without coverage
poetry run pytest --no-cov -q

# Lint (CI-enforced)
poetry run ruff check .

# Auto-fix lint issues (review the diff and keep it scoped to your change)
poetry run ruff check . --fix

# Show formatting state only (not a CI gate, so never apply it repo-wide)
poetry run ruff format --check .

# Build sdist and wheel into dist/
poetry build

# Clean generated artifacts
rm -rf dist/ .coverage coverage.xml .pytest_cache .ruff_cache
find . -path ./.venv\* -prune -o -name __pycache__ -type d -prune -exec rm -rf {} +
```

## Not available here

- **No typecheck command.** mypy/pyright are not in `pyproject.toml` and no CI step runs them.
- **No integration/e2e tier.** The suite runs on `pytest-httpx` mocks, and nothing in `src/`, `tests/`, or CI reads Auth0 tenant credentials.

`publish.yml` (manual `workflow_dispatch`) builds and runs the RL scanner, creates the GitHub release, then builds and publishes to PyPI.
