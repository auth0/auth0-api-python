# Commands

These match `.github/workflows/test.yml` (Poetry and Python versions are set there) and `CONTRIBUTING.md`.

```bash
# Install dependencies and the package (CI runs both steps)
poetry install --no-interaction --no-root
poetry install --no-interaction

# Run all unit tests (CI command)
poetry run pytest -v --cov=src --cov-report=term-missing --cov-report=xml

# Run all unit tests (short form; pyproject addopts already adds --cov=src)
poetry run pytest

# Fast loop without coverage
poetry run pytest --no-cov -q

# Lint (CI-enforced)
poetry run ruff check .

# Auto-fix lint issues (review the diff, keep it scoped to your change)
poetry run ruff check . --fix

# Show formatting state only (not a CI gate, never apply repo-wide)
poetry run ruff format --check .

# Build sdist and wheel into dist/
poetry build

# Clean generated artifacts
rm -rf dist/ .coverage coverage.xml .pytest_cache .ruff_cache
find . -path ./.venv\* -prune -o -name __pycache__ -type d -prune -exec rm -rf {} +
```

## Not available here

- **No typecheck command.** mypy/pyright are not in `pyproject.toml` and no CI step runs them.
- **No integration/e2e tier.** The detected suite runs on `pytest-httpx` mocks, and nothing in `src/`, `tests/`, or CI reads Auth0 tenant credentials.

`publish.yml` (manual `workflow_dispatch`) builds, runs the RL scanner, and publishes to PyPI. Agents do not run releases.
