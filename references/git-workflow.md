# Git Workflow

## Branch naming

From merged PR history: `feat/<topic>`, `fix/<topic>`, `docs/<topic>`, `chore/<topic>`, `release/<version>` (e.g. `release/1.0.0b10`). Dependabot opens `dependabot/...` branches. Base branch is `main`.

## Commit messages

Conventional Commits prefixes (`feat:`, `fix:`, `docs:`, `chore:`, `test:`, `refactor:`) with an optional scope such as `fix(token-vault):`, lowercase subject, no trailing period. Example: `docs: add 403 guidance for anonymous caller blocking in EXAMPLES.md`. No commit linter is configured. Older commits do not all follow this, so match the prefix style for new work.

## Pull requests

`.github/PULL_REQUEST_TEMPLATE.md` sections:

- **Changes:** what and why, endpoints added or changed, classes/methods added, changed, or deprecated, screenshots of UI changes, a usage summary for public API changes, and alternative designs considered
- **References:** supporting links (tickets, community posts)
- **Testing:** how to test, with checkboxes for unit coverage, integration coverage, and latest-platform testing
- **Checklist:** Auth0 contribution guidelines, Code of Conduct, all tests passing

The template asks for a method-level inventory, so write the PR body from the diff of the public surface (`__init__.py` `__all__`, `ApiClient` public methods, `ApiClientOptions`, `errors.py`), not from a summary of intent.

`CODEOWNERS` assigns every path to `@auth0/project-dx-sdks-engineer-codeowner`.

## CI workflows

From `.github/workflows/`. Which of these are required status checks is set in branch protection, not in the repo.

- **Build and Test** (`test.yml`): `pytest` + `ruff check .` across the Python version matrix in that workflow, on PR, merge group, and push to `main`
- **CodeQL** (`codeql.yml`): on PR, merge group, push to `main`, and a weekly schedule
- **SCA** (`sca_scan.yml`): Snyk against `requirements.txt`, with suppressions in `.snyk`. Runs on push to `main` only, so it does not gate a PR
- **Claude Code PR Review** (`claude-code-review.yml`): on issue comments, PR review comments, and submitted reviews

`ruff format` is not a check. Reformatting untouched files creates noise CI won't flag but reviewers will.

## Releases

`.version` is the version source. `.shiprc` keeps `pyproject.toml` in step with it. Releases are cut by `publish.yml` (manual dispatch, gated on the RL scan), not by an agent editing version files. Nothing in `.github/workflows/`, `.github/actions/`, or `.shiprc` writes `CHANGELOG.md`. Release PRs change it together with the version files.
