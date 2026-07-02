# Contributing to WGPL

Thank you for your interest in contributing. All documentation and code comments must be written in **English**.

## Development setup

```bash
git clone https://github.com/aleaz/wgpl.git
cd wgpl
uv sync --dev
```

## Validation (required before opening a PR)

```bash
uv run ruff check src/ tests/
uv run mypy src/
uv run pytest
```

## Architecture invariants

Read [`.cursor/rules/wgpl-architecture.mdc`](.cursor/rules/wgpl-architecture.mdc) before making changes. Key rules:

- SQLite is the SSOT; no auto-sync on `add_peer` / `remove_peer`
- Multi-step writes use `db.transaction()` (`BEGIN EXCLUSIVE`)
- Never expose `private_key` or `preshared_key` in JSON list output
- `subprocess` without `shell=True`; SQL always parameterized

## Pull requests

1. Create a branch: `feature/<slug>` or `fix/<slug>`
2. Keep changes focused and minimal
3. Add or update tests for behavior changes
4. Ensure CI passes (ruff, mypy, pytest)
5. Fill out the PR template checklist

## Commit messages

Use [Conventional Commits](https://www.conventionalcommits.org/) (`feat:`, `fix:`, `chore:`, etc.).
The message must stand on its own in `git log` for anyone who was not in the authoring session.

**Do not** reference internal process artifacts in the subject or body, for example:

- Audit or review IDs (`V1`, `F3`, `gap V5`)
- Plan or todo slugs from `.cursor/plans/`, agent sessions, or checklists
- Intermediate analysis doc names that are not versioned in the repo

Those identifiers do not exist in the codebase and become meaningless once the session ends.

**Bad:** `fix: close invariant verification gaps (V1-V3, V5)`

**Good:** `fix: route interface add/remove through core and improve peer errors`

Describe *what* changed and *why* in terms of the product and code, not the internal workflow that produced the change.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting. Do not include real WireGuard keys or database files in issues or PRs.

## Optional: AI assistant setup

- **Cursor** — project rules live in `.cursor/rules/`
- **Antigravity** — run `npx @vudovn/ag-kit@2026.6.29 init` locally (not versioned in this repo)

## GitHub settings (after making the repo public)

Configure in the repository **Settings** on GitHub:

1. **About** — add description and topics: `wireguard`, `vpn`, `python`, `cli`, `sqlite`
2. **Security** — enable Dependabot alerts and secret scanning
3. **Branches** — protect `main` (require CI status checks before merge)
4. **Releases** — create tag `v0.1.0` on the public-ready commit

Pre-push checklist:

```bash
uv run ruff check src/ tests/
uv run mypy src/
uv run pytest
git status   # ensure no *.db / *.sqlite3 files are staged
```
