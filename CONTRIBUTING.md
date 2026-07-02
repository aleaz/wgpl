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
