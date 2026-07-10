# Contributing to WGPL

Thank you for your interest in contributing. All documentation and code comments must be written in **English**.

## Development setup

```bash
git clone https://github.com/aleaz/wgpl.git
cd wgpl
uv sync --dev
uv tool run pre-commit install
```

## Validation (required before opening a PR)

```bash
uv run ruff check src/ tests/
uv run mypy src/ tests/
uv run pytest
```

> **Safe by Design Testing:** You can run `pytest` fearlessly. The test suite runs entirely on `:memory:` SQLite databases and mocks the OS-level `wg` commands. It will **not** modify your host's `iptables` or `/etc/wireguard` configurations, and it does not require `root` privileges.

## Architecture invariants

Read [DESIGN.md](DESIGN.md) for a human-readable architecture overview and
[`.cursor/rules/wgpl-architecture.mdc`](.cursor/rules/wgpl-architecture.mdc) before making changes.
Operational procedures live in [docs/runbook.md](docs/runbook.md).

```mermaid
graph TD
    CLI[wgpl/cli.py] --> CORE[wgpl/core.py]
    CORE --> DB[wgpl/db.py (SQLite)]
    CORE --> WG[wgpl/wireguard.py (OS Sync)]

    classDef boundary fill:transparent,stroke-dasharray: 5 5;
    class DB,WG boundary;
```

Key rules:

- SQLite is the SSOT; no auto-sync on `add_peer` / `remove_peer`
- Strict layers: `cli.py` → `core.py` → `db.py` / `wireguard.py` (CLI must not import `db`)
- Peer lifecycle and IP allocation logic live in `core.py` and `ipam.py` (`integrity.is_peer_active` is SSOT)
- Expired peers release IPs for allocation; use `peer prune` to remove rows physically
- IPv4-only pools and peer addresses
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
- Technical-debt wave labels (`v1.0`, `v1.1`, `v1.2`, `ola v1.2`) — these are planning names, not released semver
- Debt item IDs (`D3`, `D16`, `D1–D34`) from backlog plans
- Plan or todo slugs from `.cursor/plans/`, agent sessions, or checklists
- Intermediate analysis doc names that are not versioned in the repo

Those identifiers do not exist in the codebase and become meaningless once the session ends.
They also must not be treated as git tags or package versions unless a release step explicitly creates them.

**Bad:** `fix: v1.2 integrity hardening (D3, D16, D17)`

**Bad:** `fix: close invariant verification gaps (V1-V3, V5)`

**Good:** `fix: consistent dump snapshots and accurate update audit events`

**Good:** `fix: route interface add/remove through core and improve peer errors`

Describe *what* changed and *why* in terms of the product and code, not the internal workflow that produced the change.

## Security

See [SECURITY.md](SECURITY.md) for vulnerability reporting. Do not include real WireGuard keys or database files in issues or PRs.

## Optional: AI assistant setup

**Canonical AI context for this repo (versioned in git):**

| Tool | Location | Purpose |
| --- | --- | --- |
| **Cursor** | [`.cursor/rules/wgpl-architecture.mdc`](.cursor/rules/wgpl-architecture.mdc) | Architecture and security invariants (always apply) |
| **Cursor** | [`.cursor/rules/wgpl-git-agent.mdc`](.cursor/rules/wgpl-git-agent.mdc) | Git for agents: no co-author trailers, no push unless asked |
| **Cursor** | [`.cursor/skills/wgpl-dev/SKILL.md`](.cursor/skills/wgpl-dev/SKILL.md) | CLI workflows and pre-PR checklist |

Use `.cursor/` as the single source of truth for Cursor and for human onboarding.
Do not rely on gitignored local paths (for example `.agents/`) for architecture rules.

**Optional — Antigravity / AG Kit (local only, not in git):**

- Run `npx @vudovn/ag-kit@2026.6.29 init` to create `.agents/` on your machine.
- Generic AG Kit skills and workflows are not curated for WGPL; prefer `.cursor/` above.
- If you use Antigravity memory, keep [`.agents/memory/wgpl-invariants.md`](.agents/memory/wgpl-invariants.md) aligned with `wgpl-architecture.mdc`.

### Maintaining AI context (anti-drift)

When architecture, security, or CI validation commands change, update sources in this order:

1. Edit [`.cursor/rules/wgpl-architecture.mdc`](.cursor/rules/wgpl-architecture.mdc) — canonical source for agents and humans.
2. Keep [`.cursor/rules/wgpl-git-agent.mdc`](.cursor/rules/wgpl-git-agent.mdc) aligned if git agent policy changes.
3. Update [`.cursor/skills/wgpl-dev/SKILL.md`](.cursor/skills/wgpl-dev/SKILL.md) only if it mentions the changed behavior explicitly.
4. Update this file (Validation / Architecture invariants sections) and the PR template if the human checklist changes.
5. If you use Antigravity locally, sync [`.agents/memory/wgpl-invariants.md`](.agents/memory/wgpl-invariants.md) from step 1.

Do not add duplicate checklists to the skill — link to this file instead.
Do not add generic always-on Cursor rules (benchmark prompts, web-app templates); they contradict WGPL invariants.
CI ([`.github/workflows/ci.yml`](.github/workflows/ci.yml)) is the objective final check; keep it aligned with the Validation section above.

If you do **not** use Antigravity, you can remove local AG Kit with `rm -rf .agents/ .temp_ag_kit` to reduce editor noise.

## Repository requirements (maintainers)

Before treating the project as production-published or org-ready:

1. **Branch protection** on `main` — require CI status checks before merge
2. **GitHub Environment `pypi`** — required reviewers (and optional wait timer) for the release workflow
3. **Security** — Dependabot alerts and secret scanning enabled
4. **Releases** — annotated tag `vX.Y.Z` must match `version` in `pyproject.toml` (enforced in CI)

See [MAINTAINERS.md](MAINTAINERS.md).

Pre-push checklist:

```bash
uv run ruff check src/ tests/
uv run mypy src/ tests/
uv run pytest
git status   # ensure no *.db / *.sqlite3 files are staged
```
