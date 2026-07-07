# WGPL — System Design

Human-readable architecture reference for contributors and security reviewers.
For operational procedures, see [docs/runbook.md](docs/runbook.md).

## Purpose

WGPL (WireGuard Peer Lite) is a **disconnected Python CLI** that manages WireGuard
*peers* with a SQLite database as the single source of truth (SSOT). It targets
**hub-and-spoke remote access VPNs** (IPv4 only). It does not create network
interfaces, manage routing, or run as a daemon.

## Layered architecture

```
cli.py (Typer / presentation)
    → core.py (facade)
        → db.py / wireguard.py / dbpath.py (infrastructure)
        → integrity.py / wireformat.py (invariants and export boundaries)
        → refs.py / ipam.py / audit.py / restore.py / consistency.py / validators.py
```

| Layer | Modules | Rules |
|-------|---------|-------|
| Presentation | `cli.py` | No direct `db` access; stdout/stderr contract; `--json` redaction |
| Business | `core.py`, `refs.py`, `ipam.py`, `audit.py`, `restore.py`, `consistency.py`, `validators.py` | No Typer; no stdout/stderr; orchestrates mutations and reads |
| Invariants | `integrity.py`, `wireformat.py` | Called from `core`, not from `cli` or `db` |
| Infrastructure | `db.py`, `dbpath.py`, `wireguard.py` | No business logic |

## Data flow

1. **Mutations** (`peer add`, `peer remove`, etc.) update SQLite inside `BEGIN EXCLUSIVE`
   transactions. Audit events append in the same transaction.
2. **No automatic WireGuard sync** on mutation — by design.
3. **Apply** (`wgpl apply`) runs `validate_state` then `wg syncconf` (fail-closed).
4. **Remote apply**: `wgpl interface export | ssh host wg syncconf iface /dev/stdin`.

## Peer lifecycle

A peer is **active** when it is not soft-deleted and not expired
(`integrity.is_peer_active()` is the SSOT).

- Expired peers release IP/name for reuse after `_reclaim_inactive_peer_slots` or `peer prune`.
- Partial unique indexes only know `deleted_at IS NULL`; expired rows block INSERT until reclaimed.
- `peer prune` hard-deletes inactive rows with a `pruned` audit event each.

## Security boundaries

| Boundary | Mechanism |
|----------|-----------|
| Database file | `dbpath`: `O_NOFOLLOW`, fd connect, `chmod 600`, reject symlinks |
| Key generation | X25519 + `os.urandom` in Python memory |
| Subprocess | Argument lists only; `WGPL_WG_BIN` ignored when UID 0 |
| Export | `wireformat` validates wire-safe fields before emission |
| Restore | Untrusted input: schema contract (tables, indexes, triggers, version), full wire validation, trigger reinstall |
| Secrets in JSON | `peer list --json` / `peer show --json` omit private keys and PSK |
| Multi-interface export | `peer config` / `peer qr` require `-i` when >1 interface |

## Schema (v1)

Tables: `interfaces`, `peers`, `audit_events`. Append-only audit enforced by SQLite
triggers recreated on every `init_db()` (never `IF NOT EXISTS` for security triggers).

## Scope limits

- IPv4 address pools and peer IPs only.
- No key rotation via `peer update` — remove and re-add peers instead.
- Kernel may remain stale until explicit `apply`.

## Validation (CI)

```bash
uv run ruff check src/ tests/
uv run mypy src/
uv run pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) for full policies.
