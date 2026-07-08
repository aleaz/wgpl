# WGPL — System Design

Human-readable architecture reference for contributors and security reviewers.
For operational procedures, see [docs/runbook.md](docs/runbook.md).

## Purpose

WGPL (WireGuard Peer Lite) is a **disconnected Python CLI** that manages WireGuard
*peers* with a SQLite database as the single source of truth (SSOT). It targets
**hub-and-spoke remote access VPNs** (IPv4 only). It does not create network
interfaces, manage routing, or run as a daemon.

## Domain model

WGPL models a **declarative hub-and-spoke VPN topology**, not WireGuard text
files. WireGuard (`[Interface]`, `[Peer]`, `AllowedIPs`, `Endpoint`, etc.) is an
**export format** produced at apply/export time — not the internal domain model.

Routing derivation and operational patterns are documented in
[docs/ROUTING.md](docs/ROUTING.md).

### What WGPL models

| Concept | Stored as | Meaning |
|---------|-----------|---------|
| **VPN (topology)** | One `interfaces` row | A hub-and-spoke domain: address pool, hub endpoint, optional hub-local routes, and all remote attachments |
| **Interface** | `interfaces` table | The concentrator (hub) for one VPN domain — not the OS `wg0` device itself (BYOI) |
| **Peer** | `peers` table | A remote **attachment** to the hub: keys, tunnel IP, lifecycle, routing **intent**. A peer is not always a single host — it may represent a laptop, phone, or a site gateway advertising LANs |
| **Node** (conceptual) | Collapsed into `peers` today | The physical or logical remote entity (router, firewall, branch). Not a separate table yet |
| **Route / network** | `routed_networks` (peer or interface) | IPv4 CIDRs **behind** a node or the hub — intent to reach those prefixes via the tunnel |
| **Routing policy** | `allowed_ips_policy`, `custom_allowed_ips` | What a peer's client export should include (split/full tunnel, remote LANs, custom) |

### Domain vs WireGuard

```
Domain (SQLite intent)          WireGuard (derived export)
─────────────────────          ──────────────────────────
interfaces + peers      →      hub syncconf / client .conf
role, routed_networks   →      [Peer] AllowedIPs
allowed_ips_policy      →      client AllowedIPs scope
(keys, IP, DNS, MTU)    →      Interface / Peer fields
```

**Never stored:** derived `AllowedIPs`, computed routes, or generated configs.
Only **intent** is persisted; `routing.py` derives reachability at export time.

### Peer ≠ host

A peer represents a remote node capable of announcing zero or more networks:

- **`endpoint`** — tunnel identity only (notebook, phone, desktop); no
  `routed_networks`.
- **`subnet_router`** — gateway announcing one or more LAN CIDRs behind the
  tunnel (`routed_networks` is a comma-separated list).

The same physical router connected to two hubs would be **two peer rows** (one
per interface) with duplicated `routed_networks` today. That is an accepted
denormalization for the current single-hub-per-interface product scope.

### Evolution notes (not implemented)

The current schema does not block future extensions:

| Extension | Current posture |
|-----------|-----------------|
| Multiple hubs | Supported — one `interfaces` row per hub |
| Multiple WireGuard interfaces on one host | Supported — composite identity (`name + endpoint + port`) |
| Explicit `Node` entity | Would split attachment from advertised networks; peers would reference a node |
| IPv6 | Blocked by IPv4-only invariant; `routing.py` uses `IPv4Network` throughout |
| Alternate exporters (MikroTik, FRR) | Viable — `routing.py` is pure; new serializers beside `wireformat` |
| Advanced policies / BGP | Would consume the same derived prefix lists from `routing.py` |

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
3. **Apply** (`wgpl apply`) and all config export paths (`interface export`, `peer config`) enter a single **emit gate** in `core.py`: `assert_database_valid` → `integrity.assert_exportable_*` → `wireformat` (formatting only).
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
| Export | Emit gate in `core.py`; `integrity.assert_exportable_*` SSOT; `wireformat` formats only |
| Schema on open | Every live DB connection validates exact schema + audit trigger bodies (fail-closed) |
| Peer access | `PeerAccess` in `refs.py` (READ_PUBLIC, READ_SENSITIVE, EXPORT_SECRET, MUTATE) |
| Restore | Untrusted input: schema contract (tables, indexes, triggers, version), full wire validation, trigger reinstall |
| Secrets in JSON | `peer list --json` / `peer show --json` omit private keys and PSK |
| Multi-interface secrets | `peer show --show-secrets`, `peer config`, `peer qr`, and scoped audit history require `-i` when >1 interface |

## Schema

Tables: `interfaces`, `peers`, `audit_events`. Routing intent columns:
`interfaces.routed_networks`; `peers.role`, `routed_networks`, `allowed_ips_policy`,
`custom_allowed_ips`. See [docs/ROUTING.md](docs/ROUTING.md). Append-only audit enforced by SQLite
triggers recreated on every `init_db()` (never `IF NOT EXISTS` for security triggers).
Weakened or extra triggers are **detected on every live DB open**; `wgpl db doctor` diagnoses issues and `wgpl db doctor --repair` reinstalls triggers and normalizes `deleted_at`.

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
