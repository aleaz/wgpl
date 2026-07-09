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
| **Node** | `nodes` table | A **device identity**: a globally unique `name` and optional `desc`. It owns *who* a device is, independent of any tunnel. A node may be attached to zero or more interfaces |
| **Peer** | `peers` table | A node's **attachment** to one interface: keys, tunnel IP, lifecycle, routing **intent**. Carries `node_id` (FK to `nodes`); it has no name of its own — the display name comes from the node |
| **Route / network** | `routed_networks` (peer or interface) | IPv4 CIDRs **behind** a node or the hub — intent to reach those prefixes via the tunnel |
| **Routing policy** | `allowed_ips_policy`, `custom_allowed_ips` | What a peer's client export should include (split/full tunnel, remote LANs, custom) |

**Identity vs attachment.** The node is *pure identity* — it holds no routing or
tunnel state. All tunnel-specific state (keys, IP, `role`, `routed_networks`,
policy, lifecycle) lives on the peer. This lets the same device (one node) attach
to several hubs, each attachment carrying its own routing intent.

### Domain vs WireGuard

```
Domain (SQLite intent)             WireGuard (derived export)
─────────────────────             ──────────────────────────
interfaces + nodes + peers  →     hub syncconf / client .conf
nodes.name                  →     display / identity only (never wire)
role, routed_networks       →     [Peer] AllowedIPs
allowed_ips_policy          →     client AllowedIPs scope
(keys, IP, DNS, MTU)        →     Interface / Peer fields
```

**Never stored:** derived `AllowedIPs`, computed routes, or generated configs.
Only **intent** is persisted; `routing.py` derives reachability at export time.

### Peer role (attachment intent)

Each peer attachment declares how the node participates on that interface:

- **`endpoint`** — tunnel identity only (notebook, phone, desktop); no
  `routed_networks`.
- **`subnet_router`** — gateway announcing one or more LAN CIDRs behind the
  tunnel (`routed_networks` is a comma-separated list).

The same physical device connected to two hubs is **one node** with **two peer
rows** (one per interface). Each attachment carries its own `role` and
`routed_networks`; the shared identity (name, desc) lives once on the node.

### Node lifecycle

- A node is created explicitly (`wgpl node add`) or implicitly via the
  find-or-create path of `wgpl peer add <iface> <name>`.
- Node identity **persists** when its peers are soft-deleted or expire — the
  device is still "known" even with zero active attachments.
- `wgpl node remove` is guarded: it refuses while attachments remain unless
  `--force` (which cascades the attachments with audit). `wgpl node prune`
  removes only **orphan** nodes (no attachments, including soft-deleted rows).

### Evolution notes

The current schema does not block future extensions:

| Extension | Current posture |
|-----------|-----------------|
| Multiple hubs | Supported — one `interfaces` row per hub |
| Multiple WireGuard interfaces on one host | Supported — composite identity (`name + endpoint + port`) |
| One device across hubs | Supported — a single `nodes` row with a peer per interface |
| IPv6 | Blocked by IPv4-only invariant; `routing.py` uses `IPv4Network` throughout |
| Alternate exporters (MikroTik, FRR) | Viable — `routing.py` is pure; new serializers beside `wireformat` |
| Advanced policies / BGP | Would consume the same derived prefix lists from `routing.py` |

## Architecture verification

Post domain-model audit (implementation checked against documentation).

### Architectural principles

| Principle | Status |
|-----------|--------|
| Intent persisted; derived values never stored | Verified — no AllowedIPs columns in schema |
| WireGuard config always generated at export | Verified — emit gates in `core.py` |
| Domain model independent of WireGuard | Verified — see [Domain model](#domain-model) |
| Export is one-way (intent → wire format) | Verified — no import from `.conf` |
| `routing.py` single source of routing derivation | Verified — see below |

### Node / peer separation

Identity and attachment are distinct tables, but routing derivation stays
peer-scoped:

- The `nodes` table owns identity (`name`, `desc`); `peers.node_id` references it.
- All routing APIs still accept `peer` / `iface` rows (`routing.resolve_*`); the
  node contributes only the display name and the own-LAN exclusion key
  (`routing` excludes by `node_id` when present, falling back to `peer.id`).
- Peer read helpers JOIN `nodes` and alias `n.name AS name`, so downstream code
  that reads `peer["name"]` is unchanged.

### Routing derivation audit

Only `routing.py` computes prefix lists for AllowedIPs. Other modules **call**
it:

| Module | Uses `routing` for |
|--------|-------------------|
| `core.py` | Emit gates, JSON metadata, `explain_peer_routing` |
| `consistency.py` | LAN↔LAN completeness checks in `validate` |
| `integrity.py` | `parse_cidr_list`, enums — validation only, not derivation |

`wireformat.py` validates and joins CIDR strings; it never chooses routes.
`grep` for `/32` in `src/wgpl` finds only `routing.py`.

### Boundary violations

None found. `cli.py` does not import `db`. No business routing logic in
`wireformat` or `db`.

### Specification artifacts

- Routing invariants and invalid topologies: [docs/ROUTING.md](docs/ROUTING.md)
- Executable matrix (topology → expected AllowedIPs): [docs/routing_matrix.md](docs/routing_matrix.md)

## Layered architecture

```
cli.py (Typer / presentation)
    → core.py (facade)
        → db.py / wireguard.py / dbpath.py (infrastructure)
        → routing.py (derive AllowedIPs — pure functions)
        → integrity.py / wireformat.py (invariants and export boundaries)
        → refs.py / ipam.py / audit.py / restore.py / consistency.py / validators.py
```

| Layer | Modules | Rules |
|-------|---------|-------|
| Presentation | `cli.py` | No direct `db` access; stdout/stderr contract; `--json` redaction |
| Business | `core.py`, `refs.py`, `ipam.py`, `audit.py`, `restore.py`, `consistency.py`, `validators.py` | No Typer; no stdout/stderr; orchestrates mutations and reads |
| Routing derivation | `routing.py` | Pure functions; single source of AllowedIPs; no I/O |
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

- Expired peers release their IP and node slot for reuse after `_reclaim_inactive_peer_slots` or `peer prune`.
- Partial unique indexes only know `deleted_at IS NULL`; expired rows block INSERT until reclaimed. `idx_peers_active_node` keeps a node attached to an interface at most once while active.
- `peer prune` hard-deletes inactive peer rows with a `pruned` audit event each. Node identities survive prune; use `node prune` to remove orphan nodes.

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

Tables: `interfaces`, `nodes`, `peers`, `audit_events`. Identity columns:
`nodes.name` (globally unique), `nodes.desc`; `peers.node_id` (FK → `nodes`,
peers have no `name` column). Routing intent columns:
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
uv run mypy src/ tests/
uv run pytest
```

See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md) for full policies.
