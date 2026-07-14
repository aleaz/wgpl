# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [1.0.0] - 2026-07-14

### Notes

- **Scope (is / is not):** WGPL is a disconnected CLI for declarative hub-and-spoke IPv4 VPN intent (SQLite SSOT, BYOI). It is **not** a daemon/control plane, full-mesh overlay, direct site-to-site without a hub, IPv6 manager, WireGuard `.conf` importer, or self-service portal product (the FastAPI example is illustrative only). See README.
- **Known limitations:** Bring-your-own interface (BYOI) — WGPL does not create OS interfaces or configure hub forwarding/firewall/NAT; mutations update SQLite only (no auto-apply); remote hub sync is an operator pipe (`wgpl interface export | ssh … wg syncconf`); **IPv4-only** address pools, peer IPs, DNS, and AllowedIPs.
- **Schema evolution:** no in-place migrator; breaking schema changes require a new major version plus `db dump`/`restore` (see DESIGN.md).

### Added

- Disconnected WireGuard hub-and-spoke intent CLI (`wgpl`) with SQLite SSOT, WAL mode, and exclusive transactions
- In-memory Curve25519 key generation via `cryptography`
- Commands: `interface`, `node`, `peer`, `status`, `apply`, `validate`, `db`; `--json` M2M mode
- First-class **Node** entity: `nodes` table (globally unique `name`, optional `desc`) and `wgpl node` command group (`add`, `list`, `show`, `update`, `remove`, `prune`, `history`)
- Hybrid `wgpl peer add`: positional `<name>` find-or-creates the node and attaches it; `--node <ref>` strictly attaches an existing node; exactly one is required. Peer JSON gains `node`, `node_id`, and `node_created`
- Intent-based hub-and-spoke routing: `routing.py` derives hub and client `AllowedIPs` from stored intent (`role`, `routed_networks`, `allowed_ips_policy`); derived values are never persisted
- Routing intent on interfaces and peers; CLI flags `--role`, `--routed-networks`, `--allowed-ips-policy`, `--custom-allowed-ips` (and `--clear-*`) on `peer add` / `peer update`; `--routed-networks` on `interface add` / `interface update`
- `wgpl peer explain` — derived hub/client AllowedIPs and LAN↔LAN checklist for subnet routers
- `wgpl validate` routing topology and hub↔peer routed-network checks (errors exit 1, warnings exit 0)
- `wgpl status` overview; `peer list --format compact`; honor `COLUMNS` for stdout table width
- Peer `list` / `show` JSON includes additive `interface` (hub name) alongside `interface_id`
- JSON export metadata: `hub_allowed_ips` and `client_allowed_ips` on `peer list` / `peer show`; `client_allowed_ips` and `allowed_ips_source` on `peer config --json`
- Client config and QR export (`peer config`, `peer qr`); `peer qr --output` / `-o` writes PNG (ASCII default)
- Declarative sync via `wg syncconf` (`apply` / `interface export`)
- Soft-delete by default on `peer remove`; `--hard` for physical deletion; `peer prune -i INTERFACE`
- `peer add --expires` — peer lifetime (`7d`, `24h`, etc.); `peer list --expired`, `--all`
- Optional `--ip` on `peer add` and `--dns` / `desc` / `mtu` / `keepalive` on interface and peer
- `interface update` without removing peers; `interface remove --force` when peers remain (`InterfaceHasPeersError` without force)
- Append-only `audit_events`; `peer history` / `interface history` with `--limit` / `--offset`
- `wgpl db dump` / `wgpl db restore --yes` — binary SQLite backup with atomic restore
- `wgpl db doctor [--repair]` for schema/trigger diagnostics
- `InterfaceConflictError` — global uniqueness of interface `port` and `address_pool`
- `PeerInterfaceMismatchError` for wrong-interface peer operations
- Collision subclasses `NodeAlreadyAttachedError` and `RoutedNetworkOverlapError`
- `fields.py` SSOT for entity `NAME_RE` and peer-over-interface DNS/MTU/keepalive cascade
- Exact SQLite schema contract on restore; `dbpath` opener (`O_NOFOLLOW`, fd-based connect, `chmod 600`)
- `integrity` activation/export gates; `wireformat` emit formatting with shared AllowedIPs/DNS/MTU/keepalive cascade
- `wg` binary resolution via fixed allowlist (PATH hijack mitigation for root)
- `dbpath.open_exclusive_output()` for hardened CLI secret output paths
- Documentation: `docs/cli.md`, `docs/runbook.md`, `docs/routing.md`, `docs/routing_matrix.md`, `DESIGN.md`, `SECURITY.md`, `CONTRIBUTING.md`
- README deployment architectures: BYOI Local, Linux server, MikroTik RouterOS v7
- CI: ruff, mypy, pytest, bandit, pip-audit, gitleaks; Python 3.12+3.13; `uv sync --frozen`
- Docker workflow with Trivy before registry push (images on version tags only)
- FastAPI self-service example (illustrative): fail-closed `WGPL_PORTAL_API_KEY` with `secrets.compare_digest`
- Tests: routing, topology validate, node QA, restore adversarial, trust boundaries, output path hardening

### Changed

- **Breaking:** peer mutations require `-i` / `--interface` (no positional interface); examples: `peer add NAME -i IFACE`, `peer update PEER_ID -i IFACE`, `peer prune -i IFACE`
- **Breaking:** `--json` resource/list success always uses `{"status":"success","data":…}`; typed actions/reports (`apply`, `validate`, `db doctor`, restore/remove acks) expose top-level `status` without double-wrapping under `data`
- Peers reference a global node via `peers.node_id` (no `peers.name` column); rename with `node update` — `peer update` has no `--name`
- A node attaches to a given interface at most once while active (`idx_peers_active_node`); reclaim keyed by IP and `node_id`
- Read commands open the database via `force_readonly` (list/show/status/validate/doctor diagnose/dump); missing DB does not create an empty file
- `peer config` / `peer qr` derive client `AllowedIPs` from `allowed_ips_policy` by default; `--allowed-ips` overrides a single export; require `-i` when multiple interfaces exist
- Hub `interface export` / `apply` emit subnet-router `AllowedIPs` as tunnel `/32` plus advertised LAN prefixes
- Audit trail includes `node` entity type; peer audit metadata records `node_id`
- Minimum MTU for mutations and export is **1280**; wire-safe MTU (1280–65535) and keepalive (0–65535)
- `interface update` pool shrink rejects any non-soft-deleted peer outside the new CIDR (including expired until pruned)
- `peer update --clear-expires` and future `--expires` use the activation integrity gate
- `wgpl apply` fails closed when database validation fails (before `wg syncconf`)
- `wgpl db restore` validates schema contract and full wire-format rows, recreates audit triggers; fails closed on error-severity only (warnings do not block)
- `wgpl db dump` sets `chmod 600` on the output file; all SQLite opens route through `dbpath`
- CLI skips database open for `--help`; permission-denied guidance prefers `--db` / ownership over bare `sudo`
- Mutations print apply hints; soft-delete messaging clarifies prune
- Unified DNS/MTU/keepalive cascade and name regex via `fields.py`; activation IP collisions raise `IpAlreadyInUseError`
- README install prefers `uv`/`pip`; standalone Linux binary marked experimental with checksum guidance
- Release workflow: tag must match `pyproject.toml` version; PyInstaller pinned; binary before PyPI; `SHA256SUMS` on GitHub Release
- Reject IPv6 interface endpoints; classifier/README/CLI tagline aligned with hub-and-spoke Stable identity
- CLI/JSON compatibility promise: no breaking CLI commands/flags or public `--json` field names without a major version bump

### Fixed

- Idempotent `peer add` (existing active attachment) returns the public create shape — no `private_key` / `preshared_key` — and human CLI no longer crashes on missing `name`
- `wgpl apply --json` reports a missing `wg` binary as `{"status":"error","message":…}` via `_exit_error`; remote export tip is a stderr hint
- Peer-add usage hint matches required `-i` syntax
- `peer show --json` redacts private keys and preshared keys (consistent with `peer list --json`)
- Malformed wire-format fields rejected on export, restore, and apply
- Restore cannot persist noop audit immutability triggers from a tampered backup
- Corrupt `expires_at` values treat the peer as inactive instead of crashing the CLI
- Zero-duration `--expires` values (`0d`, `0h`) rejected at mutation time
- History pagination validated; `--limit` capped at 1000; most recent events returned
- `db restore --yes -` enforces a maximum stdin payload size
- Rich table rendering escapes user-controlled fields (terminal markup injection)
- `WGPL_DB_PATH` / `WGPL_WG_BIN` hardened against symlink and non-regular targets
- Audit metadata sanitized (no secrets; JSON-safe types; size/depth limits)
- Expired peers release IP/node slots after reclaim; soft-delete reclaim logs `reclaimed`
- `syncconf` temp file created with `chmod 600` before writing peer config

### Security

- Documented activation model, restore integrity, apply preflight, and accepted residual risks in `SECURITY.md`
- Database dump/restore at `chmod 600`; audit append-only triggers re-enforced on restore
- `chmod 600` enforced on writable database connections via `dbpath`
- `peer list` / `peer show` / idempotent `peer add` JSON do not expose `private_key` or `preshared_key`
- CI: bandit (SAST), pip-audit, gitleaks
