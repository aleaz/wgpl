# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed

- Treat naive `expires_at` timestamps as UTC in lifecycle checks (no crash on legacy rows)
- `peer history` / `interface history` `--limit` returns the most recent events (not the oldest)
- `db restore`: validate row integrity before swap; rotate backups (keep 3); clean tmp on init failure
- `peer add` exits cleanly on invalid MTU/keepalive (ValueError)

### Added

- Regression tests: audit rollback on failure, concurrent `add_peer`, dump/restore roundtrip, CLI `db restore`, peer update reclaim, audit metadata `preshared_key` guard
- Append-only `audit_events` table; `peer history` and `interface history` commands (`--json` supported)
- Audit events for peer create/remove/prune/reclaim and interface create/update/remove (including cascade on `--force`)
- `interface remove --force` — required when any peers remain on the interface
- `InterfaceHasPeersError` when removing an interface that still has peers without `--force`
- `peer update` logs an `updated` audit event with changed field names
- Gitleaks secret scan in CI
- `interface update` — change endpoint, port, public key, address pool, DNS, description, MTU, or keepalive without removing peers
- `peer update` — change name, IP, DNS override, description, MTU, or keepalive without rotating keys
- `wgpl validate [interface]` — dry-run consistency check (active peer IPs in pool, valid DNS)
- Docker-style peer ID prefixes: `peer config`, `peer qr`, and `peer remove` accept a unique hex prefix (as shown in `peer list`); `--json` still returns the full UUID
- `peer qr --output` / `-o` writes a scannable PNG (ASCII remains the default)
- Optional `--ip` on `peer add` and `--dns` on `interface add` / `peer add` (interface default, peer override; embedded in client config export)
- Soft-delete by default on `peer remove`; `--hard` for physical deletion
- `peer prune <interface>` — permanently removes soft-deleted and expired peers
- `peer add --expires` — peer lifetime (`7d`, `24h`, etc.)
- `peer list --expired`, `--all`; JSON fields `status`, `expires_at`, `deleted_at`
- `wgpl db dump` / `wgpl db restore` — logical SQL backup with atomic restore
- `InterfaceConflictError` — global uniqueness of interface `port` and `address_pool`
- Optional `desc`, `mtu`, and `keepalive` on interfaces and peers (add, update, and `--clear-*` flags)
- Effective DNS, MTU, and PersistentKeepalive cascade (peer override → interface default) in client config
- Partial unique indexes on peers (`WHERE deleted_at IS NULL`) for IP and name
- README deployment architectures: BYOI Local, Linux server, MikroTik RouterOS v7
- `PeerInterfaceMismatchError` for wrong-interface peer operations
- Interface add/remove routed through `core`

### Fixed

- `peer list --json`: `dns` reflects the effective value; added `dns_override` for the peer-stored value
- `peer remove --json`: returns canonical UUID in `id` plus the user-supplied ref in `input`
- `interface remove` reports an error when the interface does not exist
- `syncconf` temp file is created with `chmod 600` before writing peer config
- Atomic database restore with schema validation, `.bak.*` backup at `chmod 600`, and WAL/SHM cleanup
- Double peer ID resolution bug in `peer remove`
- `validate` interface issues use `peer: null` instead of an empty string
- `db.add_peer` distinguishes IP vs name uniqueness conflicts
- `validate` and `resolve_peer_ref` skip soft-deleted and expired peers by default
- `peer remove` on an already soft-deleted peer returns not found instead of re-deleting silently
- IP pool allocation no longer treats expired peers as occupying addresses (`_pool_used_ips` uses `_is_peer_active`)
- `peer prune` removes expired peers correctly (`_is_peer_active` in core, not broken SQL timestamp comparison)
- Expired peers no longer block reuse of the same peer name on `peer add` / `peer update`

### Changed

- **Breaking:** `interface remove` fails if the interface has any peers unless `--force` is passed
- Reclaiming an expired peer's IP or name logs `reclaimed` and hard-deletes the old row (audit preserved in `audit_events`)
- `get_peer_status()` delegates expiration checks to `_is_peer_active()`
- `peer update` logs an `updated` audit event with changed field names
- `peer history` / `interface history` accept `--limit` (default 100)
- README rewritten for upcoming 1.0 release
- Strict layer boundaries: CLI reads go through `core` (`list_interfaces`, `list_peers`, `ensure_database`); no direct `db` imports in `cli.py`
- Peer lifecycle SSOT in `core`: `get_peer_status`, `get_effective_dns`; expired peers release IPs for allocation
- `wgpl db dump` hints on stderr; SQL script lines come from `core.dump_database_lines()` (no I/O in core)
- `peer config` / `peer qr`: PersistentKeepalive and MTU come from the database (interface → peer cascade), not CLI flags
- CONTRIBUTING: self-contained Conventional Commit messages (no internal process IDs)

### Security

- SECURITY.md: clarify `peer update` vs key rotation via remove/add
- Database dump/restore hints for `chmod 600`; restore backups created with restrictive permissions

## [0.1.0] - 2026-07-02

### Added

- Disconnected WireGuard peer manager CLI (`wgpl`)
- SQLite SSOT with WAL mode and exclusive transactions
- In-memory Curve25519 key generation via `cryptography`
- Commands: `interface`, `peer`, `apply`, `--json` M2M mode
- Client config and QR code export
- Declarative sync via `wg syncconf` (`apply` / `export`)
- CI: ruff, mypy, pytest
- `SECURITY.md`, `CONTRIBUTING.md`, GitHub issue/PR templates

### Security

- `chmod 600` enforced on database file at every connection
- `peer list --json` redacts `private_key` and `preshared_key`

[0.1.0]: https://github.com/aleaz/wgpl/releases/tag/v0.1.0
