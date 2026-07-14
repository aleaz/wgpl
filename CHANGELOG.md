# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Notes

- **Scope (is / is not):** WGPL is a disconnected CLI for declarative hub-and-spoke IPv4 VPN intent (SQLite SSOT, BYOI). It is **not** a daemon/control plane, full-mesh overlay, direct site-to-site without a hub, IPv6 manager, WireGuard `.conf` importer, or self-service portal product (the FastAPI example is illustrative only). See README.
- **Known limitations:** Bring-your-own interface (BYOI) — WGPL does not create OS interfaces or configure hub forwarding/firewall/NAT; mutations update SQLite only (no auto-apply); remote hub sync is an operator pipe (`wgpl interface export | ssh … wg syncconf`); **IPv4-only** address pools, peer IPs, DNS, and AllowedIPs.
- **Schema evolution:** no in-place migrator; breaking schema changes require a new major version plus `db dump`/`restore` (see DESIGN.md).

### Added

- `wgpl status` overview command; `peer list --format compact`; honor `COLUMNS` for stdout table width
- Peer `list` / `show` JSON includes additive `interface` (hub name) alongside existing `interface_id`
- `fields.py` SSOT for entity `NAME_RE` and peer-over-interface DNS/MTU/keepalive cascade helpers
- Collision subclasses `NodeAlreadyAttachedError` and `RoutedNetworkOverlapError` (inherit `PeerAlreadyExistsError` for CLI compatibility)
- First-class **Node** entity: `nodes` table (globally unique `name`, optional `desc`) and `wgpl node` command group (`add`, `list`, `show`, `update`, `remove`, `prune`, `history`) for device identity independent of any tunnel
- Hybrid `wgpl peer add`: a positional `<name>` find-or-creates the node and attaches it; `--node <ref>` strictly attaches an existing node; exactly one is required. Peer JSON gains `node`, `node_id`, and `node_created`
- `wgpl validate` hub↔peer routed-network checks: an exact duplicate of an `interface.routed_networks` prefix is an error; a partial overlap is a warning
- Node adversarial regression tests (`tests/test_node_qa.py`) and restore warning/error-severity tests
- Intent-based hub-and-spoke routing: `routing.py` derives hub and client `AllowedIPs` from stored intent (`role`, `routed_networks`, `allowed_ips_policy`); derived values are never persisted
- Routing intent on interfaces and peers: `interfaces.routed_networks`; `peers.role` (`endpoint` | `subnet_router`), `routed_networks`, `allowed_ips_policy`, `custom_allowed_ips`
- CLI routing flags: `--role`, `--routed-networks`, `--allowed-ips-policy`, `--custom-allowed-ips` (and `--clear-*` counterparts) on `peer add` / `peer update`; `--routed-networks` on `interface add` / `interface update`
- `wgpl peer explain` — derived hub/client AllowedIPs and LAN↔LAN four-leg checklist for subnet routers
- `wgpl validate` routing topology checks (overlapping site LANs, pool overlap, asymmetric remote access, subnet-router keepalive warnings)
- JSON export metadata: `hub_allowed_ips` and `client_allowed_ips` on `peer list` / `peer show`; `client_allowed_ips` and `allowed_ips_source` on `peer config --json`
- Documentation: `docs/routing.md`, `docs/routing_matrix.md`, domain model and architecture verification in `DESIGN.md`, hub relay procedures in `docs/runbook.md`
- Exact SQLite schema contract on restore (reject extra tables, indexes, triggers, or views)
- Wire-safe MTU (1280–65535) and keepalive (0–65535) validation on export, apply preflight, and mutations
- `dbpath.open_exclusive_output()` for hardened CLI secret output paths
- `wg` binary resolution via fixed allowlist (PATH hijack mitigation for root)
- FastAPI self-service example: fail-closed `WGPL_PORTAL_API_KEY` guard with `secrets.compare_digest`
- Docker workflow: Trivy scans local image before registry push
- CI job `permissions: contents: read` (least privilege)
- Tests: routing derivation and topology (`tests/test_routing.py`, `tests/test_validate_topology.py`, `tests/test_cli_routing.py`)
- Tests: restore schema adversarial cases, output path hardening, wireformat MTU/keepalive, FastAPI guard

### Changed

- **Breaking (pre-release):** peer mutations require `-i` / `--interface` (no positional interface); examples: `peer add NAME -i IFACE`, `peer update PEER_ID -i IFACE`
- **Breaking (pre-release):** `--json` resource/list success always uses `{"status":"success","data":…}`; typed actions/reports (`apply`, `validate`, `db doctor`, restore/remove acks) expose top-level `status` without double-wrapping under `data`
- Read commands open the database readonly (no empty DB file created on list/show/status)
- CLI UX messages: human-mode `peer config` / ASCII `peer qr` warn on stderr about private keys; wrong `-i` with a unique peer prefix raises interface mismatch (not "not found"); `peer add -i` with an unknown interface hints `wgpl peer add <NAME> -i <INTERFACE>`
- Docs/help coherence: peer refs documented as UUID/hex prefix only (not node names); runbook examples and `peer list --interface`; `--db` / `WGPL_DB_PATH` and multi-interface `-i` help; `--json` stdout/stderr contract in README and `docs/cli.md`
- Maintainability (#2–#6): unified DNS/MTU/keepalive cascade and name regex via `fields.py`; removed `PeerResolvePolicy` and unused `wireguard.run_wg_command`; activation IP collisions raise `IpAlreadyInUseError`; trivial `_is_peer_active` / `_normalize_db_path` wrappers removed
- CLI skips database open for `--help`; permission-denied guidance prefers `--db` / ownership over bare `sudo`
- Mutations (`peer add` / `remove`, `interface add`) print apply hints; soft-delete messaging clarifies prune
- README install path prefers `uv`/`pip`; standalone binary marked experimental with checksum guidance; Quick Start pins `WGPL_DB_PATH` for sudo apply
- Release workflow: tag must match `pyproject.toml` version; PyInstaller pinned; binary built before PyPI publish; `SHA256SUMS` attached to GitHub Release
- CI: Python 3.12+3.13 matrix; `uv sync --frozen`; Docker images publish on version tags only; Dockerfile uses `uv.lock`
- Reject IPv6 interface endpoints; `peer show` accepts `-i`; BYOI noted on `interface add` / `apply` help
- Governance: CoC private contact, MAINTAINERS.md, CODEOWNERS catch-all, LICENSE copyright aligned to legal name
- Aligned classifier, README badge, CLI tagline, and package description with the hub-and-spoke intent identity (no longer “Peer Manager” / Beta framing)
- Documented CLI/JSON compatibility promise: no breaking CLI commands/flags or public `--json` field names without a major version bump (see README)
- Documentation gate: `docs/cli.md` documents `interface show` and `db doctor [--repair]`; DESIGN/README/SECURITY/routing emit narrative describes `wireformat` as emit formatting with shared validation/cascade (not “formatting only”); `docs/runbook.md` adds Troubleshooting (forgot `apply`, `-i`, DB/`--db`, `peer update` arg order)
- Hygiene: removed unused `integrity.validate_wire_peer_fields` and `consistency.get_peer_status_expired`; production `resolve_peer_ref` uses `access=PeerAccess.*` only
- Peers now reference a global node via `peers.node_id`; the `peers.name` column is removed (peer read paths JOIN `nodes` and expose the node name transparently). Device names are managed through `wgpl node`; `peer update` no longer accepts `--name` (rename with `node update`). Pre-release schema change — no migration, nothing was published
- A node attaches to a given interface at most once while active (partial unique index `idx_peers_active_node`); reclaiming an inactive peer slot is keyed by IP and `node_id`
- Audit trail gains a `node` entity type and node events; peer audit metadata records `node_id` for device provenance
- `peer config` and `peer qr` derive client `AllowedIPs` from `allowed_ips_policy` by default; `--allowed-ips` overrides a single export only
- Hub `interface export` and `apply` emit subnet-router `AllowedIPs` as tunnel `/32` plus advertised LAN prefixes (not tunnel `/32` only)
- `wgpl validate` reports routing topology issues with severities; errors exit 1, warnings exit 0
- Audit `updated` events include diffs for routing intent fields (`role`, `routed_networks`, `allowed_ips_policy`, `custom_allowed_ips`)
- Minimum MTU for mutations and export is **1280**
- `validate_state` delegates interface wire-field checks to `integrity.validate_wire_interface_fields`
- `dbpath` on Linux closes validation fd after connect; macOS re-checks inode before path-based open
- Interface descriptions escaped in Rich CLI output (`interface list` / `show`)
- `integrity` module: peer activation gate, wire-field validators, `validate_database(full=True)`
- `wireformat` module: wire-safe `build_server_config` / `build_client_config` and `validate_allowed_ips`
- `dbpath` module: unified SQLite opener (`O_NOFOLLOW`, fd-based connect, `chmod 600`)
- `PeerResolvePolicy` (`EXPORT_SECRET`, `MUTATE_INACTIVE`, `READ_ONLY`) for reference resolution in `core`
- Schema contract (`assert_schema_contract`, `PRAGMA user_version`) and `enforce_audit_immutability()` on init/restore
- `assert_database_valid()` preflight before `wgpl apply`
- `--show-secrets` on `peer show` to reveal preshared key in human-readable output
- Peer name validation (safe character set and length limit)
- Trust-boundary regression tests (DB path, `WGPL_WG_BIN`, audit metadata)
- CI security scanners: `bandit` (SAST) and `pip-audit` (dependency vulnerabilities)
- Restore integrity tests (malformed wire fields, audit trigger reinstall, schema version)
- `dbpath` and multi-interface export policy tests
- `interface update` pool shrink rejects any non-soft-deleted peer outside the new CIDR (including expired peers until pruned)
- `peer config` and `peer qr` require `--interface` / `-i` when the database has more than one interface
- `peer update --clear-expires` and future `--expires` transitions use the activation integrity gate
- `wgpl apply` fails closed when database validation fails (before `wg syncconf`)
- `wgpl db restore` validates schema contract, full wire-format rows, and recreates audit triggers
- `wgpl db dump` sets `chmod 600` on the output file
- All SQLite opens route through `dbpath` (live DB, restore, dump targets, schema checks)

### Fixed

- `wgpl apply --json` reports a missing/`wg` binary failure as `{"status":"error","message":…}` on stdout (same `_exit_error` gate as other domain failures); the remote `interface export | ssh` tip is a stderr hint and is not embedded in `message`
- Peer-add usage hint matches required `-i` syntax
- `wgpl db restore` no longer rejects a backup whose only validation issues are warnings (e.g. a subnet router without an effective keepalive); it fails closed on error-severity issues only, so a state the CLI can create is always restorable from its own backup
- `peer show --json` redacts private keys and preshared keys (consistent with `peer list --json`)
- Malformed wire-format fields in the database rejected on export, restore, and apply
- Restore cannot persist noop audit immutability triggers from a tampered backup
- Corrupt `expires_at` values treat the peer as inactive instead of crashing the CLI
- Zero-duration `--expires` values (`0d`, `0h`) rejected at mutation time
- `peer history` / `interface history` reject invalid pagination values and cap `--limit` at 1000
- `db restore --yes -` enforces a maximum stdin payload size
- Rich table rendering escapes user-controlled peer fields (terminal markup injection)
- `WGPL_DB_PATH` normalized and hardened against symlink/non-regular file targets
- `WGPL_WG_BIN` custom paths require existing, non-symlink, executable regular files
- Audit `exec_cmd` metadata sanitized and bounded
- Audit metadata validation enforces JSON-safe types plus size/depth limits
- Example FastAPI onboarding validates input and avoids returning raw subprocess stderr
- Example Ansible deployment avoids `shell:` for `wg syncconf` / `wg-quick save`

### Security

- Documented activation model, restore integrity, apply preflight, and accepted residual risks in `SECURITY.md`
- Database dump/restore at `chmod 600`; audit append-only triggers re-enforced on restore
- `chmod 600` enforced on database file at every connection via `dbpath`

## [1.0.0]

### Added

- `wgpl db restore --yes` — confirmation required before destructive restore
- `--interface` / `-i` on `peer config` and `peer qr` to disambiguate peer ID prefixes
- `--offset` on `peer history` and `interface history` for paginated audit queries
- Append-only `audit_events` table; `peer history` and `interface history` commands (`--json` supported)
- Audit events for peer create/remove/prune/reclaim and interface create/update/remove (including cascade on `--force`)
- `interface remove --force` — required when any peers remain on the interface
- `InterfaceHasPeersError` when removing an interface that still has peers without `--force`
- Gitleaks secret scan in CI
- `interface update` — change endpoint, port, public key, address pool, DNS, description, MTU, or keepalive without removing peers
- `peer update` — change name, IP, DNS override, description, MTU, or keepalive without rotating keys
- `wgpl validate [interface]` — dry-run consistency check (active peer IPs in pool, valid DNS)
- Docker-style peer ID prefixes on `peer config`, `peer qr`, and `peer remove`
- `peer qr --output` / `-o` writes a scannable PNG (ASCII remains the default)
- Optional `--ip` on `peer add` and `--dns` on interface/peer add
- Soft-delete by default on `peer remove`; `--hard` for physical deletion
- `peer prune <interface>` — permanently removes soft-deleted and expired peers
- `peer add --expires` — peer lifetime (`7d`, `24h`, etc.)
- `peer list --expired`, `--all`; JSON fields `status`, `expires_at`, `deleted_at`
- `wgpl db dump` / `wgpl db restore` — binary SQLite backup with atomic restore (`--yes` required)
- `InterfaceConflictError` — global uniqueness of interface `port` and `address_pool`
- Optional `desc`, `mtu`, and `keepalive` on interfaces and peers
- Effective DNS, MTU, and PersistentKeepalive cascade in client config
- Partial unique indexes on peers (`WHERE deleted_at IS NULL`) for IP and name
- README deployment architectures: BYOI Local, Linux server, MikroTik RouterOS v7
- `PeerInterfaceMismatchError` for wrong-interface peer operations
- Disconnected WireGuard peer manager CLI (`wgpl`)
- SQLite SSOT with WAL mode and exclusive transactions
- In-memory Curve25519 key generation via `cryptography`
- Commands: `interface`, `peer`, `apply`, `--json` M2M mode
- Client config and QR code export
- Declarative sync via `wg syncconf` (`apply` / `export`)
- CI: ruff, mypy, pytest
- `SECURITY.md`, `CONTRIBUTING.md`, GitHub issue/PR templates

### Changed

- CLI no longer imports `db` for `interface show` (lookup via `core.get_interface_by_ref`)
- **Breaking:** `interface remove` fails if the interface has any peers unless `--force` is passed
- Reclaiming an expired peer's IP or name logs `reclaimed` and soft-deletes the old row
- `get_peer_status()` delegates expiration checks to `_is_peer_active()`
- Strict layer boundaries: CLI reads go through `core`; no direct `db` imports in `cli.py`
- `wgpl db dump` writes a binary SQLite backup (not SQL text)
- `peer config` / `peer qr`: PersistentKeepalive and MTU from database cascade, not CLI flags

### Fixed

- `peer history` resolves short-ID prefixes for soft-deleted and pruned peers from audit events
- `db.update_peer` correctly distinguishes IP vs name uniqueness conflicts
- Consistent point-in-time database dumps under exclusive lock
- `peer update` resolves peer reference inside the transaction
- Soft-delete timestamps use ISO-8601 UTC
- `remove_peer` idempotent soft-remove; audit `updated` only on real value changes
- `peer history` / `interface history` `--limit` returns the most recent events
- `db restore`: validate row integrity before swap; rotate backups (keep 3)
- `syncconf` temp file created with `chmod 600` before writing peer config
- IP pool allocation uses `_is_peer_active()` (expired peers release addresses)
- Expired peers no longer block reuse of the same peer name on `peer add` / `peer update`

### Security

- `chmod 600` enforced on database file at every connection
- `peer list --json` redacts `private_key` and `preshared_key`
