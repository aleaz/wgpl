# Security Policy

## Supported versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | Yes       |
| 1.0.x   | Yes       |

## Reporting a vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security issues privately via [GitHub Security Advisories](https://github.com/aleaz/wgpl/security/advisories/new).

We aim to acknowledge reports within 48 hours and provide a fix or mitigation plan as soon as possible.

## Scope

WGPL is a local CLI that stores WireGuard cryptographic material (private keys, preshared keys) in a SQLite database file.

In scope:

- Unauthorized disclosure of keys via CLI output, logs, or exports
- SQL injection, command injection, or path traversal in WGPL itself
- Weak file permissions on the database file
- Race conditions leading to IP collisions or data corruption

Out of scope:

- WireGuard kernel implementation bugs (report upstream)
- Misconfiguration of firewalls, DNS, or `wg-quick` on the host
- Physical access to a machine where `~/.wgpl.db` is already readable

## Threat model

- The database file (default `~/.wgpl.db`) contains **private keys**. WGPL enforces `chmod 600` on every connection via the `dbpath` opener (`O_NOFOLLOW` where supported, fd-based SQLite connect).
- Never commit `*.db` or `*.sqlite3` files to version control.
- `wgpl peer list --json` returns only public fields; use `wgpl peer config <id>` (full UUID or unique short prefix from `peer list`) when a client private key is required.
- `wgpl peer show --json` returns the same redacted fields as `peer list --json` (no private keys). Human output hides the preshared key by default; use `--show-secrets` to display it, or `peer config` / `peer qr` for full client export.
- When the database contains **more than one interface**, `peer config` and `peer qr` require `--interface` / `-i` even if the peer ID is globally unique. This prevents accidental secret export from the wrong VPN.
- QR PNG files from `wgpl peer qr -o` encode the full client config (including private keys). WGPL sets `chmod 600` on the output file; do not commit or share QR images in public channels.
- `wgpl apply` requires an existing WireGuard interface in the kernel; WGPL does not create network interfaces.

## Activation and consistency model

- A peer is **active** when it is not soft-deleted and not expired (`integrity.is_peer_active()` is the SSOT). Corrupt `expires_at` values are treated as inactive (no crash); `wgpl validate` reports `corrupt_expires_at`.
- Transitions to active state (`peer add`, `peer update` with a future `--expires`, or `--clear-expires`) pass the **activation integrity gate**: IP inside the current pool, valid name, wire-safe keys, no collision with another active peer.
- Shrinking an interface `address_pool` is rejected if any non-soft-deleted peer (including expired rows not yet pruned) would fall outside the new CIDR.
- Durations that yield immediate expiration (`0d`, `0h`) are rejected at mutation time.

## Export and apply boundaries

- All WireGuard text output (`interface export`, `peer config`, `apply` / `syncconf`) passes through the **wireformat** boundary: fields with control characters or invalid Base64 keys are rejected before emission.
- `wgpl apply` runs a database consistency preflight (`validate_state`) and aborts before `wg syncconf` if active peers are invalid.
- Mutations update the SQLite SSOT only. The kernel may remain stale until you run `wgpl apply` (or `interface export | ssh … wg syncconf`). Treat post-mutation `apply` as part of your operational checklist.

## Restore integrity

- `wgpl db restore` treats backups as **untrusted input**:
  - Schema contract check (required tables, indexes, supported `PRAGMA user_version`).
  - Row-level validation (`validate_state` plus full wire-format scan of every peer/interface row).
  - `enforce_audit_immutability()` recreates append-only audit triggers (no `IF NOT EXISTS` bypass).
- Malformed keys or weakened audit triggers in a backup are rejected or repaired before the live database is replaced.
- `wgpl db dump` output is written at `chmod 600`.

## Residual risks (accepted)

- **Stale WireGuard kernel state** until `apply` — by design; document in runbooks.
- **Audit `actor` field** may reflect `SUDO_USER` / `USER` from the environment on shared hosts.
- **`examples/fastapi-self-service.py`** is illustrative only; do not deploy without authentication and network controls.

## Secure usage

- Restrict filesystem permissions on the database path (`WGPL_DB_PATH` or `--db`). Symlinks are rejected.
- Run `wgpl interface export` over SSH to trusted hosts only.
- Use `wgpl peer update` to change peer name, IP, or DNS without rotating keys.
- If a private key or PSK may have been exposed, remove the peer and add a new one
  (key rotation is not available via `peer update`).
- Run `wgpl validate` after bulk changes or restore to confirm peer IPs, DNS, and wire-format fields.
- Run `wgpl apply` after mutations that should reach the kernel.

- `wgpl db dump` output is a **binary SQLite database** containing private keys for all peers. Treat backups like the live database file (`chmod 600`, never commit to git).
- `wgpl db restore` replaces the live database atomically after validation; it is destructive and requires `--yes`. Warnings (e.g. WAL checkpoint blocked) go to stderr.
- `peer history` and `interface history` store **public keys** only; `private_key` and `preshared_key` are blocked from audit metadata.
- Append-only `audit_events` grows without in-place deletion (SQLite triggers enforce immutability; restore reinstalls them). Archive periodically with `wgpl db dump -o archive.db`; use `wgpl peer prune` to remove inactive peer rows only (audit history is preserved).
- Before `interface remove`, prune or remove peers (`interface remove` fails while peer rows exist unless `--force`).
