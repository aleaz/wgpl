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

- The database file (default `~/.wgpl.db`) contains **private keys**. WGPL enforces `chmod 600` on every connection.
- Never commit `*.db` or `*.sqlite3` files to version control.
- `wgpl peer list --json` returns only public fields; use `wgpl peer config <id>` (full UUID or unique short prefix from `peer list`) when a client private key is required.
- `wgpl peer show --json` returns the same redacted fields as `peer list --json` (no private keys). Human output hides the preshared key by default; use `--show-secrets` to display it, or `peer config` / `peer qr` for full client export.
- QR PNG files from `wgpl peer qr -o` encode the full client config (including private keys). WGPL sets `chmod 600` on the output file; do not commit or share QR images in public channels.
- `wgpl apply` requires an existing WireGuard interface in the kernel; WGPL does not create network interfaces.

## Secure usage

- Restrict filesystem permissions on the database path (`WGPL_DB_PATH` or `--db`).
- Run `wgpl interface export` over SSH to trusted hosts only.
- Use `wgpl peer update` to change peer name, IP, or DNS without rotating keys.
- If a private key or PSK may have been exposed, remove the peer and add a new one
  (key rotation is not available via `peer update`).
- Run `wgpl validate` after bulk changes to confirm peer IPs still fit their pools.

- `wgpl db dump` output is a **binary SQLite database** containing private keys for all peers. Treat backups like the live database file (`chmod 600`, never commit to git).
- `wgpl db restore` replaces the live database atomically after validation; it is destructive and requires `--yes`. Warnings (e.g. WAL checkpoint blocked) go to stderr.
- `peer history` and `interface history` store **public keys** only; `private_key` and `preshared_key` are blocked from audit metadata.
- Append-only `audit_events` grows without in-place deletion (SQLite triggers enforce immutability). Archive periodically with `wgpl db dump -o archive.db`; use `wgpl peer prune` to remove inactive peer rows only (audit history is preserved).
