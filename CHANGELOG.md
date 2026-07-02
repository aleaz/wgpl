# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- Docker-style peer ID prefixes: `peer config`, `peer qr`, and `peer remove` accept a unique hex prefix (as shown in `peer list`); `--json` still returns the full UUID
- `peer qr --output` / `-o` writes a scannable PNG (ASCII remains the default)
- Optional `--ip` on `peer add` and `--dns` on `interface add` / `peer add` (interface default, peer override; embedded in client config export)

### Fixed

- `peer list --json`: `dns` now reflects the effective value (interface default or peer override); added `dns_override` for the peer-stored value
- `peer remove --json`: returns canonical UUID in `id` plus the user-supplied ref in `input`

### Changed

- README: document `--json` flag position (before subcommand) and JSON output shapes per command

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
