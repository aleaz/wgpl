---
name: wgpl-dev
description: >-
  WGPL (WireGuard Peer Lite) CLI development and usage workflows. Use when adding
  interfaces or peers, generating client configs or QR codes, exporting/applying
  state to WireGuard, or preparing a change for PR in this repository.
---

# WGPL — CLI development and usage

WGPL manages WireGuard *peers* with the SQLite database as the single source of
truth (SSOT). See invariants in `.cursor/rules/wgpl-architecture.mdc`.

## Lifecycle (README)

```bash
# 1. Register the base interface and its IP pool
wgpl interface add wg0 vpn.example.com <SERVER_PUBLIC_KEY> 10.0.0.0/24 --port 51820
wgpl interface list

# 2. Create peers (IP, keypair, and PSK are generated automatically)
wgpl peer add wg0 "Johns_Phone"
wgpl peer list

# 3. Extract client configuration (full UUID or short prefix from peer list)
wgpl peer config <PEER_ID>
wgpl peer config 55c521ad2d94
wgpl peer config <PEER_ID> --allowed-ips="10.0.0.0/24" --keepalive=21
wgpl peer qr <PEER_ID>
wgpl peer qr <PEER_ID> -o phone.png
wgpl peer remove wg0 <PEER_ID>
wgpl peer remove wg0 55c521ad2d94

# 4. Sync with WireGuard
#   Remote (disconnected):
wgpl interface export wg0 | ssh root@my-vpn-server "wg syncconf wg0 /dev/stdin"
#   Local (server with wireguard-tools):
wgpl apply wg0
```

## Automation (M2M)

- Global flag `--json` / `-j`: data on stdout, logs on stderr.
- Example: `NEW_IP=$(wgpl --json peer add wg0 "Backup" | jq -r '.ip_address')`
- Database location: `~/.wgpl.db` by default; override with `WGPL_DB_PATH` or `--db`.

## Code map

| File | Responsibility |
|---|---|
| `src/wgpl/cli.py` | Typer commands, input validation, Rich/JSON output |
| `src/wgpl/core.py` | IP allocation, orchestration, config and QR generation |
| `src/wgpl/db.py` | Secure connection, transactions, SQLite CRUD |
| `src/wgpl/wireguard.py` | x25519 keys, PSK, `wg syncconf` |
| `src/wgpl/exceptions.py` | `WgplException` hierarchy |

## Pre-PR checklist (repo-specific)

1. `uv run ruff check src/ tests/` passes with no findings.
2. `uv run mypy src/` passes with no type errors.
3. `uv run pytest` passes.
3. Invariants in `.cursor/rules/wgpl-architecture.mdc` respected
   (SSOT, no auto-sync, exclusive transactions, `chmod 600`, no `shell=True`).
4. New commands support `--json` and send logs to stderr.
5. New domain errors inherit from `WgplException`.
6. CLI smoke test with a temporary `WGPL_DB_PATH` before opening the PR.
