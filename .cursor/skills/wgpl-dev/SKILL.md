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
wgpl interface add wg0 vpn.example.com <SERVER_PUBLIC_KEY> 10.0.0.0/24 --dns 1.1.1.1
wgpl interface add wg0 vpn.example.com <SERVER_PUBLIC_KEY> 10.0.0.0/24 \
  --desc "Production VPN" --mtu 1420 --keepalive 25
wgpl interface list

# 2. Create peers (IP, keypair, and PSK are generated automatically)
wgpl peer add wg0 "Johns_Phone"
wgpl peer add wg0 "Server" --ip 10.0.0.50
wgpl peer add wg0 "Kids" --dns 9.9.9.9
wgpl peer add wg0 "Guest" --expires 7d
wgpl peer list
wgpl peer list wg0 --expired
wgpl peer list wg0 --all

# 2b. Update without rotating keys
wgpl interface update wg0 --endpoint vpn2.example.com
wgpl peer update wg0 <PEER_ID> --name "Work Laptop"
wgpl peer update wg0 <PEER_ID> --ip 10.0.0.55
wgpl peer update wg0 <PEER_ID> --desc "CEO laptop" --mtu 1280
wgpl validate wg0

# 3. Extract client configuration (full UUID or short prefix from peer list)
wgpl peer config <PEER_ID>
wgpl peer config 55c521ad2d94
wgpl peer config <PEER_ID> --allowed-ips="10.0.0.0/24"
wgpl peer qr <PEER_ID>
wgpl peer qr <PEER_ID> -o phone.png

# 3b. Remove peers (soft-delete by default)
wgpl peer remove wg0 <PEER_ID>
wgpl peer remove wg0 <PEER_ID> --hard
wgpl peer prune wg0

# 4. Sync with WireGuard (required after remove/prune to update the kernel)
#   Remote (disconnected):
wgpl interface export wg0 | ssh root@my-vpn-server "wg syncconf wg0 /dev/stdin"
#   Local (server with wireguard-tools):
wgpl apply wg0

# 5. Database backup
wgpl db dump > backup.sql
wgpl db restore < backup.sql
```

## Automation (M2M)

- Global flag `--json` / `-j`: data on stdout, logs on stderr.
- Example: `NEW_IP=$(wgpl --json peer add wg0 "Backup" | jq -r '.ip_address')`
- Database location: `~/.wgpl.db` by default; override with `WGPL_DB_PATH` or `--db`.

## Operational notes

- `peer config` / `peer qr` read DNS, MTU, and PersistentKeepalive from the database
  (peer override → interface default). Set values with `peer update` or interface defaults.
- Soft-deleted and expired peers are excluded from `resolve_peer_ref` by default;
  use `peer remove --hard` to physically delete a soft-deleted peer.
- A peer occupies an IP and name in the pool only while active (not soft-deleted and not expired).
  Inactive peers release IP and name on `peer add` / `peer update`; `peer prune` hard-deletes
  all inactive rows using `_is_peer_active` in core.
- After `peer remove` or `peer prune`, run `wgpl apply` or `interface export` to sync the server.

## Code map

| File | Responsibility |
|---|---|
| `src/wgpl/cli.py` | Typer commands, Rich/JSON formatting; no direct `db` access |
| `src/wgpl/core.py` | IP allocation, lifecycle rules, list reads, config and QR generation |
| `src/wgpl/db.py` | Secure connection, transactions, SQLite CRUD |
| `src/wgpl/wireguard.py` | x25519 keys, PSK, `wg syncconf` |
| `src/wgpl/exceptions.py` | `WgplException` hierarchy |

## Commands

Implemented: `interface` CRUD + update, `peer` CRUD + update + prune, `validate`,
`apply`, `db dump`, `db restore`, `--json` M2M mode.

Future work: `peer rotate-keys`, `interface rename`, `peer move` (follow architecture invariants).

## Pre-PR checklist

Follow [CONTRIBUTING.md — Validation and Pull requests](CONTRIBUTING.md#validation-required-before-opening-a-pr).
Respect invariants in [`.cursor/rules/wgpl-architecture.mdc`](.cursor/rules/wgpl-architecture.mdc)
(SSOT, no auto-sync, exclusive transactions, `chmod 600`, no `shell=True`).
Run a CLI smoke test with a temporary `WGPL_DB_PATH` before opening the PR.

## Commit messages

Follow Conventional Commits. Write subjects that make sense in `git log` without
session context. **Never** cite internal IDs (audit items, plan todos, `.cursor/plans/`
slugs, agent checklist steps) — they are not in the repo and mean nothing later.
See [CONTRIBUTING.md](CONTRIBUTING.md#commit-messages).

## Git (AI agents)

Follow [`.cursor/rules/wgpl-git-agent.mdc`](.cursor/rules/wgpl-git-agent.mdc):

- Commit only when the user explicitly asks.
- **Never** add `Co-authored-by` trailers (rewrite with `git commit-tree` if auto-injected).
- **Never** push to remote unless the user explicitly asks.
