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
#    A positional name find-or-creates the device node; --node attaches an existing one
wgpl peer add wg0 "Johns_Phone"
wgpl peer add wg0 "Server" --ip 10.0.0.50
wgpl peer add wg0 --node "Johns_Phone"   # attach an existing device (e.g. to a 2nd hub)
wgpl peer add wg0 "Guest" --expires 7d
wgpl peer list --interface wg0
wgpl peer list --interface wg0 --expired
wgpl peer list --interface wg0 --all

# 2a. Device identity (global nodes)
wgpl node add "Work_Laptop" --desc "CEO laptop"
wgpl node list
wgpl node show "Work_Laptop"
wgpl node update "Work_Laptop" --name "Work_Laptop_2"   # rename device (peer has no --name)
wgpl node remove "Work_Laptop_2" --force                # cascade its attachments
wgpl node prune                                         # drop orphan devices
wgpl node history "Johns_Phone"

# 2b. Update peer attachment without rotating keys (device rename is `node update`)
wgpl interface update wg0 --endpoint vpn2.example.com
wgpl peer update wg0 <PEER_ID> --ip 10.0.0.55
wgpl peer update wg0 <PEER_ID> --desc "CEO laptop" --mtu 1280
wgpl validate wg0

# 2c. Routing (subnet routers, split/full tunnel) — see docs/ROUTING.md
wgpl interface update wg0 --routed-networks "10.50.0.0/16"
wgpl peer add wg0 "Site_A_GW" --role subnet_router \
  --routed-networks "192.168.10.0/24" \
  --allowed-ips-policy all_remote_networks --keepalive 25
wgpl peer explain Site_A_GW
# Hub relay (ip_forward, FORWARD, optional MASQUERADE): docs/runbook.md#hub-routing-relay

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
wgpl peer history wg0 <PEER_ID>

# 3c. Remove interface (blocked if peers remain unless --force)
wgpl interface remove wg0 --force
wgpl interface history wg0

# 4. Sync with WireGuard (required after remove/prune to update the kernel)
#   Remote (disconnected):
wgpl interface export wg0 | ssh root@my-vpn-server "wg syncconf wg0 /dev/stdin"
#   Local (server with wireguard-tools):
wgpl apply wg0

# 5. Database backup (binary SQLite)
wgpl db dump -o backup.db
chmod 600 backup.db
wgpl db restore --yes backup.db
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
- A peer occupies an IP and a node attachment slot only while active (not soft-deleted and not expired).
  Reclaiming an expired peer's IP or node slot logs `reclaimed` and soft-deletes the old row; history remains in `audit_events`.
  `peer prune` hard-deletes inactive peer rows with a `pruned` audit event each (audit log itself is never pruned). Node identities survive `peer prune`; use `node prune` to drop orphan devices.
- `interface remove` fails if any peer rows exist; use `peer prune` / `peer remove` first, or `--force` (audited cascade).
- After `peer remove` or `peer prune`, run `wgpl apply` or `interface export` to sync the server.

## Code map

| File | Responsibility |
|---|---|
| `src/wgpl/cli.py` | Typer commands, Rich/JSON formatting; no direct `db` access |
| `src/wgpl/core.py` | Business orchestration (CRUD, export, sync, node lifecycle); re-exports from helper modules |
| `src/wgpl/refs.py` | Peer, interface, and node (`resolve_node_ref`) reference resolution |
| `src/wgpl/ipam.py` | IPv4 pool allocation and inactive slot reclamation |
| `src/wgpl/audit.py` | Audit trail append and history queries |
| `src/wgpl/consistency.py` | `validate_state` and `assert_database_valid` |
| `src/wgpl/routing.py` | Derived AllowedIPs (hub + client); pure functions |
| `src/wgpl/restore.py` | `dump_database` and `restore_database` |
| `src/wgpl/validators.py` | Input validation helpers (DNS, endpoint, keys) |
| `src/wgpl/db.py` | Secure connection, transactions, SQLite CRUD |
| `src/wgpl/wireguard.py` | x25519 keys, PSK, `wg syncconf` |
| `src/wgpl/exceptions.py` | `WgplException` hierarchy |

## Commands

Implemented: `interface` CRUD + update, `node` CRUD + prune + history, `peer` CRUD
+ update + prune + `explain` (hybrid `peer add <name>` / `--node <ref>`),
routing flags (`--role`, `--routed-networks`, `--allowed-ips-policy`), `validate`,
`apply`, `db dump`, `db restore`, `--json` M2M mode.

Routing model: [docs/ROUTING.md](../../docs/ROUTING.md). Hub relay ops:
[docs/runbook.md — Hub routing relay](../../docs/runbook.md#hub-routing-relay).

Future work: `peer rotate-keys`, `interface rename`, `peer move` (follow architecture invariants).

## Pre-PR checklist

Follow [CONTRIBUTING.md — Validation and Pull requests](CONTRIBUTING.md#validation-required-before-opening-a-pr).
Respect invariants in [`.cursor/rules/wgpl-architecture.mdc`](.cursor/rules/wgpl-architecture.mdc)
(SSOT, no auto-sync, exclusive transactions, `chmod 600`, no `shell=True`).
Run a CLI smoke test with a temporary `WGPL_DB_PATH` before opening the PR.

## Commit messages

Follow Conventional Commits. Write subjects that make sense in `git log` without
session context. **Never** cite internal control labels (audit IDs, debt wave names
like `v1.2`, debt IDs like `D16`, plan todos, `.cursor/plans/` slugs) — they are
not semver, not git tags, and mean nothing outside the session.
See [CONTRIBUTING.md](CONTRIBUTING.md#commit-messages).

## Git (AI agents)

Follow [`.cursor/rules/wgpl-git-agent.mdc`](.cursor/rules/wgpl-git-agent.mdc):

- Commit only when the user explicitly asks.
- **Never** add `Co-authored-by` trailers (rewrite with `git commit-tree` if auto-injected).
- **Never** push to remote unless the user explicitly asks.
