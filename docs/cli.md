# WGPL CLI Reference

All commands support the global `--json` or `-j` parameter (e.g., `wgpl -j peer list`) to produce machine-parseable outputs.

## Interface Management (`wgpl interface`)

- **`add <NAME> <ENDPOINT> <PUBKEY> <POOL_IP> [options]`**: Registers a new network. Accepts `--port`, `--dns`, `--mtu`, `--keepalive`, and `--desc`.
- **`list`**: Shows interfaces and their unique IDs.
- **`update <NAME_OR_ID> [options]`**: Modifies advanced network parameters (e.g., `--mtu 1360` or `--clear-mtu`). Shrinking `address_pool` is rejected if any non-soft-deleted peer (including expired rows) would fall outside the new CIDR.
- **`export <NAME_OR_ID>`**: Prints standard `[Peer]` blocks compatible with the WireGuard server. Only **active** peers are exported; wire-format validation runs before output.
- **`remove <NAME_OR_ID> [--force]`**: Deletes the interface. Fails while peer rows exist unless `--force` (run `peer prune` or remove peers first for a clean delete).
- **`history <NAME_OR_ID> [--limit N] [--offset N]`**: Shows append-only audit events (`--limit` max: 1000).

## Peer Management (`wgpl peer`)

- **`add <INTERFACE_NAME_OR_ID> <NAME> [options]`**: Creates a new client. `<NAME>` must be alphanumeric with optional `_` / `-` and max length 64. `--expires` accepts durations like `7d` or `24h` (must be greater than zero).
- **`list [--all] [--expired]`**: Shows active/all clients.
- **`show <ID> [--show-secrets]`**: Peer details; JSON omits private keys (same fields as `list --json`).
- **`config <ID> [-i INTERFACE] [--allowed-ips …]`**: Client `.conf` with private key. When the database has **more than one interface**, `-i` / `--interface` is **required** (even for a full UUID). Use `-i` to disambiguate ID prefixes on any multi-interface host.
- **`qr <ID> [-i INTERFACE] [-o <PNG_PATH>] [--allowed-ips …]`**: QR code for the client config; same `-i` rules as `config`.
- **`update <INTERFACE_NAME_OR_ID> <ID> [options]`**: Modifies properties or uses `--clear-*` to inherit from the interface. `--clear-expires` reactivates an expired peer and runs the same activation checks as `peer add` (IP in pool, no active collisions, wire-safe keys). Cannot combine `--expires` and `--clear-expires`.
- **`remove <INTERFACE_NAME_OR_ID> <ID> [--hard]`**: Soft-deletes a peer. Use `--hard` for physical deletion.
- **`prune <INTERFACE_NAME_OR_ID>`**: Purges expired and soft-deleted peers. Recommended before `interface remove` when inactive rows remain.
- **`history <INTERFACE_NAME_OR_ID> <ID> [--limit N] [--offset N]`**: Shows append-only audit events for a peer (`--limit` max: 1000).

## General & Database

- **`wgpl apply <INTERFACE_NAME_OR_ID>`**: Synchronizes state to the WireGuard kernel via `wg syncconf`. Fails before sync if the database fails consistency checks (invalid active peers, wire-format issues, IPs outside pool).
- **`wgpl validate [INTERFACE_NAME_OR_ID]`**: Dry-run integrity report (active peer collisions, pool fit, DNS, corrupt `expires_at`, invalid wire fields). Does not mutate state.
- **`wgpl db dump [-o FILE]`**: Binary SQLite backup at `chmod 600`.
- **`wgpl db restore --yes <FILE>`**: Restores from a binary backup. Validates schema contract and all stored wire-format fields; reinstalls audit immutability triggers. Destructive; use `--yes`. Pass `-` for stdin (size-capped).

## Operational notes

1. Mutations update the database only — run **`wgpl apply`** (or remote `interface export | ssh … wg syncconf`) to push changes to WireGuard.
2. After **`db restore`**, run **`validate`** then **`apply`** on each interface you manage.
3. Multi-interface hosts: always pass **`-i`** for `peer config` and `peer qr`.
