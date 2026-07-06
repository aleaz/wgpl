# WGPL CLI Reference

All commands support the global `--json` or `-j` parameter (e.g., `wgpl -j peer list`) to produce machine-parseable outputs.

## Interface Management (`wgpl interface`)

- **`add <NAME> <ENDPOINT> <PUBKEY> <POOL_IP> [options]`**: Registers a new network. Accepts `--port`, `--dns`, `--mtu`, `--keepalive`, and `--desc`.
- **`list`**: Shows interfaces and their unique IDs.
- **`update <NAME_OR_ID> [options]`**: Modifies advanced network parameters (e.g., `--mtu 1360` or `--clear-mtu`).
- **`export <NAME_OR_ID>`**: Prints standard `[Peer]` blocks compatible with the WireGuard server.
- **`remove <NAME_OR_ID> [--force]`**: Deletes the interface (requires `--force` if peers exist).
- **`history <NAME_OR_ID> [--limit N] [--offset N]`**: Shows append-only audit events.

## Peer Management (`wgpl peer`)

- **`add <INTERFACE_NAME_OR_ID> <NAME> [options]`**: Creates a new client. Accepts `--ip`, `--dns`, `--expires`, `--mtu`, `--keepalive`, and `--desc`.
- **`list [--all] [--expired]`**: Shows active/all clients.
- **`show <ID> [--show-secrets]`**: Peer details; JSON omits private keys (same fields as `list --json`).
- **`config <ID> [--interface NAME_OR_ID]`**: Shows the client configuration ready for consumption.
- **`qr <ID> [-o <PNG_PATH>] [--interface NAME_OR_ID]`**: Generates the QR code.
- **`update <INTERFACE_NAME_OR_ID> <ID> [options]`**: Modifies properties or uses `--clear-*` to inherit from the interface.
- **`remove <INTERFACE_NAME_OR_ID> <ID> [--hard]`**: Soft-deletes a peer. Use `--hard` for physical deletion.
- **`prune <INTERFACE_NAME_OR_ID>`**: Purges expired and soft-deleted peers.
- **`history <INTERFACE_NAME_OR_ID> <ID> [--limit N] [--offset N]`**: Shows append-only audit events for a peer.

## General & Database

- **`wgpl apply <INTERFACE_NAME_OR_ID>`**: Synchronizes the state to the WireGuard kernel seamlessly using `wg syncconf`.
- **`wgpl validate [INTERFACE_NAME_OR_ID]`**: Verifies database integrity.
- **`wgpl db dump`**: Extracts the entire DB as a binary SQLite backup.
- **`wgpl db restore --yes <FILE>`**: Safely restores the database from a binary SQLite backup (destructive).
