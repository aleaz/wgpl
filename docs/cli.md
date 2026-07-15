# WGPL CLI Reference

All commands support the global `--json` or `-j` parameter (e.g., `wgpl -j peer list`) to produce machine-parseable outputs.

**JSON envelope:**

| Kind | Shape | Notes |
|------|--------|--------|
| Resource / list success | `{"status":"success","data": …}` | Single object or array under `data`. Use `jq '.data'`, `.data[]`, `.data.ip_address`. |
| Domain errors | `{"status":"error","message":…}` | On **stdout**; human error lines and recovery hints on **stderr**. |
| Typed reports / actions | Top-level `status` **without** a `data` wrap | e.g. `validate`, `db doctor`, `apply`, `db restore`, `peer remove` / `peer prune` ack. |

## Scripting & Automation Contract

WGPL uses a strict channel separation design:
- **`stdout`** is exclusively for the primary data payload (config text, binary dumps, generated tables, or JSON envelopes).
- **`stderr`** is the human diagnostic channel (success messages, warnings, logs, and validation reports).

If you are writing bash scripts, do **not** attempt to parse the text output of mutating commands (like `peer add` or `validate`). Standard success messages like `[green]Added peer...[/green]` are sent to `stderr`, meaning standard command substitution (`RESULT=$(wgpl peer add ...)`) will yield an empty string.

You **must** use the `--json` flag for automation. When `--json` is active, WGPL guarantees that a single, predictable JSON object will be emitted to `stdout` (even for errors), making it perfectly safe for `jq` pipelines.

---

Database path: global `--db PATH` or environment `WGPL_DB_PATH` (default `~/.wgpl.db`).

Routing intent is documented in [routing.md](routing.md). Operational hub
relay steps are in [runbook.md — Hub routing relay](runbook.md#hub-routing-relay).

## Interface Management (`wgpl interface`)

- **`add <NAME> <ENDPOINT> <PUBKEY> <POOL_IP> [options]`**: Registers a new network. Accepts `--port`, `--dns`, `--mtu`, `--keepalive`, `--desc`, and `--routed-networks` (comma-separated CIDRs behind the hub for split tunnel).
- **`list`**: Shows interfaces and their unique IDs.
- **`show <NAME_OR_ID>`**: Interface details (endpoint, port, public key, address pool, DNS/MTU/keepalive defaults, description).
- **`update <NAME_OR_ID> [options]`**: Modifies interface settings. Options: `--endpoint`, `--port`, `--public-key`, `--address-pool`, `--dns`/`--clear-dns`, `--desc`/`--clear-desc`, `--mtu`/`--clear-mtu`, `--keepalive`/`--clear-keepalive`, `--routed-networks`/`--clear-routed-networks`. Shrinking `address_pool` is rejected if any non-soft-deleted peer (including expired rows) would fall outside the new CIDR.
- **`export <NAME_OR_ID>`**: Prints standard `[Peer]` blocks compatible with the WireGuard server. Only **active** peers are exported; wire-format validation runs before output.
- **`remove <NAME_OR_ID> [--force]`**: Deletes the interface. Fails while peer rows exist unless `--force` (run `peer prune` or remove peers first for a clean delete).
- **`history <NAME_OR_ID> [--limit N] [--offset N]`**: Shows append-only audit events (`--limit` max: 1000).

## Node Management (`wgpl node`)

A **node** is a global device identity (name + description). A peer is a node's
attachment to one interface. Node names are **globally unique**.

- **`add <NAME> [--desc TEXT]`**: Creates a device identity. `<NAME>` must be alphanumeric with optional `_` / `-`, max length 64, and unique across the database.
- **`list`**: Shows nodes with their short ID, name, active **attachment count**, and description.
- **`show <REF>`**: Node details (`<REF>` is a node name or ID prefix). JSON includes `attachment_count`.
- **`update <REF> [--name NEW] [--desc TEXT | --clear-desc]`**: Renames or re-describes a device. A rename is reflected everywhere peers of that node are displayed or exported. (Peer rename lives here — `peer update` has no `--name`.)
- **`remove <REF> [--force]`**: Removes the node. Refused while attachments remain unless `--force`, which cascades every attachment (audited) then deletes the node.
- **`prune`**: Hard-deletes **orphan** nodes only (zero attachments, including soft-deleted). Attached nodes are untouched.
- **`history <REF> [--limit N] [--offset N]`**: Append-only audit events for the node, including after removal (`--limit` max: 1000).

## Peer Management (`wgpl peer`)

Mutations and scoped history require **`-i` / `--interface`**. Argument order is **peer ref first**, then `-i INTERFACE` (same family as `show` / `config`).

- **`add [NAME] -i INTERFACE [--node REF] [options]`**: Attaches a device to the interface as a peer. Provide **exactly one** of: a positional `<NAME>` (find-or-create the node by that name, then attach) **or** `--node <REF>` (strictly attach an existing node by name/ID). `<NAME>` must be alphanumeric with optional `_` / `-` and max length 64. A node may attach to a given interface only once. Options: `--ip` (explicit IP from pool; auto-allocated if omitted), `--dns` (DNS override for this peer), `--expires` (duration like `7d` or `24h`; units: `h`, `d`; must be > 0), `--desc`, `--mtu`, `--keepalive`. Routing: `--role endpoint|subnet_router`, `--routed-networks`, `--allowed-ips-policy`, `--custom-allowed-ips`. JSON adds `node`, `node_id`, and `node_created` under `data`.
- **`list [-i INTERFACE] [--all] [--expired] [--format table|compact]`**: Shows active/all clients (optional `-i` filter). `--format compact` / `-f compact` prints one line per peer. JSON includes `interface` (hub name) alongside `interface_id`, derived `hub_allowed_ips` / `client_allowed_ips`, plus `desc`, effective/override `mtu` and `keepalive` (same model as `peer update` JSON).
- **`show <ID> [-i INTERFACE] [--show-secrets]`**: Peer details (`<ID>` = peer UUID or unique hex prefix from `peer list`, not the node name). JSON omits private keys (same fields as `list --json`, including `interface` / `interface_id`, derived AllowedIPs and desc/mtu/keepalive). Pass `-i` when the database has more than one interface and you use `--show-secrets`.
- **`explain <ID> [-i INTERFACE]`**: Derived hub/client AllowedIPs and LAN↔LAN four-leg checklist for subnet routers.
- **`config <ID> [-i INTERFACE] [--allowed-ips …]`**: Client `.conf` with private key. Default AllowedIPs are **derived** from `allowed_ips_policy`; `--allowed-ips` overrides for this export only. When the database has **more than one interface**, `-i` / `--interface` is **required** (even for a full UUID). JSON adds `client_allowed_ips` and `allowed_ips_source` (`derived` | `override`).
- **`qr <ID> [-i INTERFACE] [-o <PNG_PATH>] [--allowed-ips …]`**: QR code for the client config; same `-i` and AllowedIPs rules as `config`.
- **`update <ID> -i INTERFACE [options]`**: Modifies attachment properties or uses `--clear-*` to inherit from the interface. `-i` is **required**. To rename the device, use `node update` (there is no `--name` here). Fields: `--ip`, `--dns`/`--clear-dns`, `--desc`/`--clear-desc`, `--mtu`/`--clear-mtu`, `--keepalive`/`--clear-keepalive`, `--expires`/`--clear-expires` (`--expires` units: `h` or `d` only, e.g. `24h`, `30d`). Routing fields: `--role`, `--routed-networks`, `--clear-routed-networks`, `--allowed-ips-policy`, `--custom-allowed-ips`, `--clear-custom-allowed-ips`. `--clear-expires` reactivates an expired peer and runs the same activation checks as `peer add` (IP in pool, no active collisions, wire-safe keys). Cannot combine `--expires` and `--clear-expires`.
- **`remove <ID> -i INTERFACE [--hard]`**: Soft-deletes a peer. Use `--hard` for physical deletion. `-i` is **required**.
- **`prune -i INTERFACE`**: Purges expired and soft-deleted peers. Recommended before `interface remove` when inactive rows remain.
- **`history <ID> -i INTERFACE [--limit N] [--offset N]`**: Shows append-only audit events for a peer (`--limit` max: 1000). `-i` is **required**.

## General & Database

- **`wgpl status`**: High-level overview (interface, node, and peer counts; DB path). JSON uses the resource envelope under `data`.
- **`wgpl apply <INTERFACE_NAME_OR_ID>`**: Synchronizes state to the WireGuard kernel via `wg syncconf`. Fails before sync if the database fails consistency checks (invalid active peers, wire-format issues, IPs outside pool).
- **`wgpl validate [INTERFACE_NAME_OR_ID]`**: Dry-run integrity report (active peer collisions, pool fit, DNS, corrupt `expires_at`, invalid wire fields, **routing topology**). Errors exit 1; warnings exit 0. Does not mutate state. JSON is a typed report (`status` + `issues` at the top level).
- **`wgpl db doctor [--repair]`**: Diagnoses schema/consistency issues (extra objects, weakened audit triggers, `deleted_at` normalization). With `--repair`, reinstalls audit triggers and normalizes empty `deleted_at` strings. Detail and when to repair vs restore: [runbook — Database doctor](runbook.md#database-doctor).
- **`wgpl db dump [-o FILE]`**: Binary SQLite backup at `chmod 600`. Prefer dump checksums (or a copied backup file) for integrity checks — opening the live DB may change on-disk file bytes without changing logical content.
- **`wgpl db restore --yes <FILE>`**: Restores from a binary backup. Validates schema contract and all stored wire-format fields; reinstalls audit immutability triggers. Destructive; use `--yes`. Pass `-` for stdin (size-capped).
- **`wgpl --version` / `-V`**: Print the installed package version and exit.

## Operational notes

1. Mutations update the database only — run **`wgpl apply`** (or remote `interface export | ssh … wg syncconf`) to push changes to WireGuard.
2. After **`db restore`**, run **`validate`** then **`apply`** on each interface you manage.
3. Multi-interface hosts: always pass **`-i`** for `peer config`, `peer qr`, `peer show --show-secrets`, and scoped history. Mutations (`peer add` / `update` / `remove` / `prune` / `history`) always require `-i`.
4. Common traps (forgot `apply`, required `-i` on mutations, DB permissions, role/policy field clears): [runbook — Troubleshooting](runbook.md#troubleshooting).
5. `peer update --role endpoint` clears `routed_networks`; non-`custom` `--allowed-ips-policy` clears `custom_allowed_ips`.
6. Pin `WGPL_DB_PATH` / `--db` when mixing `sudo apply` with non-root mutations.
