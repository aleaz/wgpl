# WireGuard Peer Lite (WGPL)

[![CI](https://github.com/aleaz/wgpl/actions/workflows/ci.yml/badge.svg)](https://github.com/aleaz/wgpl/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

**WGPL** is a secure, minimalist command-line tool designed exclusively for managing the lifecycle of WireGuard *peers*.

It is designed as a **Disconnected Configuration Compiler**. This means WGPL does not need to run on the VPN server itself. You can install it on your local laptop, manage the cryptographic state offline in a local SQLite database, and export the configuration to pipe it to your remote servers securely.

Unlike full-featured VPN managers, WGPL prioritizes **simplicity, security, and automation**. It does not manage firewall rules, Docker containers, or DNS. Instead, it acts as the Single Source of Truth (SSOT) and uses **declarative state** (`wg syncconf`) to manage your WireGuard configuration atomically and without disruptions.

## Key Features

* **"Lite" & Disconnected Architecture**: No background web servers. Does not require the `wg` binary to be installed to create peers. Can be used in any CI/CD pipeline, sysadmin machine, or directly on the server.
* **Declarative State**: Commands do not modify WireGuard interactively or partially. They register the state in the database (SSOT). This state is then extracted via `export` or explicitly synchronized locally with `apply`.
* **ACID Transactions**: Uses SQLite in WAL mode and exclusive transactions. Supports multiple scripts attempting to create peers simultaneously without IP collisions.
* **Automation First (M2M)**: All commands support the `--json` output format, ideal for integrating with Ansible, Terraform, or Bash scripts.

---

## Requirements

* **Python 3.12+**
* **uv** (Ultrafast Python package manager)
* **wireguard-tools** (Optional: Only required if you intend to use `wgpl apply` to sync configurations on the same machine)

---

## Installation

WGPL is designed to run locally using `uv`.

### 1. Clone the repository

```bash
git clone https://github.com/aleaz/wgpl.git
cd wgpl
```

### 2. Sync the environment

```bash
uv sync
```

### 3. Use the CLI (Development / Scripting)

You can run the commands using `uv run`:

```bash
uv run wgpl --help
```

### 4. Global Installation (Recommended for Production)

If you want to install the tool globally on your system to use the `wgpl` command without the `uv run` prefix, use the `tool install` feature from `uv`:

```bash
uv tool install .
```

Now you can run it directly:

```bash
wgpl --help
```

---

## Quick Start Guide

WGPL's philosophy is: **1) Declare in the database -> 2) Apply to WireGuard**.

### 1. Register an Interface

First, we register the base WireGuard interface (e.g., `wg0`) and assign an IP address pool from which peers will be served.

```bash
wgpl interface add wg0 vpn.example.com <SERVER_PUBLIC_KEY> 10.0.0.0/24 --port 51820
# Optional default DNS for all peers on this interface (embedded in client .conf only):
# wgpl interface add wg0 vpn.example.com <SERVER_PUBLIC_KEY> 10.0.0.0/24 --dns 1.1.1.1
```

*List interfaces:*

```bash
wgpl interface list
```

### 2. Manage Peers

To add a peer, you only need to give it a name. **WGPL will automatically find the next available IP, generate the keypair (Public/Private) in memory using native cryptography, and generate a Preshared Key (PSK).**

```bash
wgpl peer add wg0 "Johns_Phone"
# Optional fixed IP from the pool and per-peer DNS override:
# wgpl peer add wg0 "Server" --ip 10.0.0.50
# wgpl peer add wg0 "Kids" --dns 9.9.9.9
```

WGPL does not run DNS on the host; `--dns` only adds `DNS = ...` to exported **client** configs.

*List all created peers:*

```bash
wgpl peer list
```

When multiple peers exist, `peer list` shows a short Docker-style ID prefix (12 hex
characters). You can use that prefix with `peer config`, `peer qr`, and
`peer remove` as long as it uniquely identifies one peer. `--json` always returns
the full UUID in `id` (and echoes your input ref in `input`).

*Extract the configuration for the client:*

```bash
wgpl peer config <PEER_ID>
# Short prefix from peer list also works, e.g. 55c521ad2d94
# You can customize network boundaries:
# wgpl peer config <PEER_ID> --allowed-ips="10.0.0.0/24" --keepalive=21
```

*Extract a QR code to scan with a mobile device:*

```bash
wgpl peer qr <PEER_ID>
# Short prefix from peer list also works, e.g. 55c521ad2d94
# PNG for mobile scanning (contains private keys; file is chmod 600):
wgpl peer qr <PEER_ID> -o phone.png
```

*Remove a peer:*

```bash
wgpl peer remove wg0 <PEER_ID>
# Short prefix from peer list also works, e.g.:
wgpl peer remove wg0 55c521ad2d94
```

*Update an interface or peer (without rotating keys):*

```bash
wgpl interface update wg0 --endpoint vpn2.example.com
wgpl interface update wg0 --dns 1.1.1.1
wgpl interface update wg0 --clear-dns
wgpl interface update wg0 --address-pool 10.0.0.0/23   # rejected if peers fall outside

wgpl peer update wg0 <PEER_ID> --name "Work Laptop"
wgpl peer update wg0 <PEER_ID> --ip 10.0.0.50
wgpl peer update wg0 <PEER_ID> --clear-dns

wgpl validate              # check entire database
wgpl validate wg0          # check one interface
```

After changes that affect client configs or server peer list, WGPL prints
operational hints on stderr (e.g. re-export client `.conf`/QR, run `apply`).

### 3. Sync with WireGuard (Apply or Export)

Up to this point, we have safely saved the configuration in WGPL's local database. To apply it to the actual WireGuard kernel, you have two options depending on where WGPL is installed:

#### Option A: Remote Server (Disconnected Workflow)

If you are running WGPL on your personal laptop or a CI/CD runner, extract the declarative config and pipe it directly to your remote VPN server via SSH:

```bash
wgpl interface export wg0 | ssh root@my-vpn-server "wg syncconf wg0 /dev/stdin"
```

#### Option B: Local Server (Direct Workflow)

If WGPL is installed directly on the VPN server, you can use the built-in `apply` command to hot-reload the configuration:

```bash
wgpl apply wg0
```

> **Note:** If the `wg0` interface does not exist in the operating system, WireGuard will throw an error. WGPL does not manage the network interfaces (e.g. `wg-quick up`), only the internal state of the peers.

---

## Automation and DevOps (M2M Mode)

For Bash or Ansible scripts, you can pass the global `--json` (or `-j`) flag to any command. This will disable Rich text output and print exclusively pure JSON to `stdout`. All error logs are strictly sent to `stderr`.

**Flag position:** `--json` is a global option and must appear **before** the subcommand:

```bash
wgpl --json peer list      # correct — JSON array on stdout
wgpl peer list --json      # wrong — flag is ignored (Typer does not propagate it)
```

| Command | JSON shape (stdout) |
|---|---|
| `interface add` | `{name, endpoint, port, public_key, address_pool, dns?}` |
| `interface remove` | `{status, interface}` |
| `interface list` | `[{...interface rows...}]` |
| `interface export` | `{config: "<wg server peers>"}` |
| `interface update` | `{name, endpoint, port, public_key, address_pool, dns?, hints}` |
| `peer add` | `{id, name, ip_address, public_key, dns?}` |
| `peer remove` | `{status, id, input}` — `id` is canonical UUID; `input` is the ref you passed |
| `peer update` | `{id, name, ip_address, dns, dns_override, hints}` |
| `peer list` | `[{id, interface, name, ip_address, public_key, created_at, dns, dns_override}]` — `dns` is effective; `dns_override` is peer-only |
| `peer config` | `{config: "<full .conf>"}` — includes `PrivateKey` (intentional for M2M provisioning) |
| `peer qr` | `{qr: "<ascii>"}` — encodes full client config |
| `peer qr -o` | `{status, path, peer_id}` |
| `apply` | `{status, action, interface}` |
| `validate` | `{status, issues}` — exit 1 if `status` is `error` |

```bash
# Example: Extract the IP of the new peer in bash using jq
NEW_IP=$(wgpl --json peer add wg0 "Backup_Server" | jq -r '.ip_address')
echo "The Backup server will use IP: $NEW_IP"

# Sync
wgpl apply wg0
```

### Database Location

By default, WGPL creates a secure `wgpl.db` file in the user's home directory (`~/.wgpl.db`). You can modify this location using the `WGPL_DB_PATH` environment variable or the global `--db` flag.

```bash
WGPL_DB_PATH=/etc/wireguard/wgpl.sqlite3 wgpl interface list
# Equivalent to:
wgpl --db /etc/wireguard/wgpl.sqlite3 interface list
```

*(Note: WGPL strictly applies `chmod 600` permissions on every database connection to protect cryptographic material, regardless of where you store it).*

---

## CRUD notes

WGPL supports **create, read, update, and delete** for interfaces and peers.
Updates do not auto-sync to WireGuard — run `apply` or `export` when operational
hints say so (printed on stderr in human mode, or in the `hints` JSON field).

Changing `--address-pool` is rejected if any existing peer IP falls outside the
new CIDR. Planned for a later release: `peer rotate-keys`, `interface rename`,
`peer move`.
