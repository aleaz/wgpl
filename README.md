# WireGuard Peer Lite (WGPL)

[![CI](https://github.com/aleaz/wgpl/actions/workflows/ci.yml/badge.svg)](https://github.com/aleaz/wgpl/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

**WGPL** is a minimalistic and secure command-line tool, exclusively designed to manage the lifecycle of WireGuard peers (clients).

## Quick Start

A minimal working example in under a minute:

```bash
# 1. Register your VPN interface in the local database
wgpl interface add wg0 vpn.example.com <YOUR_SERVER_PUBLIC_KEY> 10.0.0.0/24 --port 51820

# 2. Create a new peer (Generates keys and IPs automatically)
wgpl peer add wg0 "My_Phone"

# 3. Export the peer configuration to a .conf file
wgpl peer config <PEER_ID> > phone.conf

# 4. Or generate a QR code to scan in the mobile app
wgpl peer qr <PEER_ID>

# 5. Finally, apply the changes to the WireGuard server (if running WGPL on the server)
wgpl apply wg0
```

## Features

### Peer and Interface Management

- Creation, update, and deletion of peers and interfaces.
- Automatic allocation of free IP addresses within a CIDR block.
- DNS configuration at the interface level (default) or peer level (override).

### Automation and State

- Strict JSON output (`--json`) for M2M integration (Ansible, Terraform, Bash).
- Single Source of Truth (SSOT) using a secure local SQLite database.
- Declarative synchronization with the kernel using `wg syncconf` (without interruptions).

### Security and Cryptography

- Public/private key generation (X25519) and Preshared Keys in native memory without relying on the `wg` CLI.
- Automatic strict permissions (`chmod 600`) on databases and exported QR codes.
- Proactive validation of network and IP state before modifying the database.

### Database Management

- Logical export (`dump`) of the entire database.
- Secure and immutable restoration (`restore`) with atomic recovery and corruption prevention.

### Client Export

- Complete `.conf` files ready to be consumed.
- Native QR codes in the terminal (ASCII) or exportable as PNG images.

## Deployment Architectures (BYOI)

WGPL follows a "Bring Your Own Interface" (BYOI) philosophy. It acts as a decoupled Control Plane (Single Source of Truth in SQLite), allowing you to manage peers across various topologies without forcing changes to your host's network state.

### 1. Local (Air-Gapped / Offline PKI)

Run WGPL on your local machine (e.g., laptop) to securely generate keys and allocate IPs without private keys ever leaving your device.

```bash
# 1. Register remote server
wgpl interface add wg-remote vpn.example.com <SERVER_PUBKEY> 10.0.0.0/24

# 2. Generate peer & QR code locally
wgpl peer add wg-remote "Laptop CEO"
wgpl peer qr <PEER_ID> -o ceo_qr.png

# 3. Export config to provision the remote server (e.g. via Ansible/SSH)
wgpl interface export wg-remote > wg-remote.conf
```

### 2. Native Linux Server (Zero-Downtime)

Run WGPL directly on the VPN Gateway (Debian/Ubuntu). Use `wgpl apply` to hot-reload peers into the kernel without dropping active connections.

```bash
# 1. Register local interface
wgpl interface add wg0 vpn.example.com <WG0_PUBKEY> 10.0.0.0/24

# 2. Add peer
wgpl peer add wg0 "New Employee"

# 3. Inject configuration directly into the kernel seamlessly
wgpl apply wg0
```

### 3. MikroTik (RouterOS v7) Control Plane

Use WGPL to bring modern IPAM and QR code generation to MikroTik hardware.

```bash
# 1. Register MikroTik interface in WGPL
wgpl interface add mk-vpn router.example.com <MIKROTIK_PUBKEY> 10.0.0.0/24

# 2. Add peer in WGPL
wgpl peer add mk-vpn "Smartphone"

# 3. Generate MikroTik configuration script using JSON and jq
wgpl --json peer list | jq -r '.[] | "/interface wireguard peers add interface=wg0 public-key=\"\(.public_key)\" allowed-address=\"\(.ip_address)/32\""' > mikrotik_sync.rsc
```

Then simply import `mikrotik_sync.rsc` into your router.

## Configuration

WGPL is designed to require zero configuration, but provides robust mechanisms to adjust its behavior.

| Variable/Argument       | Description                                                          | Default      |
|-------------------------|----------------------------------------------------------------------|--------------|
| `WGPL_DB_PATH` / `--db` | Path to the local SQLite database used to store cryptographic state. | `~/.wgpl.db` |
| `WGPL_WG_BIN`           | Path to the `wg` binary used by `apply` and `syncconf`.              | `wg` (PATH)  |

*Note: WGPL will always force `0600` permissions on the database file to protect your private keys.*

Address pools and peer IPs are **IPv4-only** (e.g. `10.0.0.0/24`). Expired peers release their IP for new allocations; run `peer prune` to remove expired or soft-deleted rows from the database.

## Documentation

- [Architecture & Principles](.cursor/rules/wgpl-architecture.mdc)
- [Contributing Guidelines](CONTRIBUTING.md)

### Installation

WGPL requires **Python 3.12+**.

#### Recommended Installation (via `uv`)

```bash
uv tool install wgpl
wgpl --help
```

#### Local Development Execution

```bash
git clone https://github.com/aleaz/wgpl.git
cd wgpl
uv sync
uv run wgpl --help
```

#### Prerequisites (Optional)

The system binary `wg` (`wireguard-tools`) is **only** necessary if you want to run `wgpl apply` on the same machine to synchronize local configurations.

### CLI Reference

All commands support the global `--json` or `-j` parameter **before** the subcommand (e.g., `wgpl -j peer list`) to produce machine-parseable outputs.

#### Interface Management (`wgpl interface`)

- **`add <NAME> <ENDPOINT> <PUBKEY> <POOL_IP> [--port] [--dns]`**: Registers a new WireGuard network.
- **`list`**: Shows current interfaces.
- **`update <NAME> [options]`**: Modifies the endpoint, pool, DNS or port.
- **`export <NAME>`**: Prints `[Peer]` block configurations compatible with the WireGuard server for remote sync.
- **`remove <NAME>`**: Deletes the interface and **all** its peers in cascade.

#### Peer Management (`wgpl peer`)

- **`add <INTERFACE> <NAME> [--ip] [--dns]`**: Creates a new client. Keys are auto-generated.
- **`list`**: Shows all registered clients.
- **`config <ID>`**: Shows the client configuration ready to be used.
- **`qr <ID> [-o <PNG_PATH>]`**: Generates the client's QR code.
- **`update <INTERFACE> <ID> [options]`**: Allows changing the name, forcing a specific IP or changing DNS override.
- **`remove <INTERFACE> <ID>`**: Permanently deletes a peer.

#### General & Database Commands

- **`wgpl apply <INTERFACE>`**: Atomically synchronizes the database state to the WireGuard kernel using `wg syncconf`.
- **`wgpl validate [INTERFACE]`**: Verifies database integrity.
- **`wgpl db dump`**: Extracts the entire DB as an SQL script (outputs to `stdout`).
- **`wgpl db restore <FILE>`**: Safely restores the database from an SQL script.

### Typical Workflows

#### A. Initializing and Managing a Peer

1. Set env: `export WGPL_DB_PATH=/sec/wgpl.db`
2. Create interface: `wgpl interface add wg0 my-company.com pubkey 192.168.10.0/24`
3. Add employee: `wgpl peer add wg0 "Ana_Laptop"`
4. Share access: `wgpl peer qr "Ana_Laptop" -o /tmp/ana_qr.png`

#### B. "Disconnected" Workflow (GitOps / Terraform / Ansible)

```bash
wgpl interface export wg0 | ssh root@my-vpn-server "wg syncconf wg0 /dev/stdin"
```

#### C. Backup and Secure Restoration

```bash
wgpl db dump > backup_2026.sql
chmod 600 backup_2026.sql
wgpl db restore backup_2026.sql
```

### Peer Workflow

1. **Draft / Creation:** User invokes `peer add`. WGPL takes exclusive SQLite locks (WAL), finds the next free IP, generates crypto in RAM and saves it.
2. **Distribution:** User extracts secret material using `peer config` or `peer qr`.
3. **Refinement:** User adjusts DNS overrides or changes the name.
4. **State Sync (Apply):** Administrator runs `wgpl apply wg0`. WGPL uses `wg syncconf` to match the kernel state 100% with the database seamlessly.

### Performance Considerations

- **SQLite Speed (WAL):** Uses `PRAGMA journal_mode=WAL` for concurrent reads/writes without locks.
- **Isolated Cryptography:** Uses Python's native `cryptography` library to avoid invoking costly `wg genkey` subprocesses, saving fork/exec time.
- **Storage Limits:** Scales seamlessly to tens of thousands of peers. Database size stays well under 10MB even in dense scenarios.

### Troubleshooting

- **Error: "wg executable not found in PATH"**: Install `wireguard-tools` (e.g. `apt install wireguard-tools`).
- **Error: "WGPL_DB_PATH no tiene permisos" (Permission Denied)**: Ensure the user running `wgpl` owns the DB file or has appropriate permissions.
- **Error "IP Outside Pool" in `validate`**: You shrunk the interface subnet, but old clients exist outside the new range. Delete them or update their IP explicitly.

## Contributing

Contributions are always welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) to understand module dependencies (e.g., don't mix Typer in `core.py`), version control strategy, and commit conventions.
Briefly: create a branch, develop using `uv`, run local tests, format the code, and open a PR against `main`.

## Author

- **aleaz** - [GitHub](https://github.com/aleaz)

## License

MIT
