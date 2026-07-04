# WireGuard Peer Lite (WGPL)

[![CI](https://github.com/aleaz/wgpl/actions/workflows/ci.yml/badge.svg)](https://github.com/aleaz/wgpl/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)

**WGPL** is a lightweight, Enterprise-Grade Control Plane for WireGuard. It acts as a Single Source of Truth (SSOT) to manage the lifecycle of WireGuard peers across multiple servers, decoupling the configuration management from the underlying network hardware.

## Features

### Multi-Server Ready

Manage an unlimited number of WireGuard servers from a single SQLite database.

- **Composite Identity:** Interface names (e.g. `wg0`) can be repeated across different servers. WGPL identifies tunnels by their composite key (`Name + Endpoint + Port`).
- **Global IPAM:** Automatic allocation of free IPv4 addresses within a CIDR block per server.

### Advanced Networking

Bring enterprise networking features to your tunnels automatically:

- **Per-Peer Granularity:** Customize `MTU`, `PersistentKeepalive`, and `DNS` at the interface level (default) or override them per peer.
- **FQDN & IP Support:** Endpoints are proactively validated via RFC 1123, ensuring your generated configs are always resolvable by WireGuard.

### Security & Cryptography

- **Native Generation:** Public/private key generation (X25519) in native RAM using Python's `cryptography` (no `wg genkey` subprocesses).
- **Hardened Validation:** 32-byte Base64 key validation prevents kernel panics during configuration synchronization.
- **Secure by Default:** Automatic strict permissions (`chmod 600`) on databases and exported QR codes.

### Automation and State

- **Strict JSON Output (`--json`)** for M2M integration (Ansible, Terraform, Bash).
- **Hot-Reloads:** Declarative synchronization with the Linux kernel using `wg syncconf` (without dropping TCP connections).

---

## Decoupled Architectures (BYOI)

WGPL follows a "Bring Your Own Interface" (BYOI) philosophy. It doesn't configure your kernel interfaces (`ip link add wg0`); instead, it manages the *Peers* (the clients) that connect to those interfaces.

### 1. Native Linux Server (Zero-Downtime Systemd)

Run WGPL directly on the VPN Gateway (Debian/Ubuntu). You can automate garbage collection and peer synchronization using Systemd without ever bringing the interface down.

```bash
# 1. Register the local interface
wgpl interface add wg0 vpn.example.com <WG0_PUBKEY> 10.0.0.0/24

# 2. Add a new employee
wgpl peer add wg0 "New_Employee"
```

**Systemd Automation Example:**
Create a systemd service (`/etc/systemd/system/wgpl-sync.service`) to prune expired peers and hot-reload the kernel:

```ini
[Unit]
Description=WGPL Sync & Prune
After=wg-quick@wg0.service

[Service]
Type=oneshot
ExecStartPre=/usr/local/bin/wgpl peer prune wg0
ExecStart=/usr/local/bin/wgpl apply wg0
```

Trigger it with a `.timer` every 5 minutes to fully automate your VPN lifecycle.

### 2. Remote Linux Servers (CI/CD Pipeline)

Run WGPL in your GitHub Actions, GitLab CI, or an Ansible control node to provision multiple servers remotely via SSH.

```bash
# 1. Export the declarative configuration for Server A
wgpl interface export server-a-wg0 > server-a.conf

# 2. Pipe it securely over SSH to apply changes seamlessly
cat server-a.conf | ssh root@server-a "wg syncconf wg0 /dev/stdin"
```

### 3. MikroTik (RouterOS v7) Appliances

Bring modern IPAM, TTL, and Audit capabilities to hardware routers that lack these features natively.

```bash
# 1. Add the peer
wgpl peer add mk-vpn "Smartphone"

# 2. Extract configuration via JSON and generate an .rsc script
wgpl --json peer list | jq -r '.[] | "/interface wireguard peers add interface=wg0 public-key=\"\(.public_key)\" allowed-address=\"\(.ip_address)/32\""' > mikrotik_sync.rsc
```

Then import `mikrotik_sync.rsc` into your router.

---

## Client Provisioning (End-User Devices)

Delivering the VPN to the end-user is as simple as running a command. WGPL provides formats ready for every platform.

### Mobile (iOS / Android)

Users running the official WireGuard App can scan a QR code.

```bash
# Show ASCII QR Code directly in the terminal
wgpl peer qr <PEER_ID>

# Or export it to send securely to remote users
wgpl peer qr <PEER_ID> -o ios_tunnel.png
```

### Desktop (Windows / macOS)

Export the standard `.conf` file to be imported into the official WireGuard desktop client.

```bash
wgpl peer config <PEER_ID> > my_laptop.conf
```

### Linux Clients

For users on Linux, export the config directly to `/etc/wireguard/` and enable the service.

```bash
wgpl peer config <PEER_ID> | sudo tee /etc/wireguard/wg0.conf > /dev/null
sudo systemctl enable --now wg-quick@wg0
```

---

## Enterprise Lifecycle & Audit (SRE)

WGPL is built for operations teams that need traceability and access control.

### Temporary Access (TTL)

Create peers that automatically expire. Ideal for contractors or temporary access.

```bash
wgpl peer add wg0 "Contractor_Audit" --expires 48h
```

*(Expired peers are ignored by `wgpl apply` and `wgpl interface export`)*

### Garbage Collection & Deletion

WGPL uses **Soft Deletes** by default to maintain historical records while freeing up the IP address.

```bash
# Soft delete a peer (IP is freed, history remains)
wgpl peer remove wg0 <PEER_ID>

# Permanently purge expired or soft-deleted peers
wgpl peer prune wg0

# Hard delete (Physical DB wipe + Audit event)
wgpl peer remove wg0 <PEER_ID> --hard
```

### Immutable Audit Trail

WGPL uses SQLite Triggers to maintain an append-only audit log. Fulfill SOC2 / ISO27001 requirements out-of-the-box.

```bash
# View the lifecycle history of an interface
wgpl interface history wg0

# Audit every IP change, DNS override, or Expiration of a specific peer
wgpl peer history wg0 <PEER_ID>
```

---

## Quick Start & Installation

WGPL requires **Python 3.12+**.

### Recommended Installation (via `uv`)

```bash
uv tool install wgpl
wgpl --help
```

### Configuration

WGPL requires zero configuration, but respects the following environment variables:

| Variable                  | Description                                                          | Default      |
|---------------------------|----------------------------------------------------------------------|--------------|
| `WGPL_DB_PATH`            | Path to the local SQLite database used to store cryptographic state. | `~/.wgpl.db` |
| `WGPL_WG_BIN`             | Path to the `wg` binary used by `apply` and `syncconf`.              | `wg` (PATH)  |

*Note: `wireguard-tools` (`wg`) is **only** necessary if you want to run `wgpl apply` on the same machine.*

---

## CLI Reference

All commands support the global `--json` or `-j` parameter (e.g., `wgpl -j peer list`) to produce machine-parseable outputs.

### Interface Management (`wgpl interface`)

- **`add <NAME> <ENDPOINT> <PUBKEY> <POOL_IP> [options]`**: Registers a new network. Accepts `--port`, `--dns`, `--mtu`, `--keepalive`, and `--desc`.
- **`list`**: Shows interfaces and their unique IDs.
- **`update <NAME_OR_ID> [options]`**: Modifies advanced network parameters (e.g., `--mtu 1360` or `--clear-mtu`).
- **`export <NAME_OR_ID>`**: Prints standard `[Peer]` blocks compatible with the WireGuard server.
- **`remove <NAME_OR_ID> [--force]`**: Deletes the interface (requires `--force` if peers exist).
- **`history <NAME_OR_ID>`**: Shows append-only audit events.

### Peer Management (`wgpl peer`)

- **`add <INTERFACE_NAME_OR_ID> <NAME> [options]`**: Creates a new client. Accepts `--ip`, `--dns`, `--expires`, `--mtu`, `--keepalive`, and `--desc`.
- **`list [--all] [--expired]`**: Shows active/all clients.
- **`config <ID>`**: Shows the client configuration ready for consumption.
- **`qr <ID> [-o <PNG_PATH>]`**: Generates the QR code.
- **`update <INTERFACE_NAME_OR_ID> <ID> [options]`**: Modifies properties or uses `--clear-*` to inherit from the interface.
- **`remove <INTERFACE_NAME_OR_ID> <ID> [--hard]`**: Soft-deletes a peer. Use `--hard` for physical deletion.
- **`prune <INTERFACE_NAME_OR_ID>`**: Purges expired and soft-deleted peers.
- **`history <INTERFACE_NAME_OR_ID> <ID>`**: Shows append-only audit events for a peer.

### General & Database

- **`wgpl apply <INTERFACE_NAME_OR_ID>`**: Synchronizes the state to the WireGuard kernel seamlessly using `wg syncconf`.
- **`wgpl validate [INTERFACE_NAME_OR_ID]`**: Verifies database integrity.
- **`wgpl db dump`**: Extracts the entire DB as an SQL script.
- **`wgpl db restore <FILE>`**: Safely restores the database from an SQL script.

## Contributing

Contributions are always welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) to understand the architecture, version control strategy, and commit conventions.

## Author

- **Alejandro Azario** - [GitHub](https://github.com/aleaz)

## License

MIT
