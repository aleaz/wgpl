# WGPL (WireGuard Peer Lite) — Declarative Hub-and-Spoke VPN Topology CLI

[![CI](https://github.com/aleaz/wgpl/actions/workflows/ci.yml/badge.svg)](https://github.com/aleaz/wgpl/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/downloads/)
![Status: Stable](https://img.shields.io/badge/Status-Stable-brightgreen.svg)

**WGPL (WireGuard Peer Lite)** is a disconnected Python CLI for **hub-and-spoke VPN topologies**. You declare routing **intent** in SQLite (the single source of truth); WGPL derives WireGuard `AllowedIPs`, allocates IPv4 addresses, tracks peer lifecycle and audit, and applies hub changes with **zero downtime** (`wg syncconf`). You bring your own OS interface (BYOI).

**Compatibility (1.0.x):** The `1.0.x` line follows [Semantic Versioning](https://semver.org/). Patch and minor releases in `1.0.x` will not break existing CLI commands, flags, or public `--json` field names. Breaking CLI or JSON changes require a new major version (`2.0.0`).

**Start here:** [Quick Start](#quick-start) · [Routing intent](#routing-intent) · [Documentation map](#documentation-map)

**Why it exists:** Hand-editing `wg0.conf` means picking `AllowedIPs` and free IPs by hand, restarting the interface to add a peer, and keeping no durable access history. WGPL stores topology intent in the database, derives hub and client `AllowedIPs` on validate/apply/export (never stored), and leaves the kernel unchanged until you run `apply` or remote `syncconf`.

## What WGPL is / is not

| WGPL **is** | WGPL **is not** |
| --- | --- |
| Declarative hub-and-spoke IPv4 topology manager | A network daemon or control plane |
| Routing intent engine + WireGuard config generator | Full-mesh overlay (use Tailscale / Netmaker) |
| Disconnected CLI; SQLite SSOT | A kernel routing or `iptables` manager |
| Peer lifecycle, IPAM, append-only audit | IPv6 support (IPv4 pools and peers only) |
| BYOI: you create the OS `wg0` (or equivalent) | Direct site-to-site P2P **without** a hub |

Architecture and module layers: [DESIGN.md](DESIGN.md).

## Table of Contents

- [What WGPL is / is not](#what-wgpl-is--is-not)
- [Domain model](#domain-model)
- [How it works](#how-it-works)
- [Compared to wg-quick and overlays](#compared-to-wg-quick-and-overlays)
- [When to use something else](#when-to-use-something-else)
- [Quick Start](#quick-start)
- [Routing intent](#routing-intent)
- [Features](#features)
- [Operations and audit](#operations-and-audit)
- [Deployment patterns (BYOI)](#deployment-patterns-byoi)
- [Client provisioning](#client-provisioning)
- [Integrations](#integrations)
- [Configuration](#configuration)
- [Documentation map](#documentation-map)
- [Contributing](#contributing)

## Domain model

WGPL models a **declarative hub-and-spoke VPN topology**, not WireGuard text files. WireGuard (`[Interface]`, `[Peer]`, `AllowedIPs`) is an **export format** produced at apply/export time.

```mermaid
flowchart TB
  subgraph identity [Identity]
    Node[Node — device name and desc]
  end
  subgraph attachment [Per-hub attachment]
    Peer[Peer — keys IP role policy lifecycle]
  end
  subgraph hub [VPN domain]
    Iface[Interface — pool endpoint hub routes]
  end
  Node -->|"node_id"| Peer
  Peer -->|"interface_id"| Iface
```

| Concept | Meaning |
| --- | --- |
| **VPN domain** | One `interfaces` row — a hub-and-spoke topology (pool, hub endpoint, optional hub-local routes, all remote attachments) |
| **WGPL interface** | Hub record in the DB — not necessarily the same as the OS netdev unless you named it that way (BYOI) |
| **Node** | Global **device identity** (unique `name`, optional `desc`); managed with `wgpl node` |
| **Peer** | A node's **attachment** to one interface: keys, tunnel IP, routing intent, lifecycle. Display name comes from the node |
| **Routing intent** | `role`, `routed_networks`, `allowed_ips_policy`, `custom_allowed_ips`, `interface.routed_networks` — **persisted** |
| **Hub / Client AllowedIPs** | **Derived** at export by `routing.py` — **never** stored |

**Identity vs attachment.** The node is *who* the device is. The peer is *how* that device participates on a given hub. One node may attach to several interfaces (one peer row each). A node may attach to a given interface **at most once** while active.

Rename a device with `wgpl node update` — `peer update` has no `--name`.

See [DESIGN.md — Domain model](DESIGN.md#domain-model) and [docs/routing.md — Glossary](docs/routing.md#glossary). Next: how intent becomes WireGuard text.

## How it works

Every export path runs an **emit gate** before output:

```mermaid
flowchart LR
  IntentDB[(Intent in SQLite)]
  RoutingPy["routing.py — derive AllowedIPs"]
  IntegrityPy["integrity.py — validate invariants"]
  WireformatPy["wireformat.py — emit + shared validation/cascade"]
  ApplyPaths["apply / interface export / peer config"]

  IntentDB --> RoutingPy --> IntegrityPy --> WireformatPy --> ApplyPaths
```

| Stage | Module | Responsibility |
| --- | --- | --- |
| Derive | `routing.py` | Single source of hub/client `AllowedIPs` (pure functions, no I/O) |
| Validate | `integrity.py` + `consistency.py` | Wire-safe fields, activation gates, topology checks (`wgpl validate`) |
| Emit | `wireformat.py` | Serialize precomputed CIDRs to `.conf`; normalize AllowedIPs; cascade DNS/MTU/keepalive — **must not** derive routes |
| Orchestrate | `core.py` | Mutations, emit gates, IPAM, audit |

- **Mutations** (`peer add`, `peer update`, `interface update`, `node update`, …) write the database inside transactions. They do **not** touch WireGuard.
- **Apply / export** reads intent, derives routes, validates, then emits text for `wg syncconf`, client `.conf`, QR, or JSON.
- **`wgpl apply`** fails closed if the database fails consistency checks (before `wg syncconf`).

Topology validation: errors exit **1**; warnings exit **0** (review before production either way).

## Compared to wg-quick and overlays

### vs `wg-quick` (manual config files)

| Feature | `wg-quick` (manual) | `wgpl` |
| --- | --- | --- |
| **Peer storage** | Text files (`.conf`) | Relational SQLite database |
| **IP allocation** | Manual (collision risk) | Automatic CIDR IPAM |
| **Routing / AllowedIPs** | Manual per peer in `.conf` | Declared intent; **derived** at export |
| **Applying changes** | Restarts interface (drops connections) | Zero-downtime hot-reload (`wg syncconf`) |
| **Audit & history** | None | Append-only log (SQLite triggers) |
| **Expiration** | Manual cleanup | Built-in TTL (`--expires 24h`) |
| **Topology verification** | Manual | `wgpl validate` + `peer explain` + [routing matrix](docs/routing_matrix.md) |

### vs managed overlays (Tailscale, Netmaker, …)

WGPL is a **local, auditable intent store** with deterministic derivation — not a coordinated mesh control plane. You keep full control of keys, backups, and hub relay; you operate `apply` and OS forwarding yourself. Scope boundaries: [When to use something else](#when-to-use-something-else).

## When to use something else

- **Full-mesh or managed overlay** — Tailscale, Netmaker, or similar (WGPL targets one hub per VPN domain, not P2P mesh).
- **Direct site-to-site without a hub** — **Out of scope.** A symmetric tunnel between two site gateways with no concentrator is not modeled. Configure WireGuard manually, or use `peer config --allowed-ips` for a one-off export override.
- **Site-to-site via a central hub** — **In scope.** Two `subnet_router` peers; LAN↔LAN through the concentrator. See [Routing intent](#routing-intent) and [docs/routing.md — Site-to-site](docs/routing.md#site-to-site-via-hub-vs-direct).

## Quick Start

### 1. Install

**Recommended: Python / uv** (Python 3.12+)

```bash
uv tool install wgpl
# or: pip install wgpl
```

**Experimental: standalone Linux binary**

Unsigned release artifact for air-gapped routers. Prefer `uv`/`pip` when possible.
Verify the checksum from the GitHub Release (`SHA256SUMS`) before running.

```bash
curl -sL https://github.com/aleaz/wgpl/releases/latest/download/wgpl-linux-amd64 \
  -o /usr/local/bin/wgpl
# Verify SHA-256 against SHA256SUMS from the same release, then:
chmod +x /usr/local/bin/wgpl
```

**Prerequisite (BYOI):** Create the hub WireGuard interface with `wg-quick` (e.g. `wg0`) before `wgpl apply` can sync peers to the kernel.

### 2. Register a hub and attach a device

Pin a database path so `sudo apply` and non-root mutations share the same SSOT:

```bash
export WGPL_DB_PATH="$HOME/.wgpl.db"
# or pass --db "$HOME/.wgpl.db" on every command
```

A **WGPL interface** row is the hub record for one VPN domain (you may name it `wg0` to match your OS device). The **server endpoint** is where clients connect (`vpn.example.com` below) — not the same as `peer.role = endpoint` (an end-user device).

```bash
# Register the hub: name, server endpoint host, hub public key, address pool
# Add --port N if the hub does not listen on the default 51820
wgpl interface add wg0 vpn.example.com <WG0_PUBKEY> 10.0.0.0/24

# Attach a remote-access device (default policy: vpn_only — client reaches VPN pool only)
# The positional <NAME> find-or-creates the Node; the Peer is the attachment on wg0
wgpl peer add wg0 "Alice_Laptop"

# Explicit device identity first (optional — same result as find-or-create above):
# wgpl node add "Alice_Laptop" --desc "Alice laptop"
# wgpl peer add wg0 --node "Alice_Laptop"
```

> **Client AllowedIPs:** `peer config` / `peer qr` derive from `allowed_ips_policy` (default `vpn_only`). `--allowed-ips` overrides a single export only; for a persistent policy, set `--allowed-ips-policy` on `peer add` or `peer update`.

### 3. Validate, apply, inspect, and distribute

Canonical flow: **validate → apply → explain → distribute**.

```bash
wgpl validate wg0
sudo --preserve-env=WGPL_DB_PATH wgpl apply wg0
# equivalent: sudo wgpl --db "$HOME/.wgpl.db" apply wg0

# Inspect derived routes (hub/client AllowedIPs; LAN↔LAN checklist for subnet routers)
wgpl peer explain <PEER_REF>

wgpl peer qr <PEER_REF>
wgpl peer config <PEER_REF> > alice.conf
chmod 600 alice.conf
```

`<PEER_REF>` is a peer UUID, a unique UUID prefix, or (when unambiguous) the node name shown in `peer list`. If the database has **more than one** WGPL interface, pass `-i` / `--interface` to `peer explain`, `peer config`, `peer qr`, and other secret-bearing commands. See [docs/cli.md](docs/cli.md).

## Routing intent

Building on the [domain model](#domain-model): declare policies and site LANs on interfaces and peers. WGPL derives `AllowedIPs` at export; hub packet relay (`ip_forward`, firewall) stays with the operator — see [LAN↔LAN via hub](#lanlan-via-hub-four-legs).

```mermaid
flowchart TD
  Hub[Hub concentrator]
  Ep1[Peer endpoint]
  Ep2[Peer endpoint]
  Sr[Subnet router]
  LAN[Site LAN]

  Hub --> Ep1
  Hub --> Ep2
  Hub --> Sr
  Sr --> LAN
```

### Terminology (quick reference)

| Term | Meaning |
| --- | --- |
| **Server endpoint** | `interfaces.endpoint` host (and port) — where clients connect |
| **`peer.role = endpoint`** | End-user device (laptop, phone); no `routed_networks` |
| **`peer.role = subnet_router`** | Site gateway advertising LAN CIDRs behind the tunnel |
| **`interface.routed_networks`** | CIDRs behind the hub (split-tunnel internal routes) |
| **`peer.routed_networks`** | CIDRs behind a subnet router |
| **Hub AllowedIPs** | Derived server `[Peer]` block (`apply`, `interface export`, MikroTik `allowed-address`) |
| **Client AllowedIPs** | Derived in `peer config` / `peer qr` from `allowed_ips_policy` |

Industry mapping (Tailscale / Netmaker / WireGuard): [docs/routing.md — Glossary](docs/routing.md#glossary).

### `allowed_ips_policy`

| Value | Client AllowedIPs (summary) |
| --- | --- |
| `vpn_only` (default) | VPN address pool only |
| `split_tunnel` | Pool + `interface.routed_networks` |
| `all_remote_networks` | Split set + other sites' LANs (own LANs excluded on subnet routers) |
| `full_tunnel` | `0.0.0.0/0` |
| `custom` | `peer.custom_allowed_ips` |

Inspect derived routes with `wgpl peer explain <PEER_REF>` or `wgpl --json peer list --interface wg0` (`hub_allowed_ips`, `client_allowed_ips`).

### Operational patterns

Eight hub-and-spoke patterns (detail in [docs/routing.md](docs/routing.md)):

| # | Pattern | role | allowed_ips_policy |
| --- | --- | --- | --- |
| 1 | Remote access, full tunnel | `endpoint` | `full_tunnel` |
| 2 | Remote access, split tunnel | `endpoint` | `split_tunnel` (+ hub `routed_networks`) |
| 3 | VPN peers only | `endpoint` | `vpn_only` |
| 4 | VPN + all remote LANs | `endpoint` | `all_remote_networks` |
| 5 | Site subnet router | `subnet_router` | `all_remote_networks` |
| 6 | Site-to-site via hub | 2× `subnet_router` | `all_remote_networks` |
| 7 | Endpoint ↔ endpoint via hub | `endpoint` | `vpn_only` |
| 8 | Manual exception | any | `custom` |

Executable valid/invalid topology spec: [docs/routing_matrix.md](docs/routing_matrix.md).

### LAN↔LAN via hub (four legs)

For site-to-site through a concentrator, four routing legs must be complete (hub config + both client exports). `wgpl peer explain` on a subnet router shows a **LAN↔LAN checklist** with a `complete` flag per remote site.

```mermaid
flowchart LR
  LANA[LAN_A] --> GwA[gateway_A]
  GwA --> Hub[Hub]
  Hub --> GwB[gateway_B]
  GwB --> LANB[LAN_B]
```

**Operator responsibility:** WGPL derives `AllowedIPs` only. Enable hub packet relay (`ip_forward`, firewall `FORWARD`, optional MASQUERADE) yourself. See [docs/runbook.md — Hub routing relay](docs/runbook.md#hub-routing-relay).

### Examples

Examples below match patterns **2**, **1**, and **5**:

```bash
# Split tunnel — hub advertises internal nets; clients pull them via policy
wgpl interface add wg0 vpn.example.com <WG0_PUBKEY> 10.0.0.0/24 \
  --routed-networks 10.10.0.0/16,10.20.0.0/16
wgpl peer add wg0 "Office_User" --allowed-ips-policy split_tunnel

# Remote access — route all traffic through the hub
wgpl peer add wg0 "Road_Warrior" --allowed-ips-policy full_tunnel

# Branch office gateway advertising a LAN (add --keepalive on NAT'd gateways)
wgpl peer add wg0 "Branch_GW" --role subnet_router \
  --routed-networks 192.168.50.0/24 --allowed-ips-policy all_remote_networks \
  --keepalive 25
```

## Features

Capabilities at a glance; day-2 detail in [Operations and audit](#operations-and-audit).

### Multi-server and IPAM

- **Composite identity:** Interface names (e.g. `wg0`) may repeat across servers; WGPL keys hubs by name + server endpoint + port. When names collide, use the numeric **interface ID** from `wgpl interface list`.
- **Global IPAM:** Automatic free IPv4 allocation within each hub's CIDR pool.
- **Idempotent apply:** `wgpl apply` is safe to run repeatedly; only deltas reach the kernel.

### Lifecycle and nodes

- **Device identity:** `wgpl node` manages global records. Attachment is via `peer add` (find-or-create or `--node`) — see [Quick Start](#quick-start) and [Domain model](#domain-model). The same device can attach to several hubs.
- **TTL:** `--expires 48h` for contractors and temporary access (expired peers are excluded from apply/export until pruned).
- **Soft delete:** `peer remove` frees the IP while retaining audit history; `peer prune` hard-deletes inactive peer rows. Node identities persist; `wgpl node prune` removes orphan devices (zero attachments).

### Security

- X25519 key generation in memory (`cryptography`); wire-safe validation in emit gates before export.
- `chmod 600` on database and sensitive outputs; fail-closed `apply` and restore paths.
- Append-only audit (`audit_events`); secrets never stored in audit metadata.
- See [SECURITY.md](SECURITY.md).

### Automation

- **Strict JSON output (`--json`)** for M2M integration (Ansible, Terraform, Bash), including derived `hub_allowed_ips` / `client_allowed_ips` on peer list/show.
- **Hot-reloads:** Declarative synchronization with the Linux kernel using `wg syncconf` (without dropping TCP connections).
- **CI/CD ready:** SQLite WAL mode and exclusive locks help multiple pipelines avoid corrupting state when coordinating writes.

### WireGuard fields

- **Per-peer overrides:** `MTU`, `PersistentKeepalive`, and `DNS` at the WGPL interface (default) or per peer.
- **Wire-safe MTU:** minimum **1280** on mutations and export (or unset).
- **Server endpoints** validated per RFC 1123.

## Operations and audit

After mutations: **validate**, then **apply** (or remote `syncconf`). Details: [docs/runbook.md — Post-mutation checklist](docs/runbook.md#post-mutation-checklist).

### Post-mutation workflow

1. `wgpl validate [INTERFACE]` — pool fit, wire-format checks, routing topology (errors exit 1; warnings exit 0).
2. `sudo wgpl apply INTERFACE` — or `interface export | ssh … wg syncconf` on a remote hub.

### Temporary access (TTL)

```bash
wgpl peer add wg0 "Contractor_Audit" --expires 48h
```

Expired peers are ignored by `apply` and `interface export` until pruned.

### Deletion and garbage collection

```bash
wgpl peer remove wg0 <PEER_REF>          # soft delete — IP freed, audit retained
wgpl peer prune wg0                      # hard-delete inactive peer rows
wgpl peer remove wg0 <PEER_REF> --hard   # immediate physical delete + audit event
wgpl node prune                          # remove orphan device identities
```

### Audit trail

```bash
wgpl interface history wg0
wgpl peer history wg0 <PEER_REF>
wgpl node history <NODE_REF>
```

The `audit_events` table is append-only (SQLite triggers block UPDATE/DELETE). There is no `audit prune` — audit rows are never deleted in-place by design.

### Backups and disaster recovery

```bash
wgpl db dump -o backup.db    # creates a new file; refuses to overwrite an existing path
chmod 600 backup.db
wgpl db restore --yes backup.db   # destructive; validates schema and wire fields
```

Restore fails closed on **error**-severity validation issues; **warnings** do not block restore (a state the CLI can create must be restorable from its own backup). After restore: `wgpl validate`, then `apply` on each managed interface.

### Database diagnostics

```bash
wgpl db doctor          # diagnose schema and audit trigger issues
wgpl db doctor --repair # reinstall triggers and normalize deleted_at
```

### Wire-safe MTU

```bash
wgpl validate
wgpl interface list --json | jq '.[] | select(.mtu != null and .mtu < 1280)'
wgpl peer list --json | jq '.[] | select(.mtu != null and .mtu < 1280)'
```

Fix low MTU values with `interface update --mtu 1280`, `peer update --mtu 1280`, or `--clear-mtu`. Full checklist: [docs/runbook.md — Wire-safe MTU](docs/runbook.md#wire-safe-mtu).

### Compliance notes

With proper OS-level access controls, centralized lifecycle and audit records can simplify SOC2 and ISO27001 access reviews.

| Goal | Tool |
| --- | --- |
| Archive history for compliance | `wgpl db dump -o archive-YYYY-MM.db`; store off-host with `chmod 600` |
| Remove inactive peer rows (not audit) | `wgpl peer prune <interface>` |
| Query past events | `peer history` / `interface history` / `node history` |

Related: [composite interface identity](#multi-server-and-ipam) when the same interface name exists on more than one hub.

## Deployment patterns (BYOI)

Run WGPL against hubs you already operate. WGPL does not manage `iptables` or system routing — tools that hijack those layers often break Docker, Kubernetes, or corporate firewalls.

```mermaid
graph TD
  DB[(WGPL SQLite SSOT)]
  CLI[wgpl CLI]
  Linux[Linux kernel wg0]
  Remote[Remote servers]
  Router[RouterOS / edge]
  Mobile[iOS / Android]

  DB --> CLI
  CLI -->|Zero-downtime reload| Linux
  CLI -->|SSH / Ansible| Remote
  CLI -->|JSON export| Router
  CLI -->|QR / conf| Mobile
```

### Native Linux server (systemd)

Automate prune and hot-reload on the VPN gateway:

```ini
[Unit]
Description=WGPL Sync and Prune
After=wg-quick@wg0.service

[Service]
Type=oneshot
ExecStartPre=/usr/local/bin/wgpl peer prune wg0
ExecStart=/usr/bin/sudo /usr/local/bin/wgpl apply wg0
```

Trigger with a `.timer` (e.g. every 5 minutes). See [docs/runbook.md](docs/runbook.md).

### Remote Linux servers (CI/CD)

```bash
wgpl validate wg0
wgpl interface export wg0 > hub-peers.conf
cat hub-peers.conf | ssh root@hub-host "wg syncconf wg0 /dev/stdin"
```

### MikroTik (RouterOS v7)

```bash
wgpl --json peer list --interface wg0 | jq -r '.[] | "/interface wireguard peers add interface=wg0 public-key=\"\(.public_key)\" allowed-address=\"\(.hub_allowed_ips | join(","))\""' > mikrotik_sync.rsc
```

Import `mikrotik_sync.rsc` on the router.

<a id="deployment-patterns-docker"></a>

### Docker

```bash
alias wgpl='docker run --rm -it -v $(pwd)/wgpl-data:/data ghcr.io/aleaz/wgpl'
wgpl interface list
```

To apply on the **host** kernel:

```bash
docker run --rm -v $(pwd)/wgpl-data:/data \
  --cap-add NET_ADMIN --network host \
  ghcr.io/aleaz/wgpl apply wg0
```

## Client provisioning

Export on the **management host**, then install on the end-user device. For non-trivial routing, run `wgpl peer explain` before distributing configs.

### Mobile (iOS / Android)

```bash
wgpl peer qr <PEER_REF>
wgpl peer qr <PEER_REF> -o alice-phone.png
```

### Desktop (Windows / macOS)

```bash
wgpl peer config <PEER_REF> > alice.conf
chmod 600 alice.conf
```

Import `alice.conf` into the official WireGuard desktop app.

### Linux (end-user machine)

On the **client laptop or workstation** (not the VPN hub), install the exported config. The interface name is a local choice (`wg-wgpl`, `wg0`, etc.):

```bash
# Run on the end-user machine after copying alice.conf
sudo cp alice.conf /etc/wireguard/wg-wgpl.conf
sudo chmod 600 /etc/wireguard/wg-wgpl.conf
sudo systemctl enable --now wg-quick@wg-wgpl
```

## Integrations

Copy-paste starting points in `examples/`:

- **[Ansible Playbook](examples/ansible-deployment.yml):** Multi-server zero-downtime updates from a control node.
- **[Terraform & Cloud Firewalls](examples/terraform-external-data.tf):** Whitelist peer IPs in AWS Security Groups via Terraform `external` data.
- **[GitHub Actions (GitOps)](examples/github-actions-gitops.yml):** Deploy VPN state from CI/CD.
- **[FastAPI Self-Service Portal](examples/fastapi-self-service.py):** Illustrative API wrapper for QR-based onboarding (requires `WGPL_PORTAL_API_KEY`).

## Configuration

| Variable | Description | Default |
| --- | --- | --- |
| `WGPL_DB_PATH` | Path to the SQLite database | `~/.wgpl.db` |
| `WGPL_WG_BIN` | Path to `wg` for `apply` / `syncconf` (**ignored when UID 0**; defaults to `/usr/bin/wg`) | `wg` (PATH) |

`wireguard-tools` (`wg`) is required only for `wgpl apply` on the same machine.

Docker image: `ghcr.io/aleaz/wgpl` — see [Deployment patterns — Docker](#deployment-patterns-docker).

Run `wgpl --help` or see [docs/cli.md](docs/cli.md) for the full command reference.

## Documentation map

| Document | Contents |
| --- | --- |
| [DESIGN.md](DESIGN.md) | Domain model, layered architecture, security boundaries |
| [docs/routing.md](docs/routing.md) | Routing model, patterns, scope, invariants |
| [docs/routing_matrix.md](docs/routing_matrix.md) | Executable topology spec (valid / invalid) |
| [docs/runbook.md](docs/runbook.md) | Production procedures (validate, apply, hub relay, backup) |
| [docs/cli.md](docs/cli.md) | Full CLI reference |
| [SECURITY.md](SECURITY.md) | Threat model and security policies |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development workflow and commit conventions |

## Contributing

```bash
git clone https://github.com/aleaz/wgpl.git
cd wgpl
uv sync --dev
uv tool run pre-commit install
uv run ruff check src/ tests/
uv run mypy src/ tests/
uv run pytest
```

Please read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request.

## Author

- **Alejandro Azario** — [GitHub](https://github.com/aleaz)

## License

MIT
