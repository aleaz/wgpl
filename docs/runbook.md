# WGPL Operations Runbook

Operational procedures for running WGPL in production. Complements
[SECURITY.md](../SECURITY.md) and the [CLI reference](cli.md).

## Upgrading WGPL

When upgrading to a release that enforces wire-safe MTU (minimum **1280**):

1. **Before** replacing the binary or package, list MTU values on live data:

   ```bash
   wgpl interface list --json | jq '.[] | {name, mtu}'
   wgpl peer list --json | jq '.[] | {name, mtu}'
   ```

2. Fix any interface or peer with MTU below 1280 (or null is fine — only
   explicit low values block export/apply):

   ```bash
   wgpl interface update wg0 --mtu 1280
   wgpl peer update wg0 <PEER_ID> --mtu 1280
   # or remove the override:
   wgpl peer update wg0 <PEER_ID> --clear-mtu
   ```

3. Run `wgpl validate` — it must pass before you rely on `apply` or client
   export after the upgrade.

4. Upgrade the tool (`uv tool upgrade wgpl`, package manager, or standalone
   binary), then `wgpl validate` again and `sudo wgpl apply` as usual.

## Post-mutation checklist

Every change that should reach WireGuard requires two steps after the mutation:

1. **Validate** (recommended after bulk changes or restore):

   ```bash
   wgpl validate [INTERFACE]
   ```

2. **Apply** (push active peers to the kernel):

   ```bash
   sudo wgpl apply INTERFACE
   ```

   Remote servers:

   ```bash
   wgpl interface export INTERFACE | ssh root@HOST wg syncconf INTERFACE /dev/stdin
   ```

Mutations (`peer add`, `peer remove`, `peer update`, `peer prune`, `interface update`)
update the SQLite database only. The kernel stays stale until `apply` or remote
`syncconf` runs. This is by design.

## Hub routing relay (v2)

WGPL derives WireGuard `AllowedIPs` for hub-and-spoke topologies (remote access,
subnet routers, LAN↔LAN via hub). See [ROUTING.md](ROUTING.md) for the routing
model and pattern matrix.

**WGPL does not configure the Linux kernel routing table, `ip_forward`, or
firewall rules.** WireGuard cryptokey routing only decides which packets enter
the tunnel. The hub (and each site gateway) must forward packets between
interfaces when traffic should relay — for example LAN A → hub → LAN B.

### When you need hub forwarding

| Goal | WGPL handles | Operator handles on hub |
|------|--------------|-------------------------|
| Remote client → VPN peers only | Client + hub AllowedIPs | Usually nothing beyond `apply` |
| Remote client → hub LAN / internal nets | `interface.routed_networks`, split tunnel | `ip_forward` + FORWARD if hub LAN is a physical interface |
| Site LAN ↔ site LAN via hub | Subnet routers + `all_remote_networks` | `ip_forward` + FORWARD on `wg0` (and often MASQUERADE off the uplink) |
| Full tunnel (all traffic via hub) | `allowed_ips_policy=full_tunnel` | FORWARD + MASQUERADE on hub uplink if clients need Internet |

### End-to-end workflow

1. **Declare intent** in WGPL (interface pool, optional `interface.routed-networks`,
   peers with `--role`, `--routed-networks`, `--allowed-ips-policy` as needed).
2. **Validate** routing topology:

   ```bash
   wgpl validate wg0
   wgpl --json validate wg0 | jq '.issues'
   ```

   Errors block `apply`; warnings (e.g. missing keepalive on a subnet router
   behind NAT) exit 0 but should be reviewed.
3. **Inspect derived AllowedIPs** before distributing configs:

   ```bash
   wgpl peer explain site-a-gw
   wgpl --json peer list | jq '.[] | {name, hub_allowed_ips, client_allowed_ips}'
   ```

   For LAN↔LAN, confirm the four-leg checklist in `peer explain` shows
   `complete: yes` for each remote site pair.
4. **Apply hub config**:

   ```bash
   sudo wgpl apply wg0
   # remote hub:
   wgpl interface export wg0 | ssh root@HUB wg syncconf wg0 /dev/stdin
   ```
5. **Enable forwarding and firewall on the hub** (see checklist below).
6. **Deploy client configs** at each site (`peer config` / `peer qr`) and run
   `wg-quick up` or your RouterOS import. Site gateways also need `ip_forward`
   and LAN routing for their advertised `routed_networks`.

### Hub relay checklist (Linux)

Replace `wg0` and `eth0` with your WireGuard interface and uplink/LAN interface.

**1. IPv4 forwarding (required for any relay)**

```bash
# Immediate
sudo sysctl -w net.ipv4.ip_forward=1

# Persistent (Debian/Ubuntu)
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-wgpl-forward.conf
sudo sysctl --system
```

**2. Allow forwarded traffic on WireGuard (LAN↔LAN and spoke-to-spoke via hub)**

```bash
# Traffic between peers on the same wg interface
sudo iptables -A FORWARD -i wg0 -o wg0 -j ACCEPT
```

**3. Hub LAN access (split tunnel to networks behind the hub)**

If `interface.routed-networks` includes prefixes reachable via `eth0` (or
another NIC):

```bash
sudo iptables -A FORWARD -i wg0 -o eth0 -j ACCEPT
sudo iptables -A FORWARD -i eth0 -o wg0 -m state --state RELATED,ESTABLISHED -j ACCEPT
```

**4. NAT / masquerade (optional — Internet egress through hub)**

Only when remote clients or site LANs should use the hub's public IP for
non-VPN destinations (full tunnel or egress via hub):

```bash
sudo iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE
```

Use `nftables` equivalents if your distro defaults to nft. Persist rules with
your platform's firewall manager (`iptables-persistent`, `firewalld`, etc.) —
WGPL does not install or manage these rules.

**5. Verify**

```bash
sysctl net.ipv4.ip_forward
sudo iptables -L FORWARD -v -n
sudo iptables -t nat -L POSTROUTING -v -n   # if using MASQUERADE
wg show wg0
```

From a remote client or site LAN, ping a tunnel IP and a remote LAN gateway.
Use `tcpdump -i wg0` on the hub if packets arrive but do not leave toward the
target LAN.

### Operational patterns (quick reference)

See [ROUTING.md — Operational patterns](ROUTING.md#operational-patterns) for
the full matrix. Typical WGPL commands:

**Remote access — full tunnel**

```bash
wgpl peer add wg0 "Road_Warrior" --allowed-ips-policy full_tunnel
sudo wgpl apply wg0
# Hub: FORWARD + MASQUERADE on uplink if clients need Internet
```

**Remote access — split tunnel (VPN + hub internal nets)**

```bash
wgpl interface update wg0 --routed-networks "10.50.0.0/16,192.168.100.0/24"
wgpl peer add wg0 "Road_Warrior" --allowed-ips-policy split_tunnel
sudo wgpl apply wg0
# Hub: ip_forward + FORWARD wg0 ↔ interface carrying those prefixes
```

**Site subnet router (LAN behind a gateway)**

```bash
wgpl peer add wg0 "Site_A_GW" \
  --role subnet_router \
  --routed-networks "192.168.10.0/24" \
  --allowed-ips-policy all_remote_networks \
  --keepalive 25
sudo wgpl apply wg0
wgpl peer config Site_A_GW > site-a-wg0.conf
# Site gateway: enable ip_forward; wg-quick up; ensure LAN hosts use the GW
```

**LAN↔LAN via hub (two sites)**

```bash
# Site A and Site B: both subnet_router + all_remote_networks + keepalive
wgpl validate wg0
wgpl peer explain Site_A_GW
wgpl peer explain Site_B_GW
sudo wgpl apply wg0
# Hub: ip_forward + FORWARD -i wg0 -o wg0 (minimum)
```

Subnet routers behind NAT **must** have effective `PersistentKeepalive` (peer
override or interface default). Otherwise the hub cannot maintain return paths
and LAN↔LAN becomes intermittent. `validate` emits
`subnet_router_missing_keepalive` as a warning.

### Routing validation issues

| Code | Severity | Meaning | Action |
|------|----------|---------|--------|
| `overlapping_routed_networks` | error | Two active subnet routers advertise overlapping CIDRs | Fix `routed_networks` on one peer; overlaps make hub routing non-deterministic |
| `routed_networks_overlaps_pool` | error | A routed prefix overlaps the VPN pool | Choose disjoint CIDRs |
| `subnet_router_missing_routed_networks` | error | `role=subnet_router` without LAN CIDRs | Set `--routed-networks` or change role to `endpoint` |
| `subnet_router_missing_keepalive` | warning | Subnet router with no effective keepalive | Set `--keepalive 25` (or interface default) for NAT traversal |
| `expired_subnet_router_routes_dropped` | warning | Expired subnet router no longer advertises LANs | Expected; run `peer prune` to reclaim rows |
| `asymmetric_remote_access` | warning | Subnet router not using `all_remote_networks` while others advertise LANs | Use `all_remote_networks` for bidirectional LAN↔LAN |
| `lan_to_lan_incomplete` | warning | Derived client AllowedIPs missing a remote LAN | Fix policy or topology; confirm with `peer explain` |

### MikroTik / RouterOS hub

On RouterOS v7, map WGPL **hub AllowedIPs** to WireGuard `allowed-address`:

```bash
wgpl --json peer list | jq -r '.[] | "/interface wireguard peers add interface=wg0 public-key=\"\(.public_key)\" allowed-address=\"\(.hub_allowed_ips | join(","))\""' > mikrotik_sync.rsc
```

Import the script on the router. Subnet-router peers need `/32` plus their LAN
prefix in `allowed-address`; endpoints need only `/32`. WGPL JSON includes the
derived list so you do not hard-code `/32` only.

## Automated lifecycle (systemd)

Prune expired peers and hot-reload the kernel on a schedule:

```ini
# /etc/systemd/system/wgpl-sync.service
[Unit]
Description=WGPL Sync and Prune
After=wg-quick@wg0.service

[Service]
Type=oneshot
ExecStartPre=/usr/local/bin/wgpl peer prune wg0
ExecStart=/usr/bin/sudo /usr/local/bin/wgpl apply wg0
```

```ini
# /etc/systemd/system/wgpl-sync.timer
[Unit]
Description=Run WGPL sync every 5 minutes

[Timer]
OnBootSec=2min
OnUnitActiveSec=5min

[Install]
WantedBy=timers.target
```

Enable: `systemctl enable --now wgpl-sync.timer`

## Backup and disaster recovery

### Backup

```bash
wgpl db dump -o /secure/path/wgpl-$(date +%Y%m%d).db
chmod 600 /secure/path/wgpl-*.db
```

- Store backups off-host with the same filesystem permissions as the live DB.
- Never commit `*.db` files to version control.

### Restore

```bash
wgpl db restore --yes /secure/path/wgpl-20250706.db
wgpl validate
sudo wgpl apply wg0
```

Restore is destructive and replaces the live database after validation. WGPL
rejects backups with invalid schema, malformed wire-format fields, or weakened
audit triggers. The swap uses `os.replace` after a final re-validation pass.

### Database doctor

Every CLI command validates the live schema on open. If the database fails
schema contract (extra tables, weakened audit triggers, etc.), commands fail
closed until the issue is resolved:

```bash
wgpl db doctor              # list schema and consistency issues
wgpl db doctor --repair     # reinstall audit triggers; normalize deleted_at=''
```

Use `doctor --repair` only after reviewing the reported issues. For unauthorized
schema objects, restore from a known-good backup instead of ad-hoc SQL edits.

### Export vs apply equivalence

`interface export`, `peer config`, and `apply` all pass through the same emit
gate: `validate` preflight plus `assert_exportable_*` on every field that
reaches WireGuard text output. A tampered row that blocks `apply` also blocks
export — there is no weaker export path.

## Key rotation and exposure

WGPL does not rotate keys via `peer update`. If a private key or PSK may have
been exposed:

1. `wgpl peer remove INTERFACE PEER_ID`
2. `sudo wgpl apply INTERFACE`
3. `wgpl peer add INTERFACE "New_Device_Name"`
4. Distribute the new client config or QR to the user.

Revoke the old config on the client device.

## Audit log archival

`audit_events` is append-only and grows without in-place deletion. Archive
periodically:

```bash
wgpl db dump -o archive-$(date +%Y%m).db
chmod 600 archive-$(date +%Y%m).db
```

Use `peer history` and `interface history` for access reviews. Audit rows store
public keys only; private keys and PSKs are never logged.

## Access review (compliance)

For periodic access reviews:

```bash
wgpl peer list INTERFACE --json
wgpl peer history INTERFACE PEER_ID --limit 100
```

Cross-check active peers against your identity source. Remove stale access with
`peer remove` followed by `apply`.

## Incident response

| Scenario | Action |
|----------|--------|
| Suspected DB compromise | Rotate all peers (remove + re-add), restrict filesystem access, restore from last known-good backup if tampering is confirmed |
| Leaked client config / QR | Remove peer, apply, issue new peer |
| Kernel out of sync | `wgpl validate` then `wgpl apply` |
| Corrupt database | Restore from backup; if none, re-init and re-provision peers |

## Environment and permissions

| Variable | Purpose |
|----------|---------|
| `WGPL_DB_PATH` | Database location (default `~/.wgpl.db`) |
| `WGPL_EXEC_CMD` | Optional audit metadata (sanitized, bounded) |

Ensure the database path is a regular file with mode `600`, owned by the operator.
Symlinks at `WGPL_DB_PATH` are rejected.
