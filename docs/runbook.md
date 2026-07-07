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
audit triggers.

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
