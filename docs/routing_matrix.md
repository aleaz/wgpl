# WGPL Routing Specification Matrix

Executable specification for `routing.py`. Each row defines topology intent,
expected derived AllowedIPs, and the pytest that verifies it.

**Default pool:** `10.0.0.0/24` unless noted.

See also: [routing.md](routing.md) (invariants, invalid topologies),
[DESIGN.md — Domain model](../DESIGN.md#domain-model).

---

## Valid cases

### Case 1 — Remote access (`vpn_only`)

| Field | Value |
|-------|-------|
| Topology | Laptop → Hub |
| Peer | `role=endpoint`, `allowed_ips_policy=vpn_only` |
| Hub AllowedIPs | `{tunnel_ip}/32` |
| Client AllowedIPs | `10.0.0.0/24` |
| Test | `tests/test_routing.py::test_resolve_client_vpn_only` |

---

### Case 2 — Full tunnel endpoint

| Field | Value |
|-------|-------|
| Topology | Road warrior → Hub (all traffic via VPN) |
| Peer | `role=endpoint`, `allowed_ips_policy=full_tunnel` |
| Hub AllowedIPs | `{tunnel_ip}/32` |
| Client AllowedIPs | `0.0.0.0/0` |
| Test | `tests/test_routing.py::test_resolve_client_full_tunnel` |

---

### Case 3 — Split tunnel endpoint

| Field | Value |
|-------|-------|
| Topology | Client → Hub → hub-internal nets |
| Interface | `routed_networks=10.50.0.0/16` |
| Peer | `role=endpoint`, `allowed_ips_policy=split_tunnel` |
| Hub AllowedIPs | `{tunnel_ip}/32` |
| Client AllowedIPs | `10.0.0.0/24`, `10.50.0.0/16` |
| Test | `tests/test_routing.py::test_resolve_client_split_tunnel` |

---

### Case 4 — Two subnet routers (LAN↔LAN via hub)

| Field | Value |
|-------|-------|
| Topology | LAN A → Hub ← LAN B |
| Site A | `subnet_router`, `routed_networks=192.168.10.0/24`, `all_remote_networks` |
| Site B | `subnet_router`, `routed_networks=192.168.20.0/24`, `all_remote_networks` |
| Hub Site A AllowedIPs | `{ip_a}/32`, `192.168.10.0/24` |
| Hub Site B AllowedIPs | `{ip_b}/32`, `192.168.20.0/24` |
| Client Site A AllowedIPs | `10.0.0.0/24`, `192.168.20.0/24` (excludes own LAN) |
| Client Site B AllowedIPs | `10.0.0.0/24`, `192.168.10.0/24` (excludes own LAN) |
| Test | `tests/test_routing.py::test_resolve_client_all_remote_excludes_own_lan` |

---

### Case 5 — Subnet router with multiple LANs

| Field | Value |
|-------|-------|
| Topology | Site gateway announcing office + guest + DMZ |
| Peer | `subnet_router`, `routed_networks=192.168.10.0/24,172.16.20.0/24,10.50.0.0/16` |
| Hub AllowedIPs | `{tunnel_ip}/32` + all three LAN CIDRs |
| Other router client | receives all three LANs via `all_remote_networks` |
| Test | `test_resolve_hub_allowed_ips_subnet_router_multiple_lans`, `test_resolve_client_all_remote_includes_multi_lan_from_other_router` |

---

### Case 6 — Three branches

| Field | Value |
|-------|-------|
| Topology | Branch A, B, C → Hub |
| Each branch | `subnet_router`, distinct `/24`, `all_remote_networks` |
| Each router client | pool + the other two LANs (not own) |
| Hub export | each `/32` + own LAN per branch |
| Test | `tests/test_routing.py::test_mixed_topology_endpoints_and_three_subnet_routers` |

---

### Case 7 — Mixed topology (endpoints + routers)

| Field | Value |
|-------|-------|
| Topology | 2× `vpn_only` laptops, 1× `full_tunnel` laptop, 3× subnet routers |
| `vpn_only` endpoints | Client AllowedIPs = pool only (no remote LANs) |
| `full_tunnel` endpoint | Client AllowedIPs = `0.0.0.0/0` |
| Subnet routers | each sees remote LANs, excludes own |
| Test | `tests/test_routing.py::test_mixed_topology_endpoints_and_three_subnet_routers` |

---

### Case 8 — Custom AllowedIPs

| Field | Value |
|-------|-------|
| Topology | Manual exception |
| Peer | `allowed_ips_policy=custom`, `custom_allowed_ips=…` |
| Client AllowedIPs | parsed from `custom_allowed_ips` (derivation bypasses policy table) |
| Hub AllowedIPs | still derived from role (`/32` or `/32` + LANs) |
| CLI override | `peer config --allowed-ips` bypasses derivation for that export only |
| Test | `tests/test_routing.py::test_get_peer_config_override_still_works` |

---

### Case 9 — Endpoint on hub (tunnel only)

| Field | Value |
|-------|-------|
| Peer | `role=endpoint` (default) |
| Hub AllowedIPs | `{tunnel_ip}/32` only |
| Test | `tests/test_routing.py::test_resolve_hub_allowed_ips_endpoint_is_tunnel_only` |

---

### Case 10 — All remote LANs endpoint

| Field | Value |
|-------|-------|
| Peer | `endpoint`, `allowed_ips_policy=all_remote_networks` |
| Client AllowedIPs | pool + `interface.routed_networks` + all active subnet-router LANs |
| Test | covered by operational pattern 4; extend matrix if dedicated test added |

---

## Invalid topologies

Enforcement: **mutation** = rejected at `peer add` / `peer update` / `interface update`;
**validate** = reported by `wgpl validate` (errors block `apply`).

| Invalid scenario | Example | Enforcement | Code / test |
|------------------|---------|-------------|-------------|
| Duplicate routed network (overlap) | A: `192.168.1.0/24`, B: `192.168.1.0/24` | Mutation reject | `integrity.assert_peer_activation` → `tests/test_routing.py::test_assert_peer_activation_rejects_overlapping_routed_networks` |
| Overlapping routed networks | A: `192.168.0.0/23`, B: `192.168.1.0/24` | Mutation reject + validate error | same + `tests/test_validate_topology.py::test_validate_overlapping_routed_networks_error` |
| Routed network overlaps pool | `routed_networks=10.0.0.0/24` on pool `10.0.0.0/24` | Mutation reject + validate error | `integrity.validate_routed_networks_list` |
| Tunnel IP inside routed network | tunnel `10.0.0.5`, routed `10.0.0.0/24` | Mutation reject | `validate_routed_networks_list(tunnel_ip=…)` |
| Default route in routed_networks | `0.0.0.0/0` in hub or peer LANs | Mutation reject | `reject_default_route=True` in `validate_routed_networks_list` |
| Endpoint with routed_networks | `role=endpoint` + LAN CIDRs | Mutation reject (CHECK + integrity) | `tests/test_cli_routing.py::test_cli_peer_add_rejects_endpoint_with_routed_networks` |
| Subnet router without LANs | `role=subnet_router`, `routed_networks` empty | Mutation reject + validate error | `tests/test_validate_topology.py::test_validate_subnet_router_missing_routed_networks` |
| Custom policy without CIDRs | `allowed_ips_policy=custom`, no `custom_allowed_ips` | Mutation reject (CHECK) | schema CHECK constraint |
| Malicious / wire-unsafe CIDR text | newline injection in `routed_networks` | Restore / validate reject | `tests/test_routing.py::test_validate_database_rejects_malicious_routed_networks` |
| Hub LAN exactly duplicates peer LAN | `interface.routed_networks` = `192.168.1.0/24`, peer same | Validate **error** | `consistency` `hub_peer_routed_networks_duplicate` |
| Hub LAN partially overlaps peer LAN | `interface.routed_networks` = `192.168.0.0/16`, peer `192.168.1.0/24` | Validate **warning** | `consistency` `hub_peer_routed_networks_overlap` |
| Routing loop via own LAN | subnet router receives own LAN in client export | Prevented by derivation | `all_remote_networks` excludes own `routed_networks` |

---

## Derivation pipeline (reference)

```
DB intent  →  routing.resolve_*  →  integrity.assert_exportable_*  →  wireformat
```

Only `routing.py` computes which prefixes appear in Hub / Client AllowedIPs.
`wireformat.py` joins and normalizes; it does not choose routes.
