# RFC-0001 Projection Engine — Implementation Design

- **Status:** Implementation-ready design
- **Parent RFC:** [RFC-0001: Projection Engine](0001-projection-engine.md)
- **Target Version:** 1.1.0
- **Scope:** Internal architecture and incremental migration only

---

# 1. Purpose

This document defines the complete implementation design for RFC-0001. It
translates the approved architecture into code organization, internal
interfaces, immutable data contracts, dependency rules, migration stages, and
tests.

This document is intentionally prescriptive. An implementation that follows it
must not require additional architectural decisions.

This document does not:

- add a new user-facing command or option
- create a public projection API or SDK
- add plugins, discovery, capabilities, or dynamic registration
- add artifact metadata, streaming, or binary artifacts
- change the database schema or `PRAGMA user_version`
- change WireGuard output bytes or public error behavior
- move lifecycle, routing, validation, or authorization into projections

This document refines but never overrides the parent RFC. If the two documents
conflict, implementation stops until both specifications are reconciled. The
existing public behavior is the compatibility baseline used to resolve such a
conflict; an implementer must not choose one document locally.

---

# 2. Architectural Outcome

The implementation introduces one internal application output boundary:

```text
CLI
 │
Core public facade
 │
 ├── reference and secret-access authorization
 ├── consistency and exportability gates
 ├── lifecycle filtering
 ├── routing and effective-value derivation
 └── immutable target snapshot assembly
       │
       ▼
Projection composition
       │
       ▼
Projection Engine
       │
       ▼
WireGuard projection
       │
       ▼
unchanged wireformat.py
       │
       ▼
str artifact
```

Core remains the public application facade. The Projection Engine and all
projection package symbols remain internal.

The engine does not read the database, authorize access, derive values, or
format WireGuard syntax. It selects a statically configured projection,
invokes the target-specific render method, and applies the projection error
boundary.

The WireGuard projection does not receive domain objects or persistence rows.
It receives immutable values that have already passed the current emit gate.

---

# 3. Existing Contracts to Preserve

## 3.1 Server artifact

The current server artifact is a `wg syncconf` input fragment, not a complete
interface provisioning file.

Its byte contract is:

1. Optional `MTU = ...` followed by one blank line.
2. Active peer stanzas in the order returned by
   `db.list_peers(interface_id)`.
3. Each stanza contains:
   - `[Peer]`
   - `PublicKey`
   - optional `PresharedKey`
   - normalized `AllowedIPs`
   - one terminating blank line
4. A non-empty artifact ends with one newline.
5. An interface with no MTU and no active peers produces `""`.

It does not contain:

- `[Interface]`
- an interface private key
- `ListenPort`
- the interface public key
- peer private keys
- DNS
- endpoint
- client routing policy

The current peer order is SQLite textual ordering by `p.ip_address`. Version
1.1 must preserve that order exactly, including cases such as `10.0.0.10`
sorting before `10.0.0.2`.

`get_interface_config()` returns this artifact. `sync_interface()` passes the
same artifact to `wireguard.syncconf()`.

## 3.2 Client artifact

The current client artifact has this exact order:

1. `[Interface]`
2. `PrivateKey`
3. `Address`
4. optional effective `DNS`
5. optional effective `MTU`
6. one blank line
7. `[Peer]`
8. server `PublicKey`
9. optional `PresharedKey`
10. `Endpoint`
11. normalized `AllowedIPs`
12. optional effective `PersistentKeepalive`
13. one terminal newline

Effective DNS, MTU, and keepalive are resolved with peer override first,
interface default second, and omission last.

`get_peer_config()` returns this artifact. ASCII QR and PNG QR generation pass
this exact string to the QR encoder. The JSON config payload includes this
string, the same resolved AllowedIPs, and whether AllowedIPs were derived or
overridden.

## 3.3 Emit gate

Snapshot assembly must preserve the target-specific fail-closed sequences.

Server:

```text
database consistency preflight
    ↓
interface resolution and load
    ↓
interface and active-peer exportability
    ↓
server routing derivation
    ↓
snapshot narrowing
```

Client:

```text
EXPORT_SECRET reference resolution
    ↓
active-peer and interface load
    ↓
database consistency preflight
    ↓
peer reload and active recheck
    ↓
interface and client-peer exportability
    ↓
client routing and effective-value derivation
    ↓
snapshot narrowing
```

The existing relative error order must remain unchanged for public Core
functions. In particular:

- Client reference resolution uses `PeerAccess.EXPORT_SECRET`.
- Client resolution remains active-only and interface-disambiguated.
- Server preflight continues validating active peer private keys when present,
  even though they are not copied into the Server snapshot.
- Corrupt state fails before rendering.
- A renderer never chooses whether a gate applies.

## 3.4 Read-only behavior

CLI export, config, and QR paths remain wrapped in `core.force_readonly()`.
They must not create a missing live database or mutate an existing one.

Direct Core calls retain their current public behavior. Snapshot assembly adds
no write and commits no transaction.

## 3.5 Public interfaces

The following signatures and return types remain unchanged:

```python
get_interface_config(interface_ref: str) -> str
sync_interface(interface_ref: str) -> None
get_peer_config(
    peer_id: str,
    allowed_ips: str | None = None,
    *,
    interface_ref: str | None = None,
) -> str
get_peer_config_payload(...) -> dict[str, Any]
get_peer_qr(...) -> str
get_peer_qr_png_bytes(...) -> bytes
```

CLI commands, JSON envelopes, stdout/stderr separation, warnings, exit codes,
and existing domain exception types remain unchanged.

---

# 4. Package Organization

Create this package:

```text
src/wgpl/projection/
├── __init__.py
├── snapshots.py
├── contracts.py
├── engine.py
├── wireguard.py
└── composition.py
```

Responsibilities are fixed as follows.

## 4.1 `projection/__init__.py`

Keep the file empty.

It must not re-export the engine, snapshots, protocol, registry, projection,
or errors. Internal callers import the owning submodule explicitly.

## 4.2 `projection/snapshots.py`

Owns immutable Server and Client snapshot value types.

Rules:

- imports from the Python standard library only
- no WGPL imports
- no behavior beyond representation-safe value grouping
- no inheritance hierarchy or universal base snapshot
- no `sqlite3.Row`, `Mapping`, `Any`, callable, lazy loader, or connection
- all collections are tuples

## 4.3 `projection/contracts.py`

Owns the internal `Projection` protocol.

Rules:

- imports only standard-library typing and `projection.snapshots`
- defines no registry or concrete implementation
- defines target-specific methods instead of a generic context dictionary
- returns `str` because text is the only artifact type in version 1.1

## 4.4 `projection/engine.py`

Owns `ProjectionEngine`.

Rules:

- depends only on `contracts`, `snapshots`, centralized exceptions, and the
  standard library
- knows no concrete projection
- knows no Core, CLI, database, routing, integrity, or formatter
- performs identifier lookup and target-specific invocation
- preserves `WgplException` unchanged
- wraps only unexpected non-WGPL renderer failures

## 4.5 `projection/wireguard.py`

Owns `WireGuardProjection` and renderer-local compatibility adapters.

Rules:

- depends only on `contracts`, `snapshots`, `wireformat`, centralized
  exceptions, and the standard library
- does not import `engine` or `composition`
- does not query or mutate state
- does not resolve lifecycle, routing, effective values, references, or access
- converts typed snapshots to the temporary mapping shapes expected by
  unchanged `wireformat.py`

## 4.6 `projection/composition.py`

Is the composition root for the internal projection boundary.

Rules:

- is the only module that knows both `ProjectionEngine` and
  `WireGuardProjection`
- creates one immutable registry with identifier `"wireguard"`
- exposes two internal target-specific functions to Core
- provides no registration, mutation, discovery, or capability API

## 4.7 Existing modules

Only these existing files require implementation changes:

- `src/wgpl/core.py`
  - assembles snapshots
  - invokes composition functions
  - preserves public facade signatures
- `src/wgpl/consistency.py`
  - allows `assert_database_valid()` to use a supplied connection
- `src/wgpl/db.py`
  - provides one explicit consistent read-snapshot context
- `src/wgpl/exceptions.py`
  - owns internal projection exceptions

`src/wgpl/wireformat.py`, `src/wgpl/cli.py`, the schema, and migrations remain
unchanged in version 1.1.

---

# 5. Immutable Snapshot Contracts

Implement these exact value types in `projection/snapshots.py`:

```python
from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class ServerPeerSnapshot:
    public_key: str
    preshared_key: str | None
    allowed_ips: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class ServerSnapshot:
    interface_name: str
    mtu: int | None
    peers: tuple[ServerPeerSnapshot, ...]


@dataclass(frozen=True, slots=True)
class ClientSnapshot:
    private_key: str
    ip_address: str
    address_prefix_length: int
    dns: str | None
    mtu: int | None
    server_public_key: str
    preshared_key: str | None
    endpoint: str
    port: int
    allowed_ips: tuple[str, ...]
    keepalive: int | None
```

These dataclasses are transport values across the application-to-output
boundary. They are not domain entities and do not validate themselves.

## 5.1 Server invariants

Before a `ServerSnapshot` is constructed:

- the interface has passed consistency and exportability checks
- every included peer is active and exportable in Server mode
- every AllowedIPs tuple was derived by `routing.resolve_hub_allowed_ips()`
- peer order is the original `db.list_peers()` order
- `interface_name` and `mtu` are already wire-safe

The snapshot must not include:

- interface private key
- listen port
- interface public key
- endpoint, DNS, or keepalive
- peer private keys
- peer IDs, Node IDs, names, descriptions, lifecycle timestamps, roles, or
  routing policies
- inactive peers

`interface_name` remains because unchanged `wireformat.py` validates it as part
of the current artifact behavior.

## 5.2 Client invariants

Before a `ClientSnapshot` is constructed:

- reference resolution used `PeerAccess.EXPORT_SECRET`
- the selected peer is active after consistency preflight
- the interface and peer passed Client exportability checks
- DNS, MTU, and keepalive are fully resolved
- AllowedIPs are fully derived or override-validated and normalized
- `address_prefix_length` comes from the validated IPv4 interface pool
- endpoint and port are already validated

The snapshot must not include:

- server private key
- any unrelated peer or Node
- private keys or preshared keys belonging to other peers
- interface or peer persistence IDs
- descriptions, audit data, lifecycle timestamps, role, routing policy, or raw
  routed-network intent
- database rows or callbacks

## 5.3 Why `str` remains the artifact

Do not add an artifact dataclass in version 1.1.

The current public contract is text, output metadata is explicitly deferred,
and a wrapper would add no invariant. `ProjectionEngine.render_server()` and
`render_client()` return `str`; Core returns that same value unchanged.

---

# 6. Internal Interfaces

## 6.1 Projection protocol

Implement this structural protocol in `projection/contracts.py`:

```python
from typing import Protocol

from .snapshots import ClientSnapshot, ServerSnapshot


class Projection(Protocol):
    identifier: str

    def render_server(self, snapshot: ServerSnapshot) -> str: ...

    def render_client(self, snapshot: ClientSnapshot) -> str: ...
```

Do not use `@runtime_checkable`. Static typing and direct unit tests are
sufficient. Do not add a generic `render(context)` or `dict[str, Any]`.

The two methods are the version 1.1 target contract. They prevent target and
snapshot mismatch by construction.

## 6.2 Projection Engine

Implement this interface in `projection/engine.py`:

```python
from collections.abc import Mapping

from .contracts import Projection
from .snapshots import ClientSnapshot, ServerSnapshot


class ProjectionEngine:
    def __init__(self, projections: Mapping[str, Projection]) -> None: ...

    def render_server(
        self,
        projection_id: str,
        snapshot: ServerSnapshot,
    ) -> str: ...

    def render_client(
        self,
        projection_id: str,
        snapshot: ClientSnapshot,
    ) -> str: ...
```

Construction requirements:

- copy the supplied mapping into a private dictionary
- reject an empty registry key with
  `ValueError("Projection identifier must not be empty")`
- require each registry key to equal `projection.identifier`; otherwise raise
  `ValueError("Projection registry key must match projection.identifier")`
- expose no method that mutates or returns the registry
- perform no eager rendering or I/O

The mapping key is the lookup identity. Composition derives it directly from
`projection.identifier`, so there is one source of truth. Duplicate-key
validation is not specified because a `Mapping` cannot contain duplicate keys.

Invocation requirements:

1. Look up `projection_id`.
2. When absent, raise
   `UnknownProjectionError(f"Unknown projection '{projection_id}'")`.
3. Call the target-specific protocol method.
4. Re-raise every `WgplException` unchanged.
5. Wrap any other `Exception` as
   `ProjectionRenderError(f"Projection '{projection_id}' failed for "
   f"{target} target")`, using `raise ... from exc`.
6. The renderer and engine never interpolate snapshot values into exceptions.
7. Public CLI diagnostics render only the wrapper message and never serialize
   or log `__cause__`.
8. Tests inspect the complete exception chain and assert that no known private
   key or preshared key appears in any message.

Do not catch `BaseException`.

In the error template, `target` is the fixed literal `"server"` inside
`render_server()` and `"client"` inside `render_client()`.

## 6.3 WireGuard projection

Implement this interface in `projection/wireguard.py`:

```python
class WireGuardProjection:
    identifier = "wireguard"

    def render_server(self, snapshot: ServerSnapshot) -> str: ...

    def render_client(self, snapshot: ClientSnapshot) -> str: ...
```

`render_server()` constructs only these short-lived mappings:

```python
interface_input = {
    "name": snapshot.interface_name,
    "mtu": snapshot.mtu,
}

peer_input = {
    "public_key": peer.public_key,
    "preshared_key": peer.preshared_key,
}
```

It passes `interface_input` and ordered `(peer_input, list(allowed_ips))`
pairs to `wireformat.build_server_config()`.

`render_client()` constructs:

```python
peer_input = {
    "private_key": snapshot.private_key,
    "ip_address": snapshot.ip_address,
    "preshared_key": snapshot.preshared_key,
    "dns": snapshot.dns,
    "mtu": snapshot.mtu,
    "keepalive": snapshot.keepalive,
}

interface_input = {
    "address_pool": f"0.0.0.0/{snapshot.address_prefix_length}",
    "endpoint": snapshot.endpoint,
    "port": snapshot.port,
    "public_key": snapshot.server_public_key,
    "dns": None,
    "mtu": None,
    "keepalive": None,
}
```

It passes the comma-joined `snapshot.allowed_ips` to
`wireformat.build_client_config()`.

Using `0.0.0.0/<prefix>` is intentional: unchanged `wireformat.py` reads only
the prefix length from that value. Effective fields are placed on the peer
mapping and interface defaults are disabled, so the formatter does not make a
new cascade decision.

These mappings:

- exist only within one renderer call
- are never exposed to Core or the engine
- do not contain unrelated fields or secrets
- are a version 1.1 compatibility seam, not a projection contract

The mapping keys and fallback values shown above are exhaustive and normative.
Tests must assert their exact shape. `dns`, `mtu`, and `keepalive` interface
fallbacks remain `None`; changing that would reintroduce effective-value
ownership into `wireformat.py`. Revalidation performed by the unchanged
formatter is a representation-safety assertion only and must produce the same
normalized bytes as the already-resolved snapshot.

## 6.4 Static composition

Implement in `projection/composition.py`:

```python
from .engine import ProjectionEngine
from .snapshots import ClientSnapshot, ServerSnapshot
from .wireguard import WireGuardProjection

_WIREGUARD = WireGuardProjection()
_WIREGUARD_ID = _WIREGUARD.identifier
_ENGINE = ProjectionEngine({_WIREGUARD_ID: _WIREGUARD})


def render_wireguard_server(snapshot: ServerSnapshot) -> str:
    return _ENGINE.render_server(_WIREGUARD_ID, snapshot)


def render_wireguard_client(snapshot: ClientSnapshot) -> str:
    return _ENGINE.render_client(_WIREGUARD_ID, snapshot)
```

Do not expose `_ENGINE`, `_WIREGUARD`, or a generic registry accessor.

## 6.5 Exceptions

Add to the centralized `src/wgpl/exceptions.py`:

```python
class ProjectionError(WgplException):
    """Base for internal projection dispatch and rendering failures."""


class UnknownProjectionError(ProjectionError):
    """Raised when an internal projection identifier is not registered."""


class ProjectionRenderError(ProjectionError):
    """Raised when a renderer fails outside the WGPL exception contract."""
```

Do not add unsupported-target or unsupported-option exceptions in version 1.1.
The typed target methods make target mismatch unrepresentable, and version 1.1
has no projection-owned options.

Do not export these exceptions from `wgpl.__init__` or
`wgpl.projection.__init__`.

---

# 7. Snapshot Assembly in Core

Snapshot builders remain private Core application helpers. They may depend on
DB, refs, consistency, integrity, routing, fields, and snapshot dataclasses.
No projection package module performs assembly.

## 7.1 Consistent read snapshot

Add this context manager to `db.py`:

```python
@contextmanager
def read_snapshot() -> Generator[sqlite3.Connection, None, None]:
    with get_db() as conn:
        conn.execute("BEGIN DEFERRED")
        try:
            yield conn
        finally:
            conn.rollback()
```

Properties:

- it honors the existing thread-local `force_readonly()` behavior
- it establishes one SQLite read snapshot for all assembly reads
- it never commits
- it does not use `BEGIN EXCLUSIVE`
- it owns and closes the connection
- it creates no new schema behavior

Extend `consistency.assert_database_valid()` compatibly:

```python
def assert_database_valid(
    interface: str | None = None,
    *,
    conn: sqlite3.Connection | None = None,
) -> None:
    result = validate_state(interface, conn=conn)
    ...
```

The existing call form remains valid.

All refs and DB helpers used by assembly receive the same `conn`.

## 7.2 Server builder

Create a private helper in `core.py`:

```python
def _build_server_snapshot(
    interface_ref: str,
    *,
    conn: sqlite3.Connection,
) -> ServerSnapshot: ...
```

Required sequence:

1. `assert_database_valid(interface_ref, conn=conn)`.
2. `resolve_interface_ref(interface_ref, conn=conn)`.
3. `db.get_interface(interface_id, conn=conn)`.
4. Preserve the existing `InterfaceNotFoundError` message.
5. `integrity.assert_exportable_interface(iface)`.
6. `db.list_peers(interface_id, conn=conn)`.
7. Iterate in returned order.
8. Skip peers for which `integrity.is_peer_active(peer)` is false.
9. `integrity.assert_exportable_peer(peer, iface, mode="server")`.
10. Derive `routing.resolve_hub_allowed_ips(peer)`.
11. Copy only required scalar values into `ServerPeerSnapshot`.
12. Return `ServerSnapshot` with a peers tuple.

Do not sort after step 6.

## 7.3 Client builder

Create a private helper in `core.py`:

```python
from typing import Literal


def _build_client_snapshot(
    peer_id: str,
    allowed_ips: str | None,
    *,
    interface_ref: str | None,
    conn: sqlite3.Connection,
) -> tuple[
    ClientSnapshot,
    tuple[str, ...],
    Literal["derived", "override"],
]: ...
```

The second tuple item is the public `client_allowed_ips` metadata in its
existing representation. It is not passed to the renderer.

Required sequence:

1. Resolve with
   `resolve_peer_ref(..., access=PeerAccess.EXPORT_SECRET, conn=conn)`.
2. Load the selected peer with the same connection.
3. Preserve the existing inactive-as-not-found behavior.
4. Load its interface with the same connection.
5. Preserve the current missing-interface error.
6. Select the preflight reference exactly as the current path does.
7. `assert_database_valid(preflight_ref, conn=conn)`.
8. Reload the peer using the same connection and repeat the active check.
9. `integrity.assert_exportable_interface(iface)`.
10. `integrity.assert_exportable_peer(peer, iface, mode="client")`.
11. If no override:
    - load all interface peers with the same connection
    - filter with `integrity.is_peer_active()`
    - call `routing.resolve_client_allowed_ips()`
    - use the derived ordered values for both snapshot and public metadata
12. If an override exists:
    - create public metadata by splitting the original input on commas,
      stripping each non-empty entry, and preserving each stripped value
      exactly as current `get_peer_config_payload()` does
    - call the existing AllowedIPs validator at the same relative point at
      which formatting currently validates it
    - split the normalized result into the ordered tuple used only by
      `ClientSnapshot`
13. Resolve effective DNS, MTU, and keepalive with `fields.py`.
14. Parse the validated interface pool and copy its prefix length.
15. Copy only the required scalar values into `ClientSnapshot`.

Do not pass the active peer collection into the snapshot.

## 7.4 Core projection helpers

Replace direct formatter calls with these private helpers:

```python
def _project_server_config(interface_ref: str) -> tuple[str, str]:
    """Return interface name and rendered server artifact."""


def _project_client_config(
    peer_id: str,
    allowed_ips: str | None = None,
    *,
    interface_ref: str | None = None,
) -> tuple[
    str,
    tuple[str, ...],
    Literal["derived", "override"],
]:
    """Return artifact plus public AllowedIPs metadata and source."""
```

Each helper:

1. opens one `db.read_snapshot()`
2. builds the target snapshot
3. exits the DB context
4. renders outside the connection

Rendering outside the connection proves that renderers cannot lazy-load.

`_project_server_config()` returns `snapshot.interface_name` with the artifact
so Apply does not perform a second interface read.

`_project_client_config()` keeps the secret-bearing snapshot local until
rendering finishes. It returns only the artifact and public metadata required
by `get_peer_config_payload()`.

## 7.5 Public facade rewiring

Wire public functions as follows:

- `get_interface_config()` returns `_project_server_config(...)[1]`.
- `sync_interface()` calls `_project_server_config()` once and passes its two
  returned values to `wireguard.syncconf()`.
- `get_peer_config()` returns `_project_client_config(...)[0]`.
- `get_peer_config_payload()` calls `_project_client_config()` once and uses
  `list(returned_allowed_ips_metadata)` plus the returned source. This explicit
  conversion preserves the current public `list[str]` return type while the
  private helper retains an immutable tuple.
- QR functions continue calling `get_peer_config()` unchanged.

This removes the current second read and second routing derivation in
`get_peer_config_payload()` without changing either its return shape or the
legacy distinction between normalized config text and stripped override
metadata.

---

# 8. Allowed and Forbidden Dependencies

The following matrix is normative.

| Importing module | Allowed WGPL imports | Forbidden WGPL imports |
|---|---|---|
| `cli.py` | `core` | all `projection.*` modules |
| `core.py` | `projection.snapshots`, `projection.composition`, existing dependencies | `projection.engine`, `projection.wireguard`, `projection.contracts` |
| `projection.snapshots` | none | every WGPL module |
| `projection.contracts` | `projection.snapshots` | Core, CLI, DB, domain, infrastructure, concrete projection |
| `projection.engine` | `projection.contracts`, `projection.snapshots`, `exceptions` | Core, CLI, DB, domain, infrastructure, concrete projection, composition |
| `projection.wireguard` | `projection.contracts`, `projection.snapshots`, `wireformat` | Core, CLI, DB, dbpath, refs, routing, integrity, fields, engine, composition |
| `projection.composition` | `projection.engine`, `projection.contracts`, `projection.snapshots`, `projection.wireguard` | Core, CLI, DB, refs, routing, integrity |
| `wireformat.py` | its current dependencies | every `projection.*` module |
| domain/infrastructure modules | their current dependencies | every `projection.*` module |

No module may import from `projection.__init__`.

The only permitted cycle-shaped knowledge point is composition knowing both
the engine abstraction and concrete renderer. Neither side imports
composition, so no actual import cycle exists.

---

# 9. Cycle Prevention

Add `tests/test_projection_dependencies.py`.

Use `ast` and `pathlib` from the standard library; add no dependency.

The tests must:

1. Parse all direct `Import` and `ImportFrom` nodes under
   `src/wgpl/projection`.
2. Normalize relative imports to full `wgpl.projection.*` names.
3. Enforce the module-specific allowlist in section 8.
4. Assert `projection.snapshots` has no WGPL import.
5. Assert `projection.wireguard` does not import engine or composition.
6. Assert engine does not import the concrete projection.
7. Assert no existing module except `core.py` imports composition or
   snapshots.
8. Assert domain and infrastructure modules do not import `wgpl.projection`.
9. Assert both `wgpl/__init__.py` and `projection/__init__.py` export no
   projection symbols.
10. Build a graph of internal projection imports and fail if depth-first
    traversal finds a back edge.
11. Smoke-import `wgpl.core`, `wgpl.projection.composition`, and
    `wgpl.projection.wireguard`.

Keep this test explicit rather than inferring architectural layers from file
names.

Introduce this test incrementally. Stage 1 enforces only snapshots, contracts,
engine, exceptions, and their available import graph. Stage 3 adds the
WireGuard, composition, full allowlist, and composition smoke-import checks
after those modules exist. No test may reference a module scheduled for a
later stage.

---

# 10. Incremental Migration

## Stage 0 — Characterize legacy behavior

Production code remains unchanged.

Add:

- fixed valid keys, UUIDs, timestamps, and IPs for deterministic fixtures
- exact Server and Client `.conf` golden files
- error parity cases for representative corrupt states
- explicit peer-order tests
- pre-cutover baselines for complete stdout, stderr, JSON envelopes, warnings,
  and exit codes for representative export, config, QR, and Apply cases
- pre-cutover error baselines for not-found, inactive peer, ambiguous
  reference, interface mismatch, missing interface, and invalid override

Exit condition:

- current legacy paths produce the checked-in golden bytes
- checked-in goldens are reviewed constants and are never regenerated by tests
- public baselines are captured before any Core cutover
- the complete existing suite passes

## Stage 1 — Add internal contracts

Add snapshot dataclasses, protocol, exceptions, engine, and isolated unit
tests. Do not add composition, the WireGuard renderer, or any Core connection
in this stage.

Exit condition:

- engine identifier and error tests pass
- snapshot immutability and secret-exclusion tests pass
- dependency tests for the modules present in this stage pass
- all public behavior still uses the legacy path

## Stage 2 — Add Core snapshot builders

Add `db.read_snapshot()`, connection threading for
`assert_database_valid()`, and private Server/Client builders.

Do not cut over public functions.

Exit condition:

- builder tests prove one connection is used
- a coordinated writer test commits between assembly reads and proves the
  snapshot is entirely pre-commit or post-commit, never mixed
- snapshots contain no rows or unrelated secrets
- snapshot values match legacy derivation across all routing policies
- legacy output remains unchanged

## Stage 3 — Add WireGuard renderer and differential tests

Add `WireGuardProjection`, static composition, registry wiring, and their smoke
imports. Render snapshots through the projection while public functions still
use the legacy formatter path.

For every fixture, compare:

- legacy text and projected text byte-for-byte
- legacy and projected exception type and message
- repeated projected output

Exit condition:

- differential matrix passes for Server and Client
- projection renderer has no I/O and no forbidden import
- composition imports and registry identity checks pass

## Stage 4 — Cut over Server

Rewire `get_interface_config()` and `sync_interface()` through
`_project_server_config()`.

Keep the legacy private Server helper for rollback during the release window.
Do not add a flag or environment variable.

Exit condition:

- interface export still matches the Server golden
- Apply receives exactly the value returned by interface export
- fail-closed state never reaches `syncconf`
- CLI contracts are unchanged

## Stage 5 — Cut over Client

Rewire config and config JSON payload through `_project_client_config()`. QR
continues consuming `get_peer_config()`.

Keep the legacy private Client helper for rollback during the release window.
Also retain the legacy JSON payload path and its AllowedIPs metadata behavior.
Rollback is a tested joint source-code reversion of config dispatch and payload
construction, not an emitter-only switch.

Exit condition:

- config still matches the Client golden
- config JSON AllowedIPs come from the same snapshot
- ASCII and PNG QR consume exactly the projected config string
- secret warnings and channels are unchanged

## Stage 6 — Full verification

Run the complete validation suite and read-only checks.

Exit condition:

- all RFC acceptance criteria and section 12 tests pass
- no schema or user-version change exists
- rollback consists only of reverting Core dispatch to legacy private helpers

## Stage 7 — Remove legacy helpers

Perform only after version 1.1 parity has been verified through the release
window. Their removal is cleanup, not part of the initial cutover.

Permanent golden, dependency, snapshot, and public contract tests remain.

---

# 11. Testing Design

## 11.1 Test files

Add:

```text
tests/
├── test_projection_snapshots.py
├── test_projection_engine.py
├── test_projection_wireguard.py
├── test_projection_dependencies.py
└── test_projection_parity.py

tests/golden/projection/
├── server.conf
└── client.conf
```

Extend existing tests only where the assertion belongs to an existing public
consumer:

- `tests/test_sync.py`
- `tests/test_wireformat.py`
- `tests/test_core.py`
- `tests/test_routing.py`
- `tests/test_cli.py`
- `tests/test_cli_json.py`
- `tests/test_cli_crud.py`
- `tests/test_cli_qa_matrix.py`

## 11.2 Fixed fixtures

Golden fixtures must use:

- fixed valid base64 WireGuard keys
- fixed peer UUIDs
- explicit IP addresses
- `expires_at=None`
- explicit DNS, MTU, keepalive, PSK, routed networks, and policy
- insertion order intentionally different from textual IP order

Random key generation must not be used by golden tests.

Golden files are read as bytes and compared with `artifact.encode("utf-8")`.
They are reviewed constants committed to the repository and are never
generated or updated by the test suite. Expiration behavior uses separate
fixtures with a controlled clock or timestamps calculated for that test; it is
not part of golden input.

## 11.3 Snapshot tests

Assert:

- assignment to every dataclass field raises `FrozenInstanceError`
- collection fields are tuples
- snapshots contain no `sqlite3.Row`, connection, mapping, callable, or lazy
  loader
- Server contains no peer private key
- Client contains no server private key or unrelated peer secret
- inactive peers never appear in Server
- Client includes only the selected peer secret
- renderer-local mappings are not retained
- renderer-local mappings contain exactly the keys and fallback values defined
  in section 6.3

## 11.4 Engine tests

Assert:

- `"wireguard"` resolves
- unknown identifier raises `UnknownProjectionError`
- existing `WgplException` is re-raised by identity/type without wrapping
- an unexpected renderer exception becomes `ProjectionRenderError`
- `__cause__` preserves the internal exception
- the wrapper and every message in the cause chain contain no known snapshot
  private key or preshared key
- public diagnostics render only the wrapper and never serialize the cause
- no registry mutation API exists
- empty registry keys and key/identifier mismatch raise the exact `ValueError`
  messages defined in section 6.2

## 11.5 Byte and determinism tests

Assert:

- exact Server bytes
- exact Client bytes
- optional fields preserve position and blank lines
- terminal newline behavior
- empty Server artifact is `""`
- peers preserve textual IP ordering
- explicit AllowedIPs preserve normalized input order
- derived AllowedIPs preserve routing canonical order
- repeated rendering of one snapshot produces identical bytes

## 11.6 Routing matrix

Cover exact projected output for:

- endpoint hub route
- subnet-router hub route
- `vpn_only`
- `split_tunnel`
- `all_remote_networks`
- `full_tunnel`
- successful `custom`
- explicit export override
- own-LAN exclusion
- multiple routed networks
- redundant-prefix collapse
- inactive remote subnet-router exclusion

## 11.7 Fail-closed parity

Compare legacy and projected paths for:

- not-found peer or interface
- inactive peer
- ambiguous peer reference
- interface mismatch
- missing interface after peer resolution
- invalid AllowedIPs override ordering
- invalid interface and peer public keys
- invalid selected Client private key
- invalid peer private key during Server preflight
- invalid PSK
- unsafe endpoint, IP, DNS, and AllowedIPs text
- invalid port, address pool, MTU, and keepalive
- invalid routing fields
- corrupt expiration
- warning-only consistency state

Compare:

- exception class
- exception message
- whether `wireguard.syncconf()` was called

## 11.8 Consumer identity

Assert:

- `sync_interface()` passes exactly the Server artifact returned by
  `get_interface_config()`
- ASCII QR passes exactly the Client artifact to `QRCode.add_data()`
- PNG QR passes exactly the Client artifact to `QRCode.add_data()`
- JSON config contains that same Client artifact
- JSON `client_allowed_ips` equals the legacy public metadata returned by the
  same private projection helper
- direct `get_peer_config_payload()` exposes `client_allowed_ips` as
  `list[str]`, never as the helper's internal tuple
- an override such as `10.0.0.1/24` renders
  `AllowedIPs = 10.0.0.0/24` in config while JSON preserves
  `["10.0.0.1/24"]`

## 11.9 CLI contracts

For export, config, QR, and Apply, verify:

- complete stdout
- complete stderr
- exit code
- parsed JSON envelope
- existing private-key warning behavior
- no secret in stderr or error messages
- interface disambiguation and mismatch errors
- missing DB and corrupt DB behavior

## 11.10 Read-only proof

Add fresh-database cases for interface export, peer config, and peer QR.

For successful populated-database cases:

- record DB bytes before and after
- record schema and `PRAGMA user_version`
- assert no data change
- assert no unexpected `-wal` or `-shm` persistence
- assert rendering occurs after the read connection has closed

Add a coordinated concurrency case that:

1. begins snapshot assembly
2. pauses after the first state read
3. commits a writer mutation from another connection
4. resumes all remaining reads
5. asserts the result is wholly pre-commit or wholly post-commit, never mixed

## 11.11 Required commands

Run:

```bash
uv run ruff check src/ tests/
uv run mypy src/ tests/
uv run pytest
```

No implementation stage is complete until all three pass.

---

# 12. Resolved Implementation Decisions

This section records the decisions now aligned with the parent RFC. None of
these items remains open for version 1.1.

## A1 — Server private key and listen port

**Resolved question:** The schema contains no server private key and the
current Server artifact emits neither a private key nor listen port.

**Decision:** Exclude both fields from `ServerSnapshot`.

**Rationale:** This is the only choice consistent with no schema change,
least privilege, unchanged `wireformat.py`, and byte-for-byte compatibility.

## A2 — Meaning of “complete server configuration”

**Resolved question:** Server artifact scope is the existing syncconf payload,
not an interface provisioning file.

**Decision:** In version 1.1, Server means the current complete `wg syncconf`
artifact: optional MTU plus the complete active peer set.

**Rationale:** Apply and remote sync already consume this contract. Expanding
it would change product behavior.

## A3 — Fully resolved snapshots versus unchanged `wireformat.py`

**Resolved question:** `wireformat.py` currently performs effective-field
fallback and accepts row-like mappings.

**Decision:** Core resolves all effective values. The WireGuard projection
adapts those values to temporary mappings, places resolved values in peer
positions, and disables interface fallback with `None`.

**Rationale:** This keeps domain decisions before the output boundary while
preserving the proven serializer and exact bytes.

## A4 — Snapshot consistency

**Resolved question:** The RFC requires one consistent snapshot, while current
emit steps use multiple connections.

**Decision:** Use one explicit deferred read transaction and thread its
connection through preflight, refs, reads, derivation, and assembly.

**Rationale:** It removes mixed-state artifacts without introducing write
locking, schema changes, or renderer I/O.

## A5 — Canonical peer order

**Resolved question:** Canonical order could mean numeric IP order, while
existing SQL uses textual IP order.

**Decision:** Preserve current `ORDER BY p.ip_address` textual order.

**Rationale:** Ordering is observable. Numeric sorting would violate the
backwards-compatibility requirement.

## A6 — Projection options

**Resolved question:** Version 1.1 defines no renderer-owned option.

**Decision:** Version 1.1 has no projection options and no options dictionary.
Core resolves the existing AllowedIPs override before snapshot construction.

**Rationale:** It preserves current validation ownership and avoids a
speculative extension surface.

## A7 — Registry lifetime and mutability

**Resolved question:** Static registration requires one immutable-by-interface
engine registry.

**Decision:** Construct one module-level engine that copies a mapping keyed
from `projection.identifier` into a private dict; expose no registration API.

**Rationale:** It satisfies static registration with the smallest possible
surface and no import side effects outside composition.

## A8 — Error wrapping

**Resolved question:** Projection-specific errors do not replace domain errors.

**Decision:** Re-raise `WgplException` unchanged. Wrap only unexpected
non-WGPL renderer exceptions as `ProjectionRenderError`. Renderer and wrapper
messages never interpolate snapshot values; public diagnostics never serialize
the preserved cause.

**Rationale:** Existing domain error types, messages, JSON behavior, and CLI
exit behavior remain compatible while unexpected implementation failures gain
a bounded internal error.

## A9 — Target mismatch

**Resolved question:** Target selection is represented by typed methods rather
than a generic target/context pair.

**Decision:** Use distinct `render_server(ServerSnapshot)` and
`render_client(ClientSnapshot)` methods in both protocol and engine.

**Rationale:** The type system makes invalid combinations unrepresentable;
runtime target negotiation and capabilities are unnecessary.

## A10 — Public visibility

**Resolved question:** The RFC names an engine interface but marks the contract
internal and provisional.

**Decision:** Export no projection symbol from either package `__init__.py`.
Only existing Core functions are public.

**Rationale:** Version 1.1 can refine internals without creating an SDK
compatibility obligation.

## A11 — Future extension without Core modification

**Resolved question:** A new representation and a new output purpose have
different authorization and data requirements.

**Decision:** New renderers over existing targets do not modify Core domain
rules, gates, or derivation. A new output purpose requires a future RFC and
may add application-facade wiring and a Core-owned snapshot builder.

**Rationale:** Core must retain authorization and domain-gate ownership; a
renderer must never widen its own access.

## A12 — Rollback mechanism

**Resolved question:** Code-only rollback could imply a runtime feature flag.

**Decision:** Keep private legacy helpers during the version 1.1 release
window, including the legacy Client JSON payload path. Rollback reverts config
dispatch and payload construction together; it is not a CLI option,
environment variable, or public setting.

**Rationale:** This provides safe reversal without a second permanent runtime
mode or observable behavior.

## A13 — Artifact abstraction

**Resolved question:** The RFC names an Artifact but defers metadata and
non-text formats.

**Decision:** Use `str` directly in version 1.1.

**Rationale:** An artifact dataclass would contain only one field, add no
invariant, and complicate public return-type preservation.

## A14 — JSON AllowedIPs metadata consistency

**Resolved question:** Current JSON payload construction re-reads and
re-derives values after generating config, while override metadata intentionally
differs from normalized config values.

**Decision:** Keep the Client snapshot local. Return the artifact, immutable
legacy AllowedIPs metadata, and source from one private projection helper;
convert the metadata tuple to `list[str]` when constructing the public payload.

**Rationale:** Artifact and metadata describe one database snapshot without
exposing the secret snapshot or changing public override representation.

---

# 13. Implementation Checklist

1. Add fixed legacy golden and parity fixtures.
2. Add projection exceptions to the central hierarchy.
3. Add empty `projection/__init__.py`.
4. Add frozen snapshot dataclasses.
5. Add the target-specific Projection protocol.
6. Add and unit-test Projection Engine dispatch.
7. Add dependency tests for snapshots, contracts, engine, and errors.
8. Add `db.read_snapshot()`.
9. Add optional `conn` to `assert_database_valid()`.
10. Add private Server snapshot builder in Core.
11. Add private Client snapshot and public-metadata builder in Core.
12. Add and test WireGuard compatibility adapters.
13. Add static composition with identifier `"wireguard"`.
14. Add composition smoke imports and complete dependency tests.
15. Add differential Server and Client tests.
16. Cut over Server public facade and Apply.
17. Cut over Client facade, JSON payload, and QR consumers.
18. Run CLI, read-only, secret, routing, and fail-closed matrices.
19. Run Ruff, mypy, and pytest.
20. Retain private legacy config and payload helpers through the version 1.1
    release window.
21. Remove legacy helpers only after release-window verification.

---

# 14. Definition of Done

The Projection Engine implementation is complete only when:

- the package and interfaces exactly match sections 4–6
- snapshots are immutable, least-privilege, and persistence-free
- one consistent read transaction owns each snapshot assembly
- projections perform no I/O or domain derivation
- dependencies satisfy section 8 and cycle tests pass
- Server and Client artifacts match legacy bytes exactly
- Apply and export share one Server artifact
- config, JSON, and QR share one Client artifact
- existing domain errors propagate unchanged
- unexpected renderer errors are bounded and contain no secrets
- all public CLI and Core behavior remains unchanged
- no database schema or version change exists
- no plugin, SDK, discovery, capability, metadata, streaming, or binary
  abstraction has been added
- Ruff, mypy, and pytest pass
- every resolved decision in section 12 is implemented as specified

---

# 15. Specification Traceability and Readiness

The parent RFC and this implementation design define one contract:

| Concern | RFC authority | Implementation authority | Verification |
|---|---|---|---|
| Server artifact and fields | §§5–6, §10 | §§3.1, 5.1, 6.3 | Server golden and field-exclusion tests |
| Target signatures | §§5–6, §9 | §§6.1–6.4 | mypy and engine tests |
| Gate order | §6 | §§3.3, 7.2–7.3 | old-vs-new error parity |
| Core responsibility | §§3, 6, 13–14 | §§2, 4, 7–8 | dependency tests |
| Client JSON semantics | §§16, 18 | §§7.3–7.5, 11.8 | non-canonical override parity |
| Registry and errors | §§11–12 | §§6.2, 6.4–6.5 | constructor and error-chain tests |
| Incremental migration | §13 | §10 | per-stage exit conditions |
| Rollback | §§13, 18 | §10 Stages 4–7, A12 | joint config/payload rollback test |
| Byte compatibility | §§16, 18 | §§3, 10–11 | reviewed goldens and differential tests |
| Snapshot consistency | §§6, 17–18 | §§7.1, 11.10 | coordinated writer test |

## Remediation closure

All pre-implementation Critical findings are closed:

- Server fields are identical in both documents.
- Typed Server/Client methods are the only version 1.1 target model.
- The Core-extension promise is scoped to domain rules, gates, and derivation.
- Server and Client gate order is explicit and target-specific.
- Client JSON preserves legacy override metadata.
- Each migration stage can compile and pass independently.

All Recommended findings have a verifiable contract:

- the synthetic formatter adapter has an exact tested shape
- registry identity and construction failures are defined
- registry immutability uses one mechanism
- Client rollback includes payload construction
- public baselines precede cutover
- concurrency is tested with an intervening writer
- goldens use no wall-clock expiration
- the complete exception chain is checked for secrets
- reference and override errors are part of differential parity

## Readiness verdict

The specifications are ready for implementation.

This verdict applies to the documented version 1.1 scope only. It does not
approve plugins, SDKs, new formats, metadata, capabilities, streaming, binary
artifacts, or any database change.

