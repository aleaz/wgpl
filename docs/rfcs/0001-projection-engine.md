# RFC-0001: Projection Engine

- **Status:** Draft
- **Authors:** Alejandro Azario
- **Created:** 2026-07-17
- **Target Version:** 1.1.0
- **Discussion:** TBD

---

# 1. Abstract

This RFC proposes introducing a Projection Engine into WGPL.

The Projection Engine is an application-layer output boundary that transforms
validated, fully resolved snapshots of WGPL intent into external
representations. It is not a domain entity, domain service, persisted read
model, or alternative source of truth.

The first implementation will route the current WireGuard server and client
configuration generation through this boundary without changing any existing
observable behavior.

This RFC intentionally does **not** introduce a public projection SDK, plugins,
remote execution, REST APIs, or orchestration features.

---

# 2. Motivation

WGPL currently orchestrates WireGuard configuration generation in Core. The
existing emit paths validate database consistency and exportability, derive
routing information, and then delegate text serialization to `wireformat.py`.

This approach works well today, but output selection and assembly remain part
of Core's application orchestration:

- additional representations would require changes to Core
- representation-specific dispatch could accumulate in Core
- future consumers need a stable boundary after domain rules are resolved
- new representations must not duplicate lifecycle, routing, exportability, or
  secret-access decisions

Possible future representations include:

- JSON
- YAML
- Markdown
- Inventory formats
- Terraform
- Ansible
- NetBox payloads
- API serialization

These are different representations of WGPL intent. They are not necessarily
the same payload: different output purposes may require different cardinality,
directionality, and secret scope.

The architecture should explicitly model output transformation while
preserving the existing domain and security boundaries.

---

# 3. Goals

The Projection Engine SHALL:

- keep WGPL as the single source of truth
- separate domain logic from output generation
- allow multiple representations
- allow new renderers over existing Server and Client target contracts without
  modifying Core domain rules, gates, or derivation
- maintain backwards compatibility
- require zero database schema changes
- preserve the existing fail-closed emit gate
- expose only the minimum resolved data required by each projection target
- preserve the distinction between server and client configuration contracts
- produce deterministic artifacts from immutable snapshots

---

# 4. Non Goals

This RFC does NOT introduce:

- remote provisioning
- SSH execution
- orchestration
- REST API
- daemon mode
- plugin discovery
- a public projection SDK
- third-party projection loading
- third-party integrations
- alternative databases
- persisted projections or CQRS read models
- capability negotiation
- streaming or binary artifact abstractions

Those may be addressed by future RFCs.

---

# 5. Terminology

## Source of Truth

The SQLite database containing WGPL's declarative WireGuard intent. Projection
snapshots and artifacts are derived views and never become sources of truth.

---

## Projection

A stateless, on-demand output transformation from an immutable, fully resolved
snapshot into an artifact.

Examples:

- WireGuard configuration
- JSON
- Markdown

A Projection:

- MUST NOT query or modify the database
- MUST NOT resolve references, lifecycle, routing, or effective settings
- MUST NOT make secret-access decisions
- MUST NOT depend on Core, CLI, persistence, or the Projection Engine
- MUST produce the same bytes for the same target-specific method and snapshot

Projection does not mean a persisted CQRS read model. It has no independent
lifecycle, storage, rebuild process, or eventual consistency.

---

## Projection Engine

Application-layer component responsible for:

- selecting a statically registered projection
- validating the projection identifier
- invoking the target-specific Server or Client method with an authorized
  snapshot
- returning generated artifacts

It does not own domain consistency, exportability, lifecycle, routing, field
cascades, or secret authorization.

---

## Projection Target

The directional purpose for which a snapshot and artifact are produced.

Version 1.1 recognizes two WireGuard targets:

- **Server:** the complete hub configuration consumed by export, remote sync,
  and Apply.
- **Client:** the configuration for one active peer, consumed by config export
  and QR generation.

Targets have different cardinality, directionality, effective values, and
secret requirements. In version 1.1 they are represented by distinct,
statically typed `render_server(ServerSnapshot)` and
`render_client(ClientSnapshot)` methods. There is no generic target parameter
or projection-owned options dictionary.

---

## Projection Snapshot

An immutable, internally defined, purpose-specific value assembled after the
existing domain gates have succeeded.

A snapshot contains only semantic values required by its target. It MUST NOT
contain database rows, database connections, repositories, callbacks, lazy
loaders, mutable domain objects, or unrelated metadata.

---

## Artifact

The deterministic result returned by a Projection. For version 1.1, a
WireGuard artifact is UTF-8 text whose bytes preserve the existing server or
client configuration contract.

---

# 6. Design Principles

The Projection Engine SHALL satisfy the following principles.

## Single Responsibility

Each projection renders one representation from an already resolved snapshot.

The Projection Engine performs dispatch and invocation. Snapshot construction
and domain gates remain application orchestration responsibilities.

---

## Stateless

Projections MUST NOT retain state between invocations.

---

## Read Only

Projection execution MUST NOT create, query, or modify the database. Snapshots
MUST be immutable, and projections MUST NOT mutate objects shared with Core.

Existing read-only behavior for config, export, and QR paths MUST be
preserved.

---

## Deterministic

Given the same projection identifier, target-specific method, and immutable
snapshot, a projection MUST produce byte-for-byte identical output.

Snapshot construction MUST:

- observe one consistent database state
- use canonical collection ordering
- normalize values through existing domain rules
- exclude current time, environment values, and other volatile metadata unless
  they are explicit request inputs

Encoding, line ordering, blank lines, and terminal newline are part of the
WireGuard artifact contract.

---

## Least Privilege

Each target receives only the fields and secrets required to produce its
artifact. A generic superset context is forbidden.

Future public, inventory, or diagnostic representations MUST use separate
non-secret snapshots. Secrets MUST NOT appear in projection metadata, registry
metadata, exception messages, or logs.

---

## Domain and Infrastructure Isolation

Domain policies and objects MUST NOT depend on the Projection Engine or any
projection implementation.

Dependencies flow from application orchestration toward abstractions at the
output boundary and from concrete projections toward snapshot and artifact
contracts:

```
CLI
 │
Core application facade
 │
 ├── domain gates and derivation
 │
 └── projection dispatch
      │
      └── concrete projection
           │
           └── representation formatter
```

Concrete projections MUST NOT import or call Core, CLI, persistence, or the
Projection Engine. Registration belongs to application composition and MUST
NOT be performed by domain modules or projection side effects.

---

## Gate Ownership

The existing fail-closed behavior remains authoritative, including the
target-specific ordering needed to preserve public error behavior.

Server sequence:

```
database consistency preflight
    ↓
interface resolution and load
    ↓
interface and active-peer exportability
    ↓
server routing derivation
    ↓
immutable Server snapshot
    ↓
projection rendering
```

Client sequence:

```
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
immutable Client snapshot
    ↓
projection rendering
```

The Client sequence intentionally resolves authorization before consistency
preflight because that is the existing observable error order.

The Projection Engine validates only the projection identifier and invokes the
already selected target-specific method. A projection may validate target
syntax required by its representation, but MUST NOT weaken, repeat, or replace
domain gates.

---

# 7. Proposed Architecture

```
                        CLI
                         │
                 Core application facade
                         │
             ┌───────────┴───────────┐
             │                       │
      Domain gates/derivation   Projection dispatch
             │                       │
             └──── target snapshot ──┤
                                     │
                           WireGuard projection
                             ┌───────┴───────┐
                             │               │
                        Server target   Client target
                             │               │
                             └── wireformat ─┘
```

The engine is not below Domain Services and Domain Services do not invoke it.
Core remains the public application facade. The projection boundary is
internal and provisional in version 1.1.

---

# 8. Initial Scope

Version 1.1 introduces one statically registered projection with one stable
internal identifier:

```
wireguard
```

The WireGuard projection supports two explicit targets:

```
server
client
```

It delegates final `.conf` text serialization to the existing wire-format
implementation. No other projection, plugin mechanism, discovery protocol,
public SDK, capabilities API, streaming API, binary artifact type, packaging
contract, or version negotiation is introduced.

Current users MUST observe identical output and error behavior.

---

# 9. Internal Contract

The projection contract is internal and provisional in version 1.1. Existing
Core and CLI facades remain the only supported public interfaces.

Conceptually, an invocation consists of:

- a stable internal projection identifier
- an explicit target-specific Server or Client method
- an immutable target-specific snapshot
- one returned artifact

The contract MUST NOT expose a universal dictionary or raw domain/persistence
objects. Projection name, version, description, capabilities, and discovery
metadata are not part of the version 1.1 contract.

The exact internal Python shape may be refined during implementation without
creating a compatibility commitment.

---

# 10. Target Snapshots

The application layer assembles a separate immutable snapshot for each target
after reference resolution, access authorization, consistency, exportability,
routing, and effective-value derivation.

## Server Snapshot

Represents the current complete `wg syncconf` artifact: optional interface MTU
plus the complete active peer set. It is not an interface provisioning file.

It contains only the resolved values currently required to emit that artifact,
including:

- exportable interface name, retained for current wire-format validation
- optional interface MTU
- active peer attachments in canonical order
- each peer's exportable public key and authorized preshared key
- already-derived server-side AllowedIPs

It excludes:

- interface private key and listen port
- interface public key, endpoint, DNS, and keepalive
- inactive peers
- peer private keys
- Node descriptions and audit history
- lifecycle timestamps not used by formatting
- database identifiers and persistence rows unless the wire artifact itself
  requires the semantic value
- client-side DNS, MTU, endpoint, and AllowedIPs decisions

## Client Snapshot

Represents one active peer configuration for one interface.

It contains only the resolved values currently required to emit that artifact,
including:

- the selected peer's exportable private key and authorized preshared key
- the peer address
- already-resolved effective DNS, MTU, and keepalive values
- the server public key and endpoint
- already-derived client-side AllowedIPs for the requested export policy

It excludes:

- the server private key
- private keys or preshared keys of other peers
- unrelated peers and Nodes
- audit history and persistence rows

Client snapshot authorization MUST preserve the current
`PeerAccess.EXPORT_SECRET` semantics, including interface disambiguation and
active-only access.

## Future Snapshots

Future public, inventory, or diagnostic representations MUST define their own
minimum non-secret snapshots. They MUST NOT reuse either secret-bearing
WireGuard snapshot merely for convenience.

---

# 11. Registration

Version 1.1 uses explicit static registration in application composition.

The registry contains only the stable identifier required for dispatch:

```
wireguard
```

Automatic discovery, entry points, import side effects, third-party loading,
version metadata, descriptions, and capability negotiation are intentionally
postponed.

---

# 12. Error Handling

Existing domain errors MUST propagate through the current public Core and CLI
boundaries without being converted to generic projection errors. This includes
reference resolution, consistency, exportability, lifecycle, routing, and
secret-access failures.

New internal projection errors are limited to:

- unknown projection identifier
- representation rendering failure

Version 1.1 has no unsupported-target or unsupported-option runtime path:
target and snapshot pairing is expressed by distinct typed methods, and no
projection-owned options exist.

New errors MUST preserve their internal cause for diagnostics while public
messages MUST NOT expose implementation details or secrets. Existing exception
types, messages where contractual, CLI exit codes, JSON error behavior, and
stdout/stderr separation MUST remain unchanged for existing commands.

---

# 13. Migration Plan

Current implementation:

```
Core facade
    ↓
emit gate and routing derivation
    ↓
wireformat.py
    ↓
.conf artifact
```

Version 1.1 implementation:

```
Core facade
    ↓
unchanged emit gate and routing derivation
    ↓
target-specific immutable snapshot
    ↓
Projection Engine dispatch
    ↓
WireGuard projection
    ↓
wireformat.py
    ↓
.conf artifact
```

The responsibility extracted from Core is representation dispatch and
invocation using an already authorized snapshot. Core remains responsible for
the public facade, read-only execution boundary, reference resolution, domain
gates, routing derivation, and snapshot authorization.

Migration SHALL proceed as follows:

1. Preserve the current public Core and CLI entry points.
2. Introduce target snapshot construction after the existing emit gates.
3. Add the internal static registry and WireGuard projection.
4. Run the current and projected paths against the same fixed fixtures.
5. Require byte-for-byte and error-contract parity before cutover.
6. Route existing entry points through the projected path.
7. Retain a code-only rollback path for the version 1.1 release window.

During migration:

- wireformat.py remains unchanged
- CLI remains unchanged
- database remains unchanged
- schema, migrations, and `PRAGMA user_version` remain unchanged
- export and Apply use the same server artifact
- config export and QR use the same client artifact
- no command may bypass the existing read-only or fail-closed boundaries

A pass-through wrapper without the responsibility transfer described above
does not satisfy this RFC.

---

# 14. Future Evolution

Possible future projections include:

- JSON
- YAML
- Markdown
- HTML
- Terraform
- Ansible
- NetBox
- OpenAPI payloads

Future RFCs may introduce:

- plugin loading
- dynamic registration
- packaging
- capability discovery
- public SDKs
- streaming or binary artifacts

These are intentionally excluded from this RFC.

Any future public extension mechanism requires a separate RFC after at least
one additional real projection has validated the snapshot, artifact, error,
versioning, and capability contracts.

The extension goal in this RFC applies to representation implementations over
the existing Server and Client target contracts: they do not modify Core
domain rules, gates, or derivation. Exposing a new representation through a
new application use case may require application-facade wiring and is outside
version 1.1.

---

# 15. Alternatives Considered

## Exporters

Not selected as the generic term for this boundary.

"Exporter" commonly implies serialization or transfer to an external
destination. Version 1.1 performs only an on-demand output transformation and
does not own transport, persistence, or remote application.

Existing CLI commands may continue to use the word "export"; this terminology
decision does not change their public names or behavior.

---

## Plugins

Deferred.

Plugin systems introduce additional complexity that is unnecessary for the first iteration.

---

## Template Engine

Rejected.

Many projections require computation, not only templating.

---

# 16. Backwards Compatibility

Version 1.1 permits no breaking changes to:

- CLI command names, arguments, options, output channels, warnings, and exit
  codes
- public Core signatures, return types, reference-resolution semantics, and
  exception behavior
- server and client configuration bytes, including ordering, blank lines,
  encoding, and terminal newline
- JSON envelopes and error behavior
- QR payloads and output behavior
- the exact server artifact consumed by Apply
- inactive-peer filtering, routing policies, export overrides, and fail-closed
  behavior
- read-only behavior, including not creating a missing live database
- database schema and `PRAGMA user_version`

Existing tests MUST continue passing unchanged, but that is necessary rather
than sufficient. Differential and golden tests described in the acceptance
criteria provide the compatibility proof.

---

# 17. Risks

## Secret overexposure

Mitigation:

- use distinct least-privilege snapshots for server and client targets
- never place secrets in generic metadata, exceptions, or logs
- require separate non-secret snapshots for future public representations

---

## Persistence and domain leakage

Mitigation:

- snapshots contain semantic values, not rows or persistence objects
- projections cannot query Core or the database
- dependency boundaries are verified by tests

---

## Gate bypass or duplication

Mitigation:

- preserve one authoritative gate before snapshot construction
- keep lifecycle, exportability, routing, and effective-value ownership in
  existing domain modules
- compare fail-closed behavior across old and new paths

---

## Mixed or non-deterministic snapshots

Mitigation:

- capture one consistent database state
- use immutable snapshots and canonical ordering
- exclude volatile metadata from rendering inputs

---

## Public compatibility regression

Mitigation:

- retain existing Core and CLI facades
- propagate existing domain errors
- verify artifacts, channels, JSON, QR, Apply, and exit codes differentially

---

## Dependency cycles

Mitigation:

- prohibit concrete projections from importing Core, CLI, persistence, or the
  Projection Engine
- keep registration in application composition
- add dependency-boundary checks

---

## Over-engineering and premature extensibility

Mitigation:

- version 1.1 contains one static identifier and one projection
- the internal API remains provisional
- plugins, discovery, capabilities, version negotiation, streaming, binary
  artifacts, and public SDKs are explicitly deferred

---

# 18. Acceptance Criteria

The RFC will be considered implemented when:

- an internal Projection Engine dispatches the statically registered
  `wireguard` projection
- the WireGuard projection supports explicit typed Server and Client methods
- target snapshots are immutable, least-privilege, and contain no database or
  lazy-access objects
- projections cannot import or call Core, CLI, persistence, or the Projection
  Engine
- the target-specific Server and Client gate sequences in section 6 remain
  authoritative
- existing public Core and CLI entry points remain unchanged
- existing tests pass unchanged
- differential or golden tests prove byte-for-byte parity for server and
  client artifacts, including order, blank lines, encoding, and terminal
  newline
- export and Apply consume the same server artifact
- config export and QR consume the same client artifact
- all routing policies and export overrides preserve current results
- inactive-peer filtering and corrupt-state fail-closed behavior preserve
  current results
- tests prove that each target receives only its authorized secrets and that
  metadata, errors, and logs contain no secrets
- stdout/stderr separation, warnings, JSON envelopes, exit codes, and existing
  exception behavior remain unchanged
- repeated rendering from the same fixed snapshot and request produces
  identical bytes
- read-only commands do not create or mutate the live database
- no database schema, migration, or `PRAGMA user_version` change occurs
- downgrade to the previous code path requires no data rollback
- dependency-boundary checks prevent renderer-to-Core/DB/CLI/Engine imports

---

# 19. Open Questions

The following are intentionally deferred and MUST NOT expand the version 1.1
contract:

- public projection naming and versioning conventions
- registry descriptions and output metadata
- capability discovery
- plugin discovery and packaging
- streaming support
- binary artifact support
- public SDK compatibility policy

Questions necessary to implement server/client snapshot fields or preserve
existing behavior MUST be resolved before implementation begins and recorded
in this RFC rather than delegated to individual projections.

---

# 20. References

- RFC-0001 (this document)
- [WGPL Architecture](../../DESIGN.md)
- [WGPL CLI Reference](../cli.md)
- Clean Architecture
- Domain-Driven Design