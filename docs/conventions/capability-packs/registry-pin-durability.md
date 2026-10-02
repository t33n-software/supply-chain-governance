# Capability packs — registry pin durability
[INTENT: CONSTRAINT]

## Canonical source

This file is the canonical source of truth for the registry pin durability
convention of the capability-pack registry. The anchor package
`capabilities/doc.go` references this document; every future registry home and
every tenant pins through this convention. A local copy, redefinition, or
deviation of this rationale anywhere else is an anti-pattern and forbidden
(redundancy and drift prohibition).

## The rule

A registry home whose packs tenants enumerate and read at gate time, but from
which tenants pin no tool, MUST ship a registry anchor package at the registry
root: a minimal documentation package (`capabilities/doc.go`,
`package capabilities`) with no behavior and no exported API.

A tenant MUST keep the registry module durable in its tooling module's build
list through a blank import of the anchor package in `tools/tools.go`:

```go
import _ "github.com/t33n-software/supply-chain-governance/capabilities"
```

A bare `require` without the import is not a durable form: `go mod tidy`
removes a module that delivers no imported package and no tool directive, and
the metadata gate (`go -C tools mod tidy -diff`) fails closed on the drift.

## The bound mechanism

1. The anchor package makes the tenant's consumption relationship to the
   registry module explicit and importable.
2. The blank import keeps the module in the tenant's `tools/go.mod` build list
   under `go mod tidy`; the committed, sum-pinned module channel
   (`tools/go.mod` + `tools/go.sum`) stays the integrity surface.
3. The orchestrator's pack resolution and the verifier's extends resolution
   then resolve the registry at the tenant's pinned stand through the tenant's
   own integrity-pinned tooling channel, with no warm-cache assumption.

## Why this is the foundation

- The Go module channel is the one hermetic, integrity-pinned surface every
  tenant already carries; the registry travels through the same channel as the
  tools, so no second distribution mechanism exists.
- The defect class is the missing import relationship, never the pin itself:
  `go mod tidy` drops a module that delivers no imported package and no tool
  directive. The anchor completes the channel for the data-registry case; it
  is the idiomatic Go form for pinning a data module, not a workaround.
- The consumption relationship decides the pin mechanism, never the file
  type: code tools pin through the `tool` directive (self-durable); data
  registries pin through the anchor import (durable); content with its own
  governed channel (`uses:` pins, the IaC projection, render + verify, digest
  pins, identity-asserted schema references) needs no module pin at all.
- Rejected alternatives: a manifest data-pin form with explicitly versioned
  resolution (a schema evolution plus machinery changes in two homes, and the
  trust anchor would leave the committed `go.sum`), and a catalog-admitted
  kernel tool (semantically false — the tenant would pin a conformance runner
  it never executes, diluting the tool admission).

## Placement rationale (domain-driven conventions grammar)

- Conventions are domain knowledge: they follow the bounded context and the
  ubiquitous language, never the tool or the file type. New areas are created
  domain-centrically — exactly one area folder per bounded-context domain that
  owns conventions.
- A super-folder is created only when the domain itself partitions into a
  platform and a family dimension (for example
  `hosting-platforms/<platform>/<family>/`); a sub-folder is created only when
  one family carries several convention documents. A single convention of a
  domain lives directly in its area folder as a named file.
- This convention belongs to the capability-pack registry domain, and the
  shared kernel owns the registry — so exactly one area folder is created,
  `docs/conventions/capability-packs/`, with no super-folder (the convention
  is platform-agnostic) and no sub-folders (one document). The file is named
  after the bound domain rule, never after its container.

## Handoff-chain evidence

- Sub-handoff 57 (2026-08-25) carries the proof and the decisions: the
  coupling gap (its BLOCK-001) is proven in both directions — a bare `require`
  is not tidy-stable under the metadata gate, and without the module the
  registry resolution fails fail-closed (`not a known dependency`); with the
  module resolvable, the verifier passes the full surface. The anchor solution
  is bound there (its DEC-001, user-confirmed) and confirmed as the target
  architecture for this class, not a workaround (its DEC-002).
- The same handoff binds the execution chain: the anchor delivery (its
  OPEN-001, delivered as SCG-7) and the DAI-5 completion with the blank
  import and the live pack proof (its OPEN-002). The live durability proof of
  the blank import is pending with the DAI-5 completion and is not claimed
  here.

## Verification

- The kernel's governed source suite: the anchor carries the presence test
  required by the per-package test-presence gate, and the statement-free
  package is accepted by the exact-100.0% statement-coverage gate.
- The tenant lanes re-prove the durability on every governed change: the
  metadata gate keeps the pinned module honest, and the extends resolution
  proves the registry at the pinned stand fail-closed.

## Do / Don't

- ✅ Do ship an anchor package in every registry home that tenants read but
  from which they pin no tool.
- ✅ Do pin the registry module in tenants through the blank import in
  `tools/tools.go`, followed by `go -C tools mod tidy`.
- ❌ Don't keep a bare `require` as the durable form — it drifts out under
  `go mod tidy` and the metadata gate fails closed.
- ❌ Don't run `go mod tidy -modfile tools/go.mod` from the repository root —
  the root package context pulls the main-module package tree into resolution;
  the canonical form is `go -C tools mod tidy`.
- ❌ Don't pin a catalog-foreign tool only to hold a module — it dilutes the
  tool admission with a tool the tenant never executes.
