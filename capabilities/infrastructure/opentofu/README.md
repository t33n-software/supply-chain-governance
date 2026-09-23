# Capability pack: opentofu

The `opentofu` pack carries the shared OpenTofu infrastructure gate behavior
for every tenant that declares it through the `extends` list of its
`git-governance.quality.json` at a pinned major (`opentofu@1` or
`opentofu@2`). It is language-neutral: its provisioning installs `tofu` and
its gates run `tofu`, with no dependency on the tenant's language toolchain,
so it lives in the shared kernel.

## What the pack binds

- **Provisioning (`recipe`):** the orchestrator downloads the pinned
  `tofu_1.12.5_<os>_<arch>.zip` release artifact for the runner platform,
  verifies the bound `sha256` digest fail-closed, verifies the bound cosign
  signature reference, and installs the tool into the tool cache. The enforced
  environment (`OPENTOFU_ENFORCE_GPG_VALIDATION=true`, `TF_IN_AUTOMATION=true`,
  `TF_INPUT=false`) is part of the descriptor.
- **Version assertion:** before any gate runs, the pack proves the toolchain
  banner `OpenTofu v1.12.5` from `tofu version`.
- **Gates:**
  - `opentofu-fmt-check` — `tofu fmt -check -recursive` once at the repository
    root;
  - `opentofu-init` — `tofu init -backend=false -input=false -no-color` once
    per discovered HCL root;
  - `opentofu-validate` — `tofu validate -no-color` once per discovered HCL
    root;
  - `opentofu-test` — `tofu test -no-color` once per discovered HCL root
    (major version 2): the value-evaluated custom-condition proof.
- **Discovery:** the parent directories of `**/*.tf` form the per-root set;
  `.build`, `.git`, `.cache`, `.terraform`, `coverage`, `dist`, and `vendor`
  are excluded.

## Bound versions and platforms

OpenTofu `1.12.5` is the only bound version of this pack major. The descriptor
binds the release artifacts for `linux-amd64`, `windows-amd64`, and
`darwin-arm64` by URL and digest; a diverging artifact never executes. A
version or artifact change ships as a new pack major version, never as an
in-place edit.

## Pack majors

- **v1** (`v1/pack.json`) carries the static gate layer: format check,
  initialization, and validation.
- **v2** (`v2/pack.json`) adds the value-evaluated custom-condition proof gate
  `opentofu-test` to the unchanged static layer. The mandatory verification
  surface this major binds — the exact proof limits of the static layer, the
  behavioral proof duty for every custom condition, and the guard form — is
  owned by
  `DEVELOPER_PLATFORM_INFRASTRUCTURE_AS_CODE_OPENTOFU_QUALITY_GATES_REFERENCE_001`,
  referenced here, never restated.

## The gate execution environment

The static gates prove the **committed form** of every root, never the working
directory's execution residue: the engine executes every per-root gate against
a clean staging of the root's tracked files — an isolated copy that never
carries `.terraform/`, `*.tfstate`, `*.tfvars`, or any other execution
residue. A gate that reads execution residue proves nothing about the
committed form and is a governance finding, never a valid pass and never a
valid failure. This execution environment is a property of the static gate
layer itself and is provided uniformly by the orchestrator's pack execution;
it is not a per-pack option.

Every gate also executes with a controlled environment: exactly the
descriptor's declared `environment` map over the engine's governed baseline —
never the operator process's uncontrolled inheritance, which would make the
gate outcome depend on the ambient machine state. The engine binds the
governed artifact-cache surface for the pack's cache-capable tool (the
OpenTofu plugin cache), so a per-root gate sequence downloads each bound
provider artifact once, and every gate failure surfaces the bounded captured
output of the failed step, never a bare exit code. These mechanisms are owned
by the capability-pack contract and the Go quality-authority contract,
referenced here, never restated.

## The engine machinery binding

Both pack majors declare `minEngineVersion`: the minimum engine version whose
machinery the pack's declared gates require, including the execution
environment they assume (the clean staging of every root's tracked files and
the controlled gate environment). A tenant whose pinned engine predates the
declared level — or whose pinned engine carries no compatibility proof entry
for the pack major — fails closed at gate-plan resolution: the pack's
declared form never degrades into a local re-implementation on an older
engine and never executes unproven on a newer one. The field form is owned by
the pack descriptor schema in this kernel; the resolution mechanics and the
release-proven compatibility register are owned by the Go quality-authority
contract — both referenced, never restated.

## The value-evaluation duty and the static guard

Every custom condition — every variable `validation` block, every
`precondition` and `postcondition`, and every `check` assertion — must be
proven with concrete values before it may merge. The canonical proof is the
`opentofu-test` gate: rejection paths through `expect_failures`, acceptance
paths through assertions, executed offline in plan mode. The test files live
with the code: a root that declares custom conditions carries its behavioral
proof files in the same repository — the pack executes them, it does not
author them.

A root whose encryption block resolves a key reference at initialization
cannot initialize offline. For those roots the always-on proof is the
static evaluation-safety guard — a deterministic check that every
custom-condition body is evaluation-safe against the declared variable
types — and their behavioral proof is executed in the governed window where
the key is reachable, never skipped. The guard is additionally the
belt-and-suspenders form for every other root.

## Usage

A tenant declares the pack at its pinned major and nothing else changes:

```json
{
  "schemaVersion": 4,
  "toolchain": { "language": "go", "version": "1.26.6" },
  "extends": ["opentofu@2"]
}
```

A tenant flips its pinned major through a reviewed change once the
orchestrator's pack execution supports the major's gate semantics; a flip to
`opentofu@2` before that support lands is a fail-closed finding, never a
silent skip.

The reusable CI payload stays constant; the orchestrator provisions the tool
from the recipe and composes the pack gates after the built-in core and before
the project gates. A declared-but-unknown reference is a fail-closed finding,
never a silent skip.

## Verification

`go run -mod=readonly ./cmd/check-conformance` proves the positive and
negative vectors under `conformance/` and validates the shipped descriptors
`v1/pack.json` and `v2/pack.json` against the executable `capability-pack/v1`
validator.
