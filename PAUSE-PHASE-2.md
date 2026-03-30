# Pause/Unpause Phase 2: Testability + Readability Hardening Plan

This document proposes post-feature hardening work after `pause`/`unpause` delivery.

## Goals

1. Make core behavior easier to reason about and safer to change.
2. Increase confidence in user-visible output and status semantics.
3. Reduce test friction and duplication for future feature work.

---

## Workstream A — Refactor for clearer boundaries

### A1) Split large operations into pure planning + side-effect orchestration

**Scope**
- Refactor `seal_operation.go`, `unseal_operation.go`, and `list_operation.go`.
- Keep command entrypoint methods small and orchestration-focused.
- Move decision logic into pure helper functions with explicit inputs/outputs.

**Why**
- Easier to unit test behavior without filesystem/AWS setup.
- Reduces regression risk when adding new statuses or conditions.

**Acceptance**
- Each operation has clearly separated:
  - input normalization
  - decision/planning
  - side-effect execution

**Effort**: **L**

---

## Workstream B — Strengthen behavior-focused tests

### B1) Table-driven tests for list status matrix

**Scope**
- Add table tests covering combinations of:
  - secure present/missing
  - insecure present/missing
  - hash equal/mismatch
  - paused marker on/off

**Why**
- Status logic is easy to break with small changes.
- Table tests make expected behavior explicit and reviewable.

**Acceptance**
- One test table that validates all status + marker combinations.

**Effort**: **M**

### B2) Golden tests for CLI output stability

**Scope**
- Golden files (or inline snapshots) for representative outputs:
  - `list` lines with `PAUSED`
  - `pause`/`unpause` success and idempotent messages
  - selected usage errors

**Why**
- Prevent accidental output drift that breaks scripts/docs.

**Acceptance**
- Output-format regressions are caught by tests.

**Effort**: **M**

### B3) Integration idempotency checks for pause/unpause

**Scope**
- In both integration scripts, run:
  - `pause` twice
  - `unpause` twice
- Assert friendly messages + successful exit behavior.

**Why**
- Real operators repeat commands under uncertainty.

**Acceptance**
- Integration scripts verify idempotent operator flow.

**Effort**: **S**

---

## Workstream C — Improve test ergonomics

### C1) Introduce config fixture builder utilities

**Scope**
- Add test-only builder helpers for config creation, e.g.:
  - managed file with paused state
  - KMS enabled/disabled
  - bypass entries

**Why**
- Reduces repetitive literals and brittle setup in tests.

**Acceptance**
- New tests use builder for clarity; existing noisy setups gradually migrate.

**Effort**: **S-M**

### C2) Add integration preflight wrapper target

**Scope**
- Add `make test-integration` preflight checks:
  - required commands
  - sudo availability / tty expectations
  - AWS env checks for KMS workflow

**Why**
- Fewer confusing failures and faster contributor onboarding.

**Acceptance**
- Failing preconditions are surfaced before long workflow execution.

**Effort**: **M**

---

## Workstream D — Codify invariants and quality policy

### D1) Add invariants comments near planners

**Scope**
- Document non-obvious guarantees near plan builders, especially:
  - paused entries skipped during `unseal`
  - missing tracked insecure entries tolerated in `seal`
  - when config writes are/are not expected

**Why**
- Preserves intent across refactors and future contributors.

**Acceptance**
- Critical planner assumptions are stated in code comments.

**Effort**: **S**

### D2) Add targeted coverage gates for logic-heavy paths

**Scope**
- Add CI checks for selected packages/files rather than global blanket target.

**Why**
- Protects critical logic without incentivizing low-value test inflation.

**Acceptance**
- Coverage gate enforces minimum threshold for operation/planner modules.

**Effort**: **M**

---

## Suggested execution order

1. **B3** (integration idempotency) — quick safety win (**S**)
2. **D1** (planner invariants comments) — low effort/high clarity (**S**)
3. **C1** (test fixture builder) — enables cleaner future tests (**S-M**)
4. **B1** (status matrix table tests) — behavior confidence (**M**)
5. **B2** (golden output tests) — output stability (**M**)
6. **C2** (integration preflight target) — contributor UX (**M**)
7. **D2** (targeted coverage gates) — CI quality policy (**M**)
8. **A1** (deep operation refactor) — largest structural readability gain (**L**)

---

## Exit criteria for Phase 2

- Critical pause/unpause and list behaviors are covered by matrix/snapshot tests.
- Integration scripts validate idempotency and produce clearer preflight failures.
- Operation code has clearer separation between decision logic and side effects.
- Planner invariants are documented and protected by tests.
