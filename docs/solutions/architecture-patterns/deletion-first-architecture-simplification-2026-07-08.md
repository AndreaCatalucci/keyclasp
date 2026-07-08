---
title: Deletion-First Architecture Simplification for Agent-Native Projects
date: 2026-07-08
category: docs/solutions/architecture-patterns/
module: architecture
problem_type: architecture_pattern
component: development_workflow
severity: medium
applies_when:
  - "A project's product surface has expanded beyond its strongest architectural seam"
  - "Commercial, web, enterprise, or distribution packages obscure a local/embedded core"
  - "Agent-native audit scores are misleadingly low because too many modules pretend to be core"
  - "Stale docs, dependencies, or public exports contradict the current product"
  - "Adding tools or features before shrinking the surface would harden accidental interfaces"
tags:
  - agent-native
  - simplification
  - architecture-audit
  - deletion-first
  - document-review
  - plan-review
  - workspace
---

# Deletion-First Architecture Simplification for Agent-Native Projects

## Context

Keyblind (TypeScript MCP secrets vault, AES-256-GCM encrypted SQLite, MCP stdio server) accumulated a sprawling product surface around a strong local vault kernel. An agent-native architecture audit (8 principles, 8 parallel subagents) revealed that the repository still carried web, dashboard, enterprise, commercial, and distribution packages even after the runtime licensing system was removed. The audit gap—essential MCP context injection and surviving-core parity—was blocked by too many modules pretending to be core.

The solution was a full-cycle deletion-first workflow: audit, brainstorm, plan, parallel-review, and strengthen, producing a 7-unit implementation plan that sequences
commercial residue cleanup → dashboard/REST/HTTPS removal → team/SSO/deadman cuts → distribution surface classification → optional domain decisions → MCP context injection → surviving-core parity. Seven parallel document-review agents (coherence, feasibility, product lens, security lens, scope guardian, design/discovery lens, adversarial) reviewed the plan before a single line of code was changed, surfacing cross-cutting concerns that led to 4 pre-implementation decision gates and hardened plan sections.

## Guidance

The deletion-first pattern has five phases:

1. **Agent-native architecture audit.** Enumerate gaps against current code, not against the docstring or the intent. Count MCP tools, REST routes, CLI commands, public exports, package dependencies, stale docs. Distinguish core strengths (the vault kernel seam) from overextension (dashboard, enterprise, commercial, distribution). Produce specific numeric scores.

2. **Brainstorm and requirements.** Frame the problem, map actors and flows, produce solution directions with tradeoff tables (e.g., cut to one product, split packages, keep but re-architect, deepen agent interface). Write acceptance examples that tie to requirements. The requirements document becomes the origin the plan traces.

3. **Plan with deletion-before-parity sequencing.** Structure implementation units so non-core surfaces are cut before new capabilities are added to the surviving surface. Each unit names exact files to modify or delete, test scenarios, verification grep targets, and dependency order. Record every deletion candidate path so a downstream implementation agent never invents product direction.

4. **Parallel document review.** Dispatch specialist reviewers (coherence, feasibility, product, security, scope, design/discovery, adversarial) against both the requirements and plan documents simultaneously. Merge findings: auto-apply safe fixes; promote gated/manual findings into decision gates, strengthened verification, and scope boundary adjustments. Security-lens and adversarial-lens findings at this stage are higher-signal than after-the-fact code review.

5. **Strengthen from review.** Translate reviewer findings into concrete plan additions before implementation:
- **Pre-implementation decision gates** for unresolved product choices (e.g., HTTP transport disposition, team vault fate, public API contract, secret-value handling promise).
- **Data-disposition rules** for prefixed vault/database records whose owning feature is being deleted (purge, export, archive, or documented manual cleanup with denylist tests).
- **Safe-projection boundaries** for MCP context resources (redacted audit summary, no raw secret names, no client info; use action counts and time buckets instead of raw getAuditLog output).
- **Corrected invariants** where the prior claim was aspirational rather than accurate (e.g., current MCP resolve_secret returns plaintext through MCP responses; the plan must either redesign injection out-of-band or update the product promise).

## Why This Matters

**Without deletion-first:** The agent-native scores remain misleading. Missing CRUD/parity is partly a real gap and partly a signal that too many modules are pretending to be core. Adding tools for features that should leave core wastes implementation and review effort on interfaces that will disappear.

**Without parallel review:** Cross-cutting concerns surface late. A feasibility reviewer finds ACME dependency residue that a deletion unit omitted; a security reviewer finds that stale secret-bearing records survive module deletion because no data-disposition step was planned; an adversarial reviewer finds that public exports are being cut without defining the stable core boundary promised to future extension authors. Catching these in the plan phase costs a document edit; catching them after implementation costs rework, rollback, or stale data.

**Without explicit gates:** Implementation agents make product decisions ad hoc inside deletion PRs. The HTTP transport disposition, team vault fate, and secret-value handling promise get decided by the first implementer who encounters the ambiguity rather than by deliberate product choice.

## When to Apply

- The project has a strong core seam (vault kernel, protocol server, storage engine) that is diluted by adjacent products.
- An agent-native audit shows low CRUD/parity/context scores that are partly artifacts of module sprawl.
- Stale commercial, paid-tier, or launch artifacts still exist in docs, dependencies, or public exports after the runtime feature was removed.
- The cost of adding another MCP tool or CLI command exceeds the cost of deleting three unused ones.
- Multiple independent product/distribution decisions are bundled into a single cleanup PR without explicit rationale.

Do not apply deletion-first when the core seam itself is weak—narrow the product identity first, then audit and cut.

## Examples

### Solution direction comparison (brainstorm phase)

| Direction | Tradeoff | Best when |
|-----------|----------|-----------|
| **Cut to one product** — delete dashboard/REST/HTTPS/pairing, SSO, deadman, extensions | Biggest complexity reduction; easy to explain and test | Identity is "blind AI to your keys" |
| **Split products** — move dashboard/extensions outside core, keep core as library/CLI/MCP package | Preserves experiments without distorting core | Some adjacent products have real users |
| **Keep dashboard, make it agent-native** — add event propagation, parity, auth | Highest cost; keeps REST/HTTP/HTTPS in scope | Dashboard is a committed product promise |
| **Deepen agent interface first** — add MCP context, safety metadata, parity tests | Directly addresses weakest gaps | Core boundary is already narrow enough |

The brainstorm produced 12 requirements (R1–R12) across product boundary, agent-native core, and cleanup/deletion groups, with 4 acceptance examples (AE1-AE4) tracing back to requirements.

### Pre-implementation decision gates (strengthened from review)

Four gates were added to the plan after parallel document review:

- **G1. HTTP transport disposition:** Remove HTTP entirely, or keep a minimal MCP-only HTTP transport bound to loopback with explicit non-loopback opt-in and session/auth gating.
- **G2. Team vault disposition:** Delete team vaults with SSO, move out, or retain as an open local-collaboration feature with a separate parity/data-migration plan.
- **G3. Public API contract:** Define whether future extensions integrate through package exports, MCP stdio, or both; add export-shape tests.
- **G4. Secret-value handling promise:** Decide whether secret resolution remains plaintext MCP response content or moves to out-of-band injection; update docs so the product promise is precise.

### Verification grep patterns (plan U2 example)

After deleting dashboard/REST/HTTPS/pairing from core, the plan's verification step specifies that grep must show zero hits for: `dashboard-login`, pairing token, dashboard REST `/api/*`, `app.keyblind.dev`, web-dashboard promise, `start --http`, `start --https`, `acme-client`, or dashboard-specific HTTP route residue.

### Safe audit projection (plan U6 example)

Rather than reusing raw `getAuditLog` output for MCP context resources, the plan defines a safe audit projection: action counts, coarse time buckets, and warning flags without raw `secretName` or `clientInfo` by default. A security-lens reviewer flagged that raw audit output would leak sensitive secret names and session metadata into automatically-surfaced agent context.

## Related

- [docs/brainstorms/2026-07-08-agent-native-core-simplification-requirements.md](../brainstorms/2026-07-08-agent-native-core-simplification-requirements.md) — origin requirements document
- [docs/plans/2026-07-08-agent-native-core-simplification-plan.md](../plans/2026-07-08-agent-native-core-simplification-plan.md) — implementation plan
- [docs/solutions/tooling-decisions/node-26-compatibility-upgrade-2026-07-08.md](../solutions/tooling-decisions/node-26-compatibility-upgrade-2026-07-08.md) — prior institutional learning on dependency cleanup process
- `skill://ce-agent-native-architecture` — agent-native principles used in the audit
- `skill://ce-brainstorm` — brainstorm workflow used for requirements
- `skill://ce-plan` — planning workflow producing the 7-unit plan
- `skill://ce-doc-review` — document-review workflow used for the 7-agent review pass