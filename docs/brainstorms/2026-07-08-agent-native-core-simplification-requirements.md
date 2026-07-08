---
date: 2026-07-08
topic: agent-native-core-simplification
---

# Agent-Native Core Simplification

## Summary

Keyblind should become a smaller, more agent-native local secrets product: encrypted local vault, MCP stdio server, safe `.env` sandbox/restore, runtime secret resolution, local configuration, and boring diagnostics. Commercial licensing was removed from the runtime core, but the repository still carries web, dashboard, enterprise, and distribution surfaces that obscure the product boundary and keep agent-native gaps harder to fix.

---

## Problem Frame

Keyblind's strongest architectural seam is the local vault kernel: AES-256-GCM encrypted SQLite storage, key/session handling, audit logging, secret CRUD, and MCP access. That seam is deep enough to be useful to agents and boring enough for maintainers to trust.

The repo around it has grown faster than the seam can support. The current checkout still has a dashboard/REST backend, HTTP/HTTPS transport, pairing/JWT auth, SSO, team vaults, dead man's switch, browser/editor extensions, Terraform scaffolding, and commercial/deployment residue. These are not equally bad, but they all widen the product surface before the core agent loop has dynamic context, safety modes, or complete parity for surviving core workflows.

The immediate pain is not that every feature is broken. The pain is that each adjacent feature adds a new interface path, state concept, or user promise. That makes agents ask poorer questions, users see stale or conflicting docs, and future implementers treat incidental modules as product commitments.

---

## Actors

- A1. Local developer: installs Keyblind, stores secrets, sandboxes `.env`, and expects no network, no telemetry, and low cognitive load.
- A2. AI coding agent: uses MCP tools to resolve/store/list/delete secrets and operate safely without reading plaintext secrets into chat.
- A3. Maintainer: reviews changes, chooses product boundaries, and needs a core that is testable without commercial/web/enterprise scaffolding.
- A4. Future extension author: may build dashboards, extensions, or providers, but should depend on an explicit stable core rather than implicit internals.

---

## Key Flows

- F1. Local agent secret resolution
  - **Trigger:** A2 needs a secret during a coding session.
  - **Actors:** A1, A2
  - **Steps:** A1 initializes/stores secrets locally; A2 calls MCP; Keyblind resolves the value just in time; audit state records access; the implementation must define whether the value is injected out-of-band or intentionally returned through MCP.
  - **Outcome:** A2 can complete the task without reading `.env` plaintext, and the product promise around transcript exposure is accurate rather than assumed.
  - **Covered by:** R1, R2, R6, R8

- F2. Safe `.env` work session
  - **Trigger:** A1 wants an AI agent to work in a repo with `.env` files.
  - **Actors:** A1, A2
  - **Steps:** A1 stores or imports values; Keyblind replaces `.env` values with deterministic fakes; A2 reads fake values only; A1 restores real values when needed.
  - **Outcome:** Git diffs stay stable and AI-visible files contain non-secret placeholders.
  - **Covered by:** R1, R2, R6, R9

- F3. Core boundary maintenance
  - **Trigger:** A3 reviews a feature or cleanup PR.
  - **Actors:** A3, A4
  - **Steps:** The PR is checked against the product boundary; non-core surfaces are deleted, moved, or explicitly justified; public exports, CLI help, docs, and tests stay aligned.
  - **Outcome:** The repository does not accumulate second products by accident.
  - **Covered by:** R3, R4, R5, R10, R11

- F4. Agent capability discovery
  - **Trigger:** A2 or A1 needs to know what Keyblind can do in the current state.
  - **Actors:** A1, A2
  - **Steps:** Agent reads MCP resource/status/capability context; unavailable or dangerous actions are annotated; docs mirror the actual shipped surface.
  - **Outcome:** Agents do not infer stale license/dashboard/team behavior, and users discover real capabilities.
  - **Covered by:** R7, R8, R12

---

## Architecture Findings

**Observed core strengths**

- The core local MCP server exposes 22 MCP tools in `src/server.ts`.
- The vault kernel is concentrated in `src/vault.ts` and owns encryption, SQLite persistence, key derivation, audit log, expiry metadata, and key/vault consistency verification.
- The local secret CRUD loop has strong locality: `storeSecret`, `resolveSecret`, `listSecrets`, and `deleteSecret` live in the vault module and are directly surfaced to MCP.
- The `.env` sandbox flow is product-relevant: deterministic fake values reduce transcript leakage and preserve stable diffs.
- The recent key/vault mismatch hardening moved an important invariant into `src/vault.ts`: a key file must match the encrypted vault before callers trust it.

**Observed overextension**

- `src/server.ts` is still both an MCP server and a REST/dashboard backend. It imports `StreamableHTTPServerTransport`, `http`, HTTPS helpers, pairing support, dashboard auth support, and handles `/api/*` routes after the MCP tool definitions.
- `src/cli.ts` is 1,392 lines and exposes many more commands than the agent-facing MCP surface, including dashboard/HTTP/HTTPS, team, SSO, deadman, sync, import/export, config, and history flows.
- `package.json` still depends on non-core deployment/commercial packages that are not part of the local MCP vault kernel.
- A license-delivery webhook still exists and should not be part of the core repo.
- `dashboard/` still exists and contains ~1,735 TypeScript/TSX LOC, while MCP mutations do not have a push path into dashboard state.
- `src/index.ts` still publicly exports team, deadman, HTTPS, SSO, pairing, alerts, sync, share, and TOTP APIs, which makes them look like stable core surface.
- Docs still contain stale paid/commercial references: `docs/commands.md` has `Team Vaults (Pro/Team)` and `License`; `docs/faq.md` documents Ed25519 license keys and Pro/Team tiers; `docs/security.md` documents license validation; `docs/recipes.md` references `KEYBLIND_LICENSE`; `docs/editors.md` says biometric sessions require Pro or Team.

**Agent-native audit synthesis after licensing removal**

- Action parity improved because fake paid-tier actions disappeared, but CLI/domain actions still exceed MCP coverage.
- Tools-as-primitives improved because `store_secret` no longer gates on commercial secret limits, but several domain tools remain workflows (`sandbox_env`, `unsandbox_env`, `team_pull`, `create_share_link`). Some of those workflows may be acceptable stable domain operations.
- Context injection remains the weakest area: no observed MCP resources/prompts expose vault status, config status, backend status, recent activity, warnings, or capability metadata.
- Shared workspace is strong for storage locality: CLI and MCP operate over the same vault files. Safety scoping is weak: MCP has broad access without read-only, namespace, or destructive-operation annotations.
- CRUD completeness remains low if every module is treated as core. This should be fixed by deleting or moving non-core domains first, not by adding tools for features that should not survive.
- UI integration remains poor if the dashboard survives: REST/dashboard pages are snapshots and do not observe MCP mutations through SSE, WebSocket, polling, or a shared event bus.
- Capability discovery is decent in static docs and CLI help, but stale paid-feature docs pollute discovery and there is no runtime capability resource for agents.
- Prompt-native features improved with licensing removal, but code-defined product policy still exists in team, SSO, deadman, dashboard pairing, share TTL semantics, sync bundle behavior, and sandbox workflows.
- Security/product-promise tension remains: current MCP secret-resolution tools return decrypted values in MCP responses, so the docs and architecture must either redesign runtime injection out-of-band or explicitly narrow the \"plaintext never appears in transcript\" promise.

---

## Brainstormed Solution Directions

**Direction A — Cut to one product: local agent-safe `.env` replacement**

Delete dashboard/REST/HTTPS/pairing, commercial webhook/deployment residue, SSO, deadman, and duplicate extension/provider packages from the core repo. Keep only the local vault, MCP stdio server, sandbox/unsandbox, config, backends, doctor, setup-mcp, hook/watch, and minimal CLI adapter.

- **Upside:** Biggest complexity reduction. Makes the product easy to explain, test, and trust.
- **Downside:** Removes surfaces that might become marketing/demo assets.
- **Best when:** Keyblind's identity is "blind AI to your keys" rather than a general secret-management suite.

**Direction B — Split products, keep optional surfaces outside core**

Move dashboard, extension/provider packages, commercial webhook, SSO/team/deadman experiments, and remote HTTPS transport into separate packages or branches. Keep core as a published library/CLI/MCP package with explicit API boundaries.

- **Upside:** Preserves experiments without letting them distort the core package.
- **Downside:** More repo/package management; still requires strong boundary discipline.
- **Best when:** Some adjacent products have real users or launch value but should not be loaded into every local CLI install.

**Direction C — Keep dashboard, make it agent-native**

If dashboard is a committed product, stop treating it as incidental REST UI. Add event propagation from vault mutations to dashboard state, align dashboard actions with MCP tools, and define dashboard auth/pairing as a real product surface.

- **Upside:** Better user-facing UI and demo path.
- **Downside:** Highest implementation cost; keeps REST/HTTP/HTTPS/pairing in scope.
- **Best when:** Web dashboard is part of the product promise, not just a launch artifact.

**Direction D — Deepen the agent interface before adding features**

Add MCP resources/status surfaces, tool annotations, safety modes, and parity tests for the surviving core. Avoid adding MCP tools for modules that may be deleted.

- **Upside:** Directly addresses the weakest agent-native gaps.
- **Downside:** Does not by itself reduce product sprawl; must follow or accompany cuts.
- **Best when:** Core boundary is already narrowed enough that parity work will not be wasted.

---

## Requirements

**Product boundary**

- R1. Keyblind's core product must remain a local encrypted secrets vault for AI agents, centered on MCP runtime resolution and safe `.env` sandbox/restore.
- R2. The core must preserve zero-network, zero-telemetry operation for normal local use.
- R3. Non-core surfaces must be deleted, moved, or explicitly justified before adding parity or context work for them.
- R4. Commercial/premium/product-tier behavior must not influence vault runtime behavior, local CLI behavior, MCP tool availability, or local docs unless a future commercial product boundary is explicitly reintroduced outside the core.
- R5. Public exports, CLI help, docs, tests, and package dependencies must match the actual surviving product surface.

**Agent-native core**

- R6. Surviving core user actions must have equivalent MCP capabilities or a documented reason they are intentionally human-only.
- R7. MCP must expose runtime context for agents: vault initialized state, project name, backend, secret count or safe summary, sandbox backup summary, recent audit summary, warnings, and capability metadata.
- R8. MCP tools must expose safety semantics through names, descriptions, annotations, or resources: read-only vs destructive, idempotent vs state-changing, secret-sensitive inputs, and session/auth requirements.
- R9. Sandbox/unsandbox may remain workflow-shaped only if the product treats `.env` protection as a first-class domain operation rather than generic file editing.

**Cleanup and deletion decisions**

- R10. Dashboard/REST/HTTPS/pairing must be either removed from the core package or promoted to a committed product surface with event propagation and parity tests.
- R11. Team vaults, SSO, and dead man's switch must be either deleted/moved or justified as core user problems independent of paid tiers.
- R12. Stale license, Pro/Team, commercial delivery, activation, and dashboard-login docs must be removed or rewritten to match the current product.

---

## Acceptance Examples

- AE1. **Covers R3, R5, R12.** Given the runtime licensing system has been removed, when a maintainer searches docs and source for activation/pricing/license-delivery behavior, only MIT/license/legal context and intentionally retained launch/archive material remain.
- AE2. **Covers R6, R7, R8.** Given an agent connects over MCP, when it asks what it can safely do, it can discover initialized state, backend/config state, available capabilities, and destructive/read-only semantics without probing by failure.
- AE3. **Covers R10.** Given a secret is changed through MCP, if dashboard remains in core, then the dashboard updates through an explicit propagation mechanism rather than waiting for manual refresh; if dashboard is removed, no stale UI promise remains.
- AE4. **Covers R11.** Given team vaults/SSO/deadman are still present in the package, when a maintainer reads the product docs, each has a current core-product justification and matching MCP/CLI/docs/test coverage; otherwise they are absent from core.

---

## Success Criteria

- The root package can be explained as one product in one sentence: local encrypted vault + MCP stdio + safe `.env` sandbox/restore for agents.
- A downstream planning/implementation agent can identify deletion candidates, keep candidates, and follow-up agent-native improvements without inventing product direction.
- Stale commercial and paid-tier artifacts no longer contradict the MIT/free/unlimited local-product story.
- Core parity and context work is sequenced after deletion decisions so the team does not add tools for features that should be cut.
- Maintainers can run targeted tests/builds without unrelated dashboard/commercial infrastructure affecting the core path.

---

## Scope Boundaries

- Do not reintroduce licensing, pricing, paid-tier gates, commercial delivery paths, hosted deployment paths, or dashboard activation as part of the local core.
- Do not add parity tools for every current module before deciding whether that module survives.
- Do not turn Keyblind into a generic password manager, enterprise identity product, web dashboard product, or editor-extension suite in the core package.
- Do not weaken encryption, key/vault mismatch checks, machine-identity binding, audit logging, or sandbox determinism for simplicity.
- Do not delete MIT license/legal references.
- Do not remove TOTP/share/sync/backends blindly; classify them by product identity and agent utility first.

---

## Key Decisions

- Start with subtraction, not more tools: The low CRUD/parity scores are partly artifacts of too many modules being treated as core.
- Keep the vault kernel deep: encryption, key derivation, SQLite storage, audit log, expiry metadata, and key/vault consistency belong in `src/vault.ts` or similarly deep core modules.
- Prefer MCP stdio as the core server boundary: HTTP/REST/HTTPS exists mainly for dashboard/remote use and should not be loaded into the local default path.
- Treat `.env` sandbox/unsandbox as domain operations: they are workflows, but they directly serve the product promise and should not be decomposed into generic file-editing primitives unless Keyblind's product identity changes.
- Add runtime context after product cuts: context resources are highest leverage once the surviving surface is known.


> 📚 **Institutional learning:** [deletion-first-architecture-simplification-2026-07-08.md](../solutions/architecture-patterns/deletion-first-architecture-simplification-2026-07-08.md) documents the full workflow that produced this requirements document and the resulting implementation plan.

## Dependencies / Assumptions

- The current strategic direction favors a smaller local agent-safe product over preserving every launch/demo surface.
- The current checkout after `origin/main` includes licensing removal in runtime source, but still includes commercial residue in package dependencies, webhook code, and docs.
- The untracked `.worktrees/` directory is local workspace scaffolding and not part of the product surface.
- No current evidence shows dashboard event propagation from MCP mutations; if dashboard survives, this must be re-verified during planning.

---

## Outstanding Questions

### Resolve Before Planning

None. The planning path can proceed with a deletion-first recommendation and classify ambiguous surfaces during implementation planning.

### Deferred to Planning

- [Affects R10][Technical] If dashboard is removed, should `start --http` be removed entirely or kept only as Streamable HTTP MCP transport without REST routes?
- [Affects R11][Product/technical] Should team vaults be deleted with SSO, moved out, or retained as an open local collaboration feature?
- [Affects R9][Product] Should TOTP and share remain core-adjacent because they help agents complete login and handoff flows, or move out with other secondary domains?
- [Affects R7][Technical] Should runtime context be exposed as MCP resources, status tools, or both for client compatibility?
