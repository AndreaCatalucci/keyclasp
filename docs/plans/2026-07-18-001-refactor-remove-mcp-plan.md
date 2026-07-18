---
title: Remove MCP From Keyclasp - Plan
type: refactor
date: 2026-07-18
artifact_contract: ce-unified-plan/v1
artifact_readiness: implementation-ready
product_contract_source: ce-plan-bootstrap
execution: code
---

# Remove MCP From Keyclasp - Plan

## Goal Capsule

- **Objective:** Remove the MCP server and every supporting product surface in one breaking change, leaving Keyclasp as a local CLI for encrypted storage, deterministic `.env` sandboxing, and guarded process injection.
- **Source:** Internal product-direction decision from the repository owner.
- **Input:** The current TypeScript package, CLI, tests, package metadata, website, bundled skill, and documentation.
- **Operation:** Delete the protocol boundary and its orphaned authentication/audit machinery, then align tests and published surfaces around the CLI-only product.
- **Outcome:** The package builds and tests without the MCP SDK; removed commands and exports are absent; live documentation contains no MCP setup or capability claims.
- **Execution profile:** Standard, destructive refactor across package, CLI, vault, tests, and published documentation.
- **Stop condition:** Stop if removal requires changing the encrypted secret-value format or deleting user secrets. Command, API, and documentation compatibility are explicitly not stop conditions.

---

## Product Contract

### Summary

Keyclasp will become a smaller CLI-first product centered on encrypted storage, agent-safe project files, and guarded command execution.

### Problem Frame

The MCP boundary returns plaintext to its client, weakening the product promise while adding a server, setup automation, dependency, public API, tests, editor docs, and biometric machinery. Compatibility would preserve the complexity this change removes.

### Requirements

**Runtime and package boundary**

- R1. Delete the MCP server, setup automation, SDK dependency, bundled MCP-oriented skill, package metadata, public exports, and protocol-specific tests.
- R2. Remove `keyclasp start`, `keyclasp setup-mcp`, their flags, completions, help text, generated configuration, and all aliases or shims for those commands.
- R3. Delete `keyclasp unlock`, exported biometric/session APIs, and unreachable per-secret-access machinery as intentional breaking removals; do not redesign them as CLI features.
- R4. Remove MCP-only audit client metadata while preserving the audit log's secret name, action, and timestamp behavior.

**Product surface**

- R5. Keep vault, backend, sandbox/unsandbox, guarded `keyclasp run`, aliases, TOTP, sharing, sync/history, doctor, hook/watch, completions, and their current CLI behavior.
- R6. Publish the removal as version `0.7.0` with no deprecation period, compatibility package, migration shim, or retained stale documentation; the GitHub/npm release notice must name the removed commands, integrations, exports, and the surviving sandbox/run workflow.

### Acceptance Examples

- AE1. Given a clean install, when the user runs `keyclasp start` or `keyclasp setup-mcp`, then the CLI follows the normal unknown-command path and no compatibility message or hidden server starts.
- AE2. Given an existing vault containing audit rows with legacy `client_info` data, when the updated CLI lists audit activity, then the supported fields still render and the unused legacy column does not require a data migration.
- AE3. Given the packaged output, when dependencies, exports, commands, skills, and live docs are inspected, then the only MCP reference permitted is this retained decision plan.

### Scope Boundaries

- Do not preserve compatibility.
- Do not introduce a replacement agent protocol, daemon, editor extension, or direct secret-to-model interface.
- Do not change encryption, vault paths, secret record format, backends, or guarded command semantics.
- Do not migrate old audit tables merely to drop an extra column; new code reads only the surviving fields.

---

## Planning Contract

### Key Technical Decisions

- KTD1. **One atomic deletion.** Runtime, CLI, package, tests, documentation, and the `0.7.0` version change land together so no intermediate release advertises or imports a missing server.
- KTD2. **Delete orphaned biometrics.** `src/auth.ts` and the vault session/per-access gates exist to protect the long-lived server process. Removing them is simpler than inventing a new CLI contract.
- KTD3. **Tolerate legacy audit schema.** Remove `setClientInfo` and `clientInfo` from code and public types, but select named surviving columns so existing SQLite tables with an extra column continue working incidentally.
- KTD4. **CLI-only product identity.** `keyclasp sandbox` and `keyclasp run` are the coding-agent integration boundary. Documentation teaches names, fake values, and guarded processes rather than direct secret resolution by an agent.

### Sequencing

Implement U1 and U2 as one working-tree change before running tests; the CLI cannot compile between server deletion and import cleanup. Complete U3 after the code and package surface are stable, then run the final repository audit.

### System-Wide Impact

This breaks installed editor configurations, server/setup/biometric/session imports, and scripts invoking `start`, `setup-mcp`, or `unlock`. Existing vaults and remaining CLI commands stay in place. No long-lived local process remains.

---

## Implementation Units

### U1. Delete the protocol and package boundary

- **Goal:** Remove every executable, installable, and importable MCP surface. Covers R1, R2, and R6.
- **Files:** Delete `src/server.ts`, `src/setup-mcp.ts`, `tests/server.test.ts`, `manifest.json`, `glama.json`, and `server.json`; modify `src/cli.ts`, `src/completions.ts`, `src/index.ts`, `package.json`, `package-lock.json`, `.gitignore`, `tests/version.test.ts`, and `tests/vault.test.ts`.
- **Patterns:** Follow the deletion-first cuts already visible in git history: remove imports, command branches, exports, tests, dependency entries, and help/completion text in the same change.
- **Approach:** Remove server/setup imports and CLI cases, delete start-only flags, remove exported setup/server symbols, delete registry manifests, remove the bundled `skills` package entry, drop the obsolete `.mcp.json` ignore entry, `mcpName`, protocol keywords, `@modelcontextprotocol/sdk`, and `zod`, set the package version to `0.7.0`, then regenerate the lockfile through npm rather than hand-editing dependency nodes.
- **Test scenarios:** Build has no missing imports; help/completions omit removed commands; old invocations use the unknown-command path; exports omit server/setup symbols; alias behavior removed with server tests remains covered elsewhere.
- **Verification:** `npm run build`; focused version, vault, completion, and CLI tests; `rg -n '@modelcontextprotocol|setup-mcp|createServer|startServer|McpServer|StdioServerTransport|"zod"' src tests package.json package-lock.json` returns no hits.

### U2. Remove orphaned authentication and audit state

- **Goal:** Delete machinery whose only enabling path was the server while preserving ordinary vault and audit behavior. Covers R3-R5 and AE2.
- **Files:** Delete `src/auth.ts` and `tests/biometric-auth.test.ts`; modify `src/vault.ts`, `src/sync.ts`, `src/cli.ts`, `src/index.ts`, `src/completions.ts`, `tests/integration.test.ts`, and affected vault/sync tests discovered during implementation.
- **Patterns:** Keep the vault module deep: remove global mode flags and unreachable branches instead of replacing them with adapters.
- **Approach:** Remove biometric imports, session flags, `requireSecretAccess`, the `unlock` command, and auth exports. Remove client-info mutation and return fields from audit APIs while querying only `secret_name`, `action`, and `created_at`; leave existing tables with extra columns readable.
- **Test scenarios:** Secret get/history/rollback work without auth globals; a fresh vault creates `audit_log` without `client_info`; existing databases with the old extra column remain readable; audit rows still record and render actions; help and completions omit unlock and biometric flags.
- **Verification:** Focused vault, sync, integration, and CLI tests pass; `rg -n 'auth\.js|biometric|setRequireSession|setRequireBiometric|requireSecretAccess|setClientInfo|clientInfo' src tests` returns no product-code hits.

### U3. Finish the CLI-only product cut

- **Goal:** Ensure every shipped and maintained surface describes only the surviving product. Covers R5, R6, and AE3.
- **Files:** Modify `README.md`, `AGENTS.md`, `docs/*.md`, `index.html`, `privacy.html`, and remaining `demo/**`; delete `skills/keyclasp-agent/**`, `Dockerfile`, `docker-compose.yml`, obsolete protocol-specific docs, demos, plans, decisions, and solutions.
- **Patterns:** Use the rewritten README flow: explain the problem, secure setup, sandboxing, guarded execution, common workflows, and limitations before reference material.
- **Approach:** Remove editor/server configuration and direct agent-resolution claims, delete the server-only container deployment and current agent skill, replace website/demo copy and assets with sandbox/run workflows, and remove stale historical artifacts instead of annotating superseded architecture. Retain this plan as the decision record and exempt only its path from the final text audit. Document a future CLI-first agent skill as deferred; do not build it in this change. Publish a concise GitHub/npm release notice from R6 without retaining compatibility documentation in the product guides.
- **Test scenarios:** Every documentation link resolves; install and command examples use real surviving commands; no packaged or container entrypoint invokes `start`; local-vault claims are qualified separately from remote backends; the packed artifact contains no agent skill.
- **Verification:** Link/path inspection plus a case-insensitive MCP/reference grep over the repository excluding `.git`, `node_modules`, build output, and this plan returns no hits; `npm pack --dry-run` contains no removed server/setup files or stale docs.

---

## Verification Contract

| Gate | Command or evidence | Covers |
|---|---|---|
| Compile | `npm run build` | U1, U2 |
| Behavior | `npm test` | U1, U2 |
| Package | `npm pack --dry-run` and inspect file list | U1, U3 |
| Release identity | `package.json` and lockfile both report `0.7.0`; release notice covers R6 | U1, U3 |
| Dependency | `npm ls @modelcontextprotocol/sdk` reports absent | U1 |
| Removed surface | Repository grep patterns from U1-U3 return no hits except this plan | U1-U3 |
| Surviving workflow | `keyclasp init`, secure set, sandbox, guarded run, status, and list smoke flow in an isolated temporary vault | R5 |

---

## Definition of Done

- The project builds and all tests pass without the MCP SDK, server, setup automation, biometric server gates, or audit client metadata.
- Removed commands and public exports are absent with no compatibility behavior.
- The packed artifact and live documentation expose only the CLI-first product.
- Existing vault contents remain readable, and guarded execution plus sandbox workflows retain coverage.
