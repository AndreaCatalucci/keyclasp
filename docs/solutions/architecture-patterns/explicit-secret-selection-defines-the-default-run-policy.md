---
title: Explicit secret selection defines the default run policy
date: 2026-08-23
category: architecture-patterns
module: run authorization
problem_type: product_contract
component: security
severity: high
tags: [run, env, touch-id, authorization, unattended]
---

# Explicit secret selection defines the default run policy

## Invalidated assumption

The macOS hardware plan drifted from the shipped scoped-run behavior and began requiring Touch ID for every secret-bearing `run`. That made unattended agent use impossible and pushed the design toward biometric-bound key release, stored capabilities, and a broker before the product required them.

## Current contract

Portable and planned hardware modes share the selection boundary but differ when operator authorization is unavailable:

| Request | Current portable mode | Planned hardware mode | Effectively locked hardware request |
| --- | --- | --- | --- |
| One or more explicit `--env SOURCE[:TARGET]` mappings | No operator gate; the vault must already be usable | No Touch ID | Require Touch ID |
| No `--env`, meaning every secret in the resolved scope | Touch ID when available, otherwise interactive vault passphrase | Require Touch ID without passphrase fallback | Require Touch ID without passphrase fallback |
| Missing value, malformed mapping, duplicate target variable, or unresolved secret | Fail without spawning | Fail without spawning | Fail without spawning |

Human `get` and sensitive administrative operations keep their operator authorization. Authenticated `lock` and `unlock` rules now cover project-only, environment-only, exact-scope, and exact-secret selectors; documentation must use that implemented interface rather than inventing another flag or configuration key.

## Lesson

Explicit secret selection is a least-privilege scope boundary, not authentication against another process running as the same user. A same-user caller that knows a secret name can request it for a child command under the default policy. Public claims must state that boundary and that the authorized child receives a usable credential.

The native authority must enforce the distinction itself. Node may describe the request but cannot assert that it is authorized. An invalid explicit selection must never fall back to whole-scope injection. `--allow-unsafe` may change output protection only; it cannot change the authorization case.

Hardware custody and user-presence policy are separate requirements. Device binding must make copied vault material unusable on another Mac without forcing a Touch ID prompt for every effectively unlocked named run. In hardware mode, broad and effectively locked requests complete Touch ID before decryption or child launch.

The mode boundary follows the same separation. Passphrase and machine modes are software implementations; hardware mode is an optional implementation selected explicitly. They conform to shared command-level interfaces for scope, command metadata, and status. They do not share key-custody or decryption code, and the common interface exposes no generic decrypt, key-return, or plaintext-return operation. The CLI selects an implementation instead of spreading hardware conditionals across commands.

## Scope

This applies to `keyclasp run` in portable and planned hardware modes, with the fallback difference stated above. It does not make an approved child trustworthy, add protection from root or a compromised operating system, or define the future brokered-capability model.

Useful pointers:

- `src/run.ts`
- `src/runtime.ts`
- `src/software/runtime.ts`
- `src/hardware/status.ts`
- `src/biometric.ts`
- `docs/security.md`
- `docs/plans/2026-08-22-001-macos-hardware-beta-to-ga-plan.md`
- `docs/security-hardening-checklist.md`
