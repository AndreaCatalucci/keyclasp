---
title: "release: software beta and optional macOS hardware mode"
type: delivery
status: planned
date: 2026-08-23
---

# release: software beta and optional macOS hardware mode

## Desired outcome

Ship a solid public beta without making the unfinished macOS hardware work a prerequisite:

1. Passphrase mode is deliberately portable with the passphrase.
2. Machine mode is the default for unattended local agents and provides software-derived machine binding, not hardware security.
3. Hardware mode is an additional mode that users explicitly configure on supported Macs after its own physical qualification.

Across every mode, a named `keyclasp run --env ...` is non-interactive by default. Omitting `--env` requests the whole scope and requires operator authorization. A project/environment strict setting requires Touch ID for named runs too. Explicit selection limits disclosure to the child; it does not authenticate the caller or defend against every process running as the same user.

Slice 3 is the public software-beta milestone. Slice 4 is an independent, optional hardware-beta milestone. Failure or deferral of Slice 4 must not weaken or block the software beta.

The detailed hardware evidence and eventual Developer ID/notarization work remain in [`2026-08-22-001-macos-hardware-beta-to-ga-plan.md`](./2026-08-22-001-macos-hardware-beta-to-ga-plan.md). This delivery map supersedes that plan's hardware-first release ordering.

## Relevant current codebase

- [`src/runtime.ts`](../../src/runtime.ts) defines the normalized command-level request and result shared by implementations.
- [`src/software/runtime.ts`](../../src/software/runtime.ts) implements passphrase and machine execution without exposing keys or plaintext through the shared contract.
- [`src/hardware/status.ts`](../../src/hardware/status.ts) is a status-only hardware adapter. It cannot enroll, recover, decrypt, or launch a secret-bearing child.
- [`src/cli.ts`](../../src/cli.ts) parses a run request once and delegates it through the software runtime.
- [`src/run.ts`](../../src/run.ts) selects secrets, builds the child environment, and launches without a shell.
- [`src/vault.ts`](../../src/vault.ts) stores AES-256-GCM ciphertext in SQLite and wraps the data key with a passphrase or the documented software machine mechanism.
- [`src/biometric.ts`](../../src/biometric.ts) performs the current macOS operator-authorization prompt.
- [`native/keyclasp-core/`](../../native/keyclasp-core/) contains a status-only public executable plus private hardware experiments. The tested ad-hoc permanent-Keychain path failed with `errSecMissingEntitlement`.
- [`tests/mode-boundary.test.ts`](../../tests/mode-boundary.test.ts) enforces that software and hardware implementations do not import one another and cannot bypass the shared boundary with dynamic loading.

The shared runtime seam and module boundary are already complete and verified. They are prerequisites to this map, not another delivery slice.

## Gap

The software product works, but it is not yet a defensible beta because request validation, ciphertext identity binding, authenticated strict policy, existing-file permission repair, disaster recovery, clean-package verification, and release evidence are incomplete.

The hardware product is further behind. The public native core is intentionally status-only; no physically qualified design yet provides device-bound custody, the corrected authorization policy, recovery, and child launch under the exact distributed code identity.

## Resolved decisions

- The first public beta contains passphrase and machine modes. It makes no Secure Enclave or hardware-custody claim.
- Machine mode is the default for unattended local use. Its machine binding is a convenience and theft-resistance layer, not a non-exportable hardware key.
- Strict authorization is stored per project/environment. No command-line flag or environment variable may weaken it.
- `keyclasp strict enable|disable --project P --environment E` is the smallest new policy surface. `keyclasp status` reports the effective policy without revealing secrets.
- Enabling or disabling strict mode requires operator authorization. On macOS, a strict named run requires Touch ID and fails closed if Touch ID is unavailable or cancelled; there is no passphrase fallback for that run.
- Whole-scope `run` continues to require operator authorization regardless of strict mode. Named `--env` runs do not prompt unless strict mode is enabled.
- Record-level authenticated encryption binding is a beta requirement. A separately anchored manifest or rollback counter remains a hardware-GA hardening item.
- Initial hardware support may be limited to Apple Silicon Macs with Touch ID. Intel/T2 support is deferred until separately tested.
- Hardware implementations reuse command-level interfaces, not the software vault or its cryptographic implementation. The native authority must own live key use, decryption, authorization, secret input, and child launch.

## Walking skeleton

The shortest end-to-end beta proof is:

1. Initialize a fresh software vault, store two secrets, and run a packed installation against one explicitly selected secret.
2. Prove an invalid or duplicate multi-secret request decrypts nothing and launches no child.
3. Prove ciphertext moved to another logical record fails authentication.
4. Enable strict mode for one project/environment, observe Touch ID on a named run, and observe Touch ID on every whole-scope run.
5. Back up, restore, upgrade, and run the same packed artifact on the supported clean-platform matrix.
6. Publish a tagged beta whose package contents, checksums, provenance, and limitations match the tested artifact.

The later hardware extension sends the same normalized request through the hardware implementation. The native authority launches the child with the selected secret while the Node process never receives the plaintext or vault key, and copying the hardware vault to a second Mac does not enable decryption.

## Slice 1: Make software storage and selection tamper-evident

**Status:** completed on 2026-08-23; reopened controller-review findings closed on 2026-08-24. Slice 2 has not started.

Deliver one secure named-run path whose complete request is accepted before any selected value is decrypted and whose ciphertext cannot be transplanted to another logical record.

### Implementation

- Parse and normalize every `--env` mapping before opening the vault.
- Validate the complete selection for malformed names, duplicate target variables, unresolved source names, and scope errors before decrypting any selected value. Query metadata when existence must be checked without decryption.
- Reject invalid secret values, such as environment NUL bytes, before launching the child; never widen an empty or failed selection to whole scope.
- Introduce a versioned vault format with a random vault identifier and stable record identifier.
- Bind AES-GCM ciphertext to the vault identifier, record identifier, project, environment, secret name, record kind, and format version through canonical associated data.
- Make rename decrypt and re-encrypt under the new identity in the existing atomic/locked operation rather than updating identity columns alone.
- Add a backup-first, locked migration from the current format. Record the new format before normal use so older binaries refuse it instead of corrupting it.
- Enforce and repair owner-only permissions on existing vault directories, database files, WAL/SHM files, key material, and backups. Fail closed when safe repair is impossible.
- Define deterministic behavior for missing, corrupt, partially migrated, mismatched, or concurrently opened vault state.

### Verification

- Unit and integration tests prove malformed, duplicate, and unresolved multi-secret selections cause zero decrypt calls and no child launch.
- Swap, replay-to-another-name, cross-scope, cross-vault, and metadata-tamper tests fail authentication.
- Migration tests cover interruption at every durable boundary, retry, old-binary refusal, backup restoration, rename, and concurrent access.
- Permission tests start from permissive existing directories and SQLite side files and verify repair or an actionable closed failure.
- Existing passphrase, machine, unsafe-override, child-exit, signal, and output-containment tests remain green.

### Acceptance

A packed local build can complete the walking skeleton through step 3, and no tested invalid request, identity transplant, migration interruption, or unsafe file mode yields plaintext or launches a child.

### Completed work

- Named-run mappings are normalized before vault access and validated as a complete set before unlock or decryption. Malformed names, duplicate targets, missing sources, disappeared sources, and NUL-bearing values fail without launching a child; invalid metadata selections cause zero decrypt calls.
- Vault format 2 assigns a random vault ID and stable random record IDs. Canonical AES-GCM associated data binds the format version, vault ID, record ID, project, environment, name, and record kind. An authenticated vault key check also rejects mismatched key files when the vault has no secret rows.
- Rename operations retain each record ID and decrypt/re-encrypt every moved value inside the existing `IMMEDIATE` transaction. Concurrent first writes also choose and use one record ID inside an `IMMEDIATE` transaction.
- Legacy conversion creates a consistent SQLite backup before any schema change, performs the conversion under a write lock, and records the new schema and format atomically. Missing, corrupt, partial, interrupted, restored, and concurrent states fail closed or retry deterministically. Current-schema constraints make older writers fail before inserting a row without record identity.
- Existing vault directories, keys, databases, SQLite side files, and backups are checked for symlinks and repaired to `0700`/`0600` on Unix. Hosts where owner-only ACLs cannot be verified currently fail closed.
- The reopened controller review is closed. The v4 key file anchors the vault ID and makes the frozen v3 open path refuse the format before SQLite access. Empty, rolled-back, foreign, missing, partially migrated, and atomically replaced live databases fail closed for both secret and metadata-only operations.
- Initialization is serialized with a process-lifetime SQLite advisory lock that is released on process exit. Migration publishes a pending v4 key only after its consistent backup is complete while an `IMMEDIATE` database write lock blocks competing writers, then publishes the active key after commit.
- A whole-scope run snapshots the selected secret names at request start and resolves that selection in one stable database snapshot. Removing a selected secret before resolution aborts the run; secrets added after request start are available to the next run. Malformed names, duplicate targets, NUL-bearing values, or disappeared sources never launch a subset child.
- Permission enforcement verifies the current owner and removes and rechecks macOS ACLs for the vault directory, live key and database, SQLite side files, database backups, and key backups. Snapshot entries that vanish during concurrent SQLite or key publication are tolerated only after their path is confirmed absent.

### Verification evidence

- `npm run build` passed.
- `npm test` passed: 18 files, 300 tests.
- `git diff --check` passed.
- Named regressions cover the frozen v3 binary path, fresh database replacement, atomic empty/foreign replacement under a live handle, metadata-only replacement access, forced concurrent initialization, process-lifetime lock release, a competing migration writer during backup, real batch resolution with a corrupt present record plus a missing source, per-file ownership, every macOS ACL path class, and permission-scan disappearance races.
- Independent correctness, simplicity, security, test, and concurrency reviews reran after the fixes and returned clean passes.
- `npm pack` produced `keyclasp-0.1.1.tgz` from the final working tree (`sha1 b145d18d3fa5be8b1182d381da6b4f6bb4300446`, 47 files). A clean offline temporary install stored two scoped secrets and injected only one named mapping. Duplicate-target and transplanted-ciphertext runs exited before their sentinel children launched.

### Remaining risks or blockers

- Windows vault use is intentionally blocked until Slice 3 defines and verifies an owner-only ACL implementation; Unix mode repair does not claim Windows ACL coverage.
- Migration interruption coverage uses deterministic faults at each durable boundary plus two-process contention and backup restoration. A real power-loss test remains part of the clean-platform release work.
- Direct in-place overwrite of an open database is unsupported. Slice 2 owns managed restore and serialization between restore and vault lifecycle operations.
- One intermediate parallel full-suite run transiently failed the existing single-secret delete integration test. Its isolated rerun and the final complete 300-test run passed; no reproducible Slice 1 defect was found.
- The packed artifact is a local verification artifact, not a published beta. Publication remains Slice 3.

## Slice 2: Add strict authorization and recoverable operations

**Status:** pending; depends on Slice 1.

Deliver the complete user-facing authorization contract in both software modes, including a safe path to recover and administer the vault.

### Implementation

- Store strict policy per project/environment in an authenticated, domain-separated vault record.
- Add `keyclasp strict enable|disable` with the normal explicit scope flags. Require operator authorization for both mutations and audit the result without secret values.
- Report the effective mode and strict policy through `keyclasp status` without treating hardware availability as hardware enrollment.
- Enforce policy in one pre-unlock decision:
  - named request, strict off: no Touch ID;
  - named request, strict on: Touch ID before vault unlock;
  - whole-scope request: operator authorization before vault unlock;
  - cancelled or unavailable required authorization: no fallback, decrypt, or child.
- Preserve normal passphrase unlocking after authorization when the selected software mode requires it. Touch ID authorizes the operation; it does not replace the vault's encryption key.
- Make strict policy impossible to weaken through command flags, environment variables, context files, unsafe overrides, or direct use of a lower-level exported API.
- Define and document backup, restore, forgotten-passphrase, copied-machine-vault, strict-policy-on-an-unsupported-host, and corrupt-key behavior.
- Update the Keyclasp agent guidance so agents always use explicit project, environment, and named secrets and never request or print values.

### Verification

- A policy matrix covers passphrase and machine modes, named and whole-scope runs, strict on/off, cancellation, unavailable biometrics, wrong passphrase, unsafe override, and child failure.
- Interactive macOS tests prove the prompt timing and that cancellation launches no child. Non-macOS tests prove unsupported strict policy fails closed.
- Authenticated-policy tamper, scope transplant, downgrade, backup, restore, and upgrade tests fail safely.
- Public API and package-export tests prove callers cannot bypass the normalized runtime and policy decision through supported imports.

### Acceptance

The walking skeleton passes through step 4. A user can explain from `keyclasp status` which software mode and authorization policy are active, and every path either follows that policy or fails before secret release.

## Slice 3: Ship the software beta

**Status:** pending; depends on Slices 1 and 2.

Deliver an installable, supportable public prerelease for passphrase and machine modes.

### Implementation

- Establish the supported Node and OS matrix and exercise macOS, Linux, and Windows in CI.
- Build the npm tarball once, inspect its contents, and install that exact artifact into clean environments. Keep native experiments, development fixtures, vault files, and release credentials out of the package.
- Test fresh initialization, upgrade and migration from the last public version, backup/restore, uninstall/reinstall, spaces and Unicode in paths, shell metacharacters, child signals, cancellation, and interrupted writes.
- Run focused dependency, license, native-addon, install-script, public-export, and vulnerability reviews. Resolve release blockers or document bounded accepted risks.
- Reconcile the README, command reference, getting-started guide, FAQ, security model, agent skill, and release notes with the exact implemented contract.
- State prominently that passphrase mode is portable, machine mode is software-bound, named selection is not same-user authentication, the child is trusted, output redaction is not an exfiltration boundary, and hardware mode is unavailable.
- Produce one candidate artifact, checksums, source revision, dependency lockfile, test receipt, supported matrix, and reproducible package-content manifest.
- Publish a tagged prerelease only from the reviewed candidate. A reasonable first target is `0.2.0-beta.1`; confirm the exact version immediately before release.

### Verification

- CI and clean-install receipts identify the exact artifact and separate source tests from package tests.
- Representative coding-agent workflows inject only named secrets and cover normal success, missing secret, unsafe override, child cancellation, signal forwarding, cleanup, and attempted output disclosure.
- A release review finds no unsubstantiated hardware, same-user-isolation, or zero-exposure claim.
- The tag, npm package, checksums, source revision, and documented version all agree.

### Acceptance

The walking skeleton passes through step 6 on the published support matrix. A new user can install the beta, choose passphrase or default machine mode, run a named secret unattended, opt one scope into strict Touch ID on macOS, back up and restore the vault, and understand the remaining trust boundaries.

## Slice 4: Add the optional macOS hardware beta

**Status:** pending; independent of the Slice 3 release after the shared contract is stable.

Deliver hardware mode only if the exact implementation and distributed identity pass physical qualification. A failed experiment leaves the status-only boundary in place and does not change the software-beta claims.

### Gate A: Prove the persistence design

- Build a disposable CryptoKit Secure Enclave `dataRepresentation` spike without exposing enrollment or lifecycle operations in the public CLI.
- On a physical Apple Silicon Mac with Touch ID, prove create, process restart, representation reopen, non-interactive device-key use for an exact named request, Touch-ID-gated whole-scope/strict use, tamper rejection, update continuity, and deletion semantics.
- Copy the complete test state to a second Mac and prove it cannot use the private key.
- Record the exact code identity, entitlements, OS/hardware versions, commands, hashes, prompts, and results.
- If the spike fails, require an accepted stable signing identity or defer hardware mode. Do not substitute a software key, unsafe cast, mock result, or account-free claim.

### Gate B: Implement behind the shared interfaces

- Add hardware mode as an explicit initialization choice, tentatively `keyclasp init --hardware`, only on qualified systems. Existing `keyclasp init` remains the software flow.
- Implement hardware operations under `src/hardware/` and `native/keyclasp-core/`. Hardware code may implement or extend shared command-level contracts but cannot import `src/software/`, `src/vault.ts`, or `src/biometric.ts`.
- Keep enrollment, key unwrap, vault decryption, recovery-secret input, authorization, environment construction, and child launch inside the short-lived native authority. Return only bounded status and exit information to Node.
- Apply the same selection and authorization semantics as software mode: named requests are non-interactive by default, whole-scope requests require Touch ID, and strict mode requires Touch ID for named requests.
- Define an authenticated, atomic metadata format for the opaque Secure Enclave representation, recovery wrap, vault identity, migration generation, and active/staged state.
- Preserve a trusted recoverable copy through activation. Treat a post-activation durability or rename failure as indeterminate, never as a safe rollback.
- Implement explicit migration between software and hardware modes without silently changing custody or deleting the last recoverable copy.

### Gate C: Qualify and release

- Verify recovery, device loss, copied-vault failure, biometric-set change, cancelled prompts, malformed protocol input, large environments, signals, orphan cleanup, concurrent invocations, power-loss boundaries, update, rollback, and uninstall.
- Run property, fuzz, fault-injection, dependency, FFI, unsafe-code, permission, process-boundary, and independent security reviews.
- Test the exact packaged artifact on clean supported Macs under the exact pre-GA identity and installation path. Limit the first matrix to Apple Silicon plus Touch ID unless T2 evidence is added.
- Publish checksums, provenance, support matrix, recovery procedure, deletion limitations of retained opaque representations, and precise beta limitations.
- Keep Developer ID signing, notarization, Intel/T2 expansion, and hardware GA under the supporting hardware-to-GA plan.

### Acceptance

The hardware walking skeleton passes from explicit initialization through named and strict runs, recovery, update, and copied-Mac rejection without exposing a vault key or secret plaintext to Node. Only then may `keyclasp status` report hardware mode as enabled and the project publish a hardware beta.

## Technical bets and bounded spikes

1. **Canonical record AAD.** Freeze one binary encoding and test vectors before migration code. The spike ends when two independent test helpers produce identical associated data for edge-case names and versions.
2. **Authenticated scoped policy.** Prove policy records can be read before secret decryption, cannot be transplanted between scopes, and cannot be downgraded through supported APIs.
3. **Cross-platform permissions.** Resolve the difference between Unix modes and Windows ACL guarantees before declaring the clean-platform matrix.
4. **CryptoKit opaque representation.** Time-box this to physical evidence. Successful creation alone is not success; restart/reopen, policy separation, tamper, update, deletion semantics, and copied-Mac failure are mandatory.

## Deferred decisions

- Developer ID signing, notarization, and the final macOS hardware GA installation channel.
- Intel/T2 Macs, Windows TPM, Linux TPM, external hardware tokens, and mobile platforms.
- A daemon, stored capabilities, workload identity, or resistance to a malicious same-user caller beyond explicit selection.
- A separately anchored manifest MAC, monotonic rollback counter, and cryptographic revocation of every retained local hardware representation.
- Remote stores, teams, synchronization, accounts, telemetry, and Bitwarden Agent Access.
- Hardware-mode support in the first software-beta artifact; the public status probe may remain unavailable or explicitly experimental.

## Overall done criteria

The planned work is complete only when:

- Slices 1–3 have shipped as a tagged software beta with clean-artifact evidence and accurate limitations;
- every software beta claim is supported by tests against the published artifact, not only source or compiled checks;
- Slice 4 is either shipped after all physical gates or explicitly deferred with the status-only boundary intact;
- software and hardware implementations remain separate behind shared command-level interfaces;
- documentation distinguishes software binding, hardware custody, operator authorization, scoped disclosure, trusted-child behavior, and same-user limitations;
- the plan and security checklist link to the exact receipts for each satisfied release gate.
