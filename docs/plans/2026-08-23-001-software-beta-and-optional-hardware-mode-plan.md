---
title: "release: software beta and optional macOS hardware mode"
type: delivery
status: planned
date: 2026-08-23
---

# release: software beta and optional macOS hardware mode

## Desired outcome

Ship a solid public beta without making the unfinished macOS hardware work a prerequisite:

1. Every software vault can keep unattended secrets under a machine-bound data key and interactive secrets under a separate passphrase-protected data key.
2. Lock rules select interactive custody; unlock rules select machine custody. Changing a rule moves existing matching records between those key domains and sets the default for future matching records.
3. macOS adds Touch ID before interactive-key use; Linux uses the interactive passphrase as both authorization and key unlock. Optional hardware mode remains a separate later product.

An unlocked named `keyclasp run --env ...` uses only the machine key and remains unattended. A locked named run uses only the interactive key and requires operator authorization. Broad `run`, `get`, policy mutation, backup, and restore also require operator authorization even when they touch only machine-key records. Explicit selection limits disclosure to the child; it does not authenticate the caller or defend against every process running as the same user.

Slice 3 adds the missing two-key custody boundary. Slice 4 qualifies and ships the public software beta. Hardware work remains outside the software-beta critical path.

The detailed hardware evidence and eventual Developer ID/notarization work remain in [`2026-08-22-001-macos-hardware-beta-to-ga-plan.md`](./2026-08-22-001-macos-hardware-beta-to-ga-plan.md). This delivery map supersedes that plan's hardware-first release ordering.

## Relevant current codebase

- [`src/runtime.ts`](../../src/runtime.ts) defines the normalized command-level request and result shared by implementations.
- [`src/software/runtime.ts`](../../src/software/runtime.ts) implements passphrase and machine execution without exposing keys or plaintext through the shared contract.
- [`src/hardware/status.ts`](../../src/hardware/status.ts) is a status-only hardware adapter. It cannot enroll, recover, decrypt, or launch a secret-bearing child.
- [`src/cli.ts`](../../src/cli.ts) parses a run request once and delegates it through the software runtime.
- [`src/run.ts`](../../src/run.ts) selects secrets, builds the child environment, and launches without a shell.
- [`src/vault.ts`](../../src/vault.ts) currently stores every record under one random data key and wraps that key either with a passphrase-derived key or the documented software machine mechanism. This exclusive one-key mode is the custody gap addressed by Slice 3.
- [`src/biometric.ts`](../../src/biometric.ts) performs the current macOS operator-authorization prompt.
- [`native/keyclasp-core/`](../../native/keyclasp-core/) contains a status-only public executable plus private hardware experiments. The tested ad-hoc permanent-Keychain path failed with `errSecMissingEntitlement`.
- [`tests/mode-boundary.test.ts`](../../tests/mode-boundary.test.ts) enforces that software and hardware implementations do not import one another and cannot bypass the shared boundary with dynamic loading.

The shared runtime seam and module boundary are already complete and verified. They are prerequisites to this map, not another delivery slice.

## Gap

Slice 2 now enforces the requested authorization policy through supported commands, but one machine- or passphrase-wrapped data key still decrypts every record. A lock is therefore a command gate, not cryptographic separation from the unattended machine path. The final beta also lacks physical Touch ID evidence against the two-key artifact, a declared clean-platform matrix, Windows disposition, dependency/install-script qualification, and release-candidate evidence.

The hardware product is further behind. The public native core is intentionally status-only; no physically qualified design yet provides device-bound custody, the corrected authorization policy, recovery, and child launch under the exact distributed code identity.

## Resolved decisions

- The first public beta uses two independent software data keys. The machine key is the default for unattended records; the interactive key is protected by a non-empty passphrase. Neither is a Secure Enclave or hardware-custody key.
- The machine key is wrapped by the existing software machine mechanism. The interactive key is wrapped only by the interactive passphrase. A process that can obtain the machine key must still be unable to decrypt an interactive-key record.
- Lock and unlock rules can target one project, one environment, an exact project/environment, or an exact secret. No command-line flag, environment variable, context file, supported import, rename, backup, or restore path may weaken the effective result.
- `keyclasp lock|unlock [--project P] [--environment E] [SECRET]` changes both the effective rule and the custody class of existing matching records. `keyclasp inherit` removes an exact override and moves matching records to the custody class selected by the next effective rule. This third operation is required because hierarchical overrides otherwise cannot return to inherited policy.
- A new or migrated vault may be machine-only until an interactive passphrase is enrolled. It can run unlocked named selections, but `lock`, broad `run`, `get`, backup, restore, and other gated operations fail closed. `keyclasp passphrase set|change` is the bounded enrollment and rotation surface; passphrase removal is outside the beta.
- Operator authorization is platform-specific. macOS requires Touch ID. Linux requires a non-empty vault passphrase. One Linux passphrase prompt both authorizes the operation and unlocks the vault.
- macOS requires the interactive passphrase after successful Touch ID whenever interactive authorization is required. Cancelling or failing Touch ID fails closed; the passphrase is not a Touch ID fallback.
- Broad `run`, `get`, lock/unlock mutations, and managed backup or restore require operator authorization. A named run requires it when any selected secret is effectively locked.
- Linux reuses one successful interactive-passphrase entry for authorization and interactive-key unlock. A machine-only vault can run unlocked named selections unattended but cannot satisfy a gate, so gated operations fail before unlock, decryption, mutation, or child launch.
- Windows authorization remains a Slice 4 support-matrix decision. The software beta may ship for macOS and Linux while Windows fails closed and is documented as unsupported; Windows does not block the beta unless it is advertised as supported.
- Record-level authenticated encryption binding is a beta requirement. A separately anchored manifest or rollback counter remains a hardware-GA hardening item.
- Initial hardware support may be limited to Apple Silicon Macs with Touch ID. Intel/T2 support is deferred until separately tested.
- Hardware implementations reuse command-level interfaces, not the software vault or its cryptographic implementation. The native authority must own live key use, decryption, authorization, secret input, and child launch.

## Walking skeleton

The shortest end-to-end beta proof is:

1. Initialize a fresh software vault, store two secrets, and run a packed installation against one explicitly selected secret.
2. Prove an invalid or duplicate multi-secret request decrypts nothing and launches no child.
3. Prove ciphertext moved to another logical record fails authentication.
4. Store one unlocked and one locked secret, prove the unattended path can decrypt only the machine-key record, and prove policy or ciphertext tampering cannot relabel either record's custody class.
5. Lock, unlock, and inherit a record through authenticated atomic transitions; prove macOS Touch ID plus passphrase and Linux one-passphrase authorization against the exact packed artifact.
6. Back up, restore, migrate, and install that exact artifact on the supported clean-platform matrix, then publish the reviewed artifact as a tagged prerelease after explicit release authorization.

The later hardware extension sends the same normalized request through the hardware implementation. The native authority launches the child with the selected secret while the Node process never receives the plaintext or vault key, and copying the hardware vault to a second Mac does not enable decryption.

## Slice 1: Make software storage and selection tamper-evident

**Status:** completed on 2026-08-23; reopened controller-review findings closed on 2026-08-24.

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

- Windows vault use is intentionally blocked until Slice 4 defines the supported matrix and verifies an owner-only ACL implementation or a closed unsupported-platform path; Unix mode repair does not claim Windows ACL coverage.
- Migration interruption coverage uses deterministic faults at each durable boundary plus two-process contention and backup restoration. A real power-loss test remains part of the clean-platform release work.
- Direct in-place overwrite of an open database is unsupported. Slice 2 owns managed restore and serialization between restore and vault lifecycle operations.
- One intermediate parallel full-suite run transiently failed the existing single-secret delete integration test. Its isolated rerun and the final complete 300-test run passed; no reproducible Slice 1 defect was found.
- The packed artifact is a local verification artifact, not a published beta. Publication remains Slice 3.

## Slice 2: Add scoped authorization locks and recoverable operations

**Status:** policy implementation and automated verification completed on 2026-08-24. The 63-file artifact passed 402 tests plus one platform skip and all five review perspectives. Physical Touch ID evidence was not collected. The later two-key decision means that proof must run against the Slice 3 artifact; the current artifact is retained as automated authorization evidence, not a beta candidate.

Deliver the complete user-facing authorization contract in both software modes, including a safe path to recover and administer the vault.

The implementation and evidence below describe the completed policy-only iteration. Slice 3 preserves its command behavior and replaces the custody semantics: lock, unlock, and inherit will move records between independent data keys instead of changing policy alone.

### Implementation

- Store authenticated authorization rules that can match an exact secret, an exact project/environment, one project, or one environment. Rules apply to existing and future secrets.
- Replace the public strict-policy command with `keyclasp lock|unlock [--project P] [--environment E] [SECRET]`. At least one scope flag is required; `SECRET` requires both flags. Both mutations require platform operator authorization and audit the result without secret values.
- Resolve matching rules in this order: exact secret, exact project/environment, project-only or environment-only, then unlocked. Locked wins when project-only and environment-only rules conflict. A more-specific unlock overrides a broader lock.
- In the completed Slice 2 artifact, lock/unlock changes authorization policy only and never rewrites vault mode or key custody. Slice 3 supersedes that custody behavior by moving matching records between the two data keys.
- Report the effective software mode and authorization state through `keyclasp status` without revealing values or treating hardware availability as hardware enrollment.
- Enforce policy in one pre-unlock decision:
  - named request, every selected secret effectively unlocked: normal vault-mode behavior;
  - named request, any selected secret effectively locked: platform operator authorization before vault unlock;
  - whole-scope request: platform operator authorization before vault unlock;
  - cancelled, incorrect, unavailable, or non-interactive required authorization: no fallback, decryption, mutation, or child launch.
- Use this authorization matrix:

  | Operation | macOS | Linux |
  | --- | --- | --- |
  | Named `--env`, effectively unlocked | Vault passphrase in passphrase mode; no prompt in machine mode | Vault passphrase in passphrase mode; no prompt in machine mode |
  | Named `--env`, effectively locked | Touch ID, then vault passphrase when one exists | One vault-passphrase prompt; machine mode fails closed |
  | Whole-scope `run` | Touch ID, then vault passphrase when one exists | One vault-passphrase prompt; machine mode fails closed |
  | `get`, lock/unlock mutation, backup, or restore | Touch ID, then vault passphrase when one exists | One vault-passphrase prompt; machine mode fails closed |

- On Linux, use the successful passphrase entry as both operator authorization and vault unlock; never prompt twice for the same operation. For restore without a usable live vault, authenticate against and unlock the passphrase-protected backup.
- On macOS, Touch ID authorizes the operation but does not replace a passphrase vault's encryption key. A failed or cancelled Touch ID cannot fall back to passphrase-only authorization.
- Make effective authorization impossible to weaken through command flags, environment variables, context files, unsafe overrides, supported imports, rename, backup, or restore.
- Define and document backup, restore, forgotten-passphrase, copied-machine-vault, authorization-policy-on-an-unsupported-host, and corrupt-key behavior.
- Update the Keyclasp agent guidance so agents always use explicit project, environment, and named secrets and never request or print values.

### Verification

- A policy matrix covers exact-secret, exact-scope, project-only, environment-only, equal-specificity conflicts, more-specific unlocks, future secrets, passphrase and machine modes on macOS and Linux, named and broad runs, `get`, policy and recovery mutations, cancelled or unavailable Touch ID, wrong or unavailable passphrases, non-interactive input, unsafe override, and child failure.
- Interactive macOS tests prove Touch ID precedes passphrase unlock when both are required and that cancellation launches no child. Interactive Linux tests prove one passphrase prompt both authorizes and unlocks, while Linux machine-only and non-interactive gated operations fail before secret release.
- Authenticated-policy tamper, scope transplant, downgrade, backup, restore, and upgrade tests fail safely.
- Public API and package-export tests prove callers cannot bypass the normalized runtime and policy decision through supported imports.

### Acceptance

The supported command paths enforce the scoped authorization matrix and fail before secret release when authorization fails. Slice 3 must preserve those gates while replacing policy-only lock state with cryptographic custody separation. Physical acceptance moves to the final Slice 3 artifact so one proof covers the behavior that will ship.

### Completed work

- Replaced the obsolete public strict command with `keyclasp lock|unlock [--project P] [--environment E] [SECRET]`. Project-only, environment-only, exact-scope, and exact-secret rules apply to existing and future secrets. Secret selectors require both explicit scope flags; neither ambient environment nor persisted context can supply a policy-mutation scope.
- Upgraded the authenticated policy document to store explicit locked and unlocked rules. Exact secret overrides exact scope, exact scope overrides one-dimensional rules, locked wins equal-specificity conflicts, and a more-specific unlock overrides a broader lock. The vault-bound SQLite commitment and interruption journal continue to reject tampering, deletion, replay, downgrade, transplant, and forged recovery state; the authenticated v1 policy upgrades on mutation.
- Implemented one typed operator-authorization contract across run, get, policy, and recovery paths. macOS uses Touch ID with no passphrase-only fallback, then the vault passphrase when present. Linux uses one non-empty passphrase entry to authorize and unlock; machine-only and non-interactive gated operations fail closed. The low-level runner has no alternate biometric fallback.
- Preserved normal behavior for effectively unlocked named runs: passphrase vaults prompt for their normal unlock and machine vaults remain unattended. Broad runs and `get`, lock/unlock, backup, and restore always authorize before unlock, decryption, mutation, or child launch. Wrong, cancelled, unavailable, closed-input, and non-interactive credentials fail before side effects, including under `--allow-unsafe`.
- Made `keyclasp status` metadata-only. It reports `software-passphrase` or `software-machine`, effective locked/unlocked/mixed counts, and the future-secret scope default without unlocking the data key, decrypting values, or revealing plaintext.
- Prevented bypass through flags, environment, context, unsafe override, supported imports, deep imports, rename, backup, and restore. Supported package exports no longer expose raw vault database readers; the exact allowlist contains parsing, context, biometric-result classification, path reporting, and name validation only. Rename proceeds only when every moved secret has the same effective authorization state at its destination.
- Added operator-authorized managed backup and restore. Backups contain a synced SQLite snapshot, matching key, authenticated policy, and data-key-authenticated manifest. Linux total-loss restore verifies and reuses one backup passphrase. Restore mode inspection is read-only before authorization; permission repair and all live mutation happen afterward through authenticated staging, replacement, commit, and cleanup journal phases under an exclusive lifecycle lock.
- Replaced separate permission checks with one internal owner-only path verifier for vault, policy, recovery, backup, journal, and lifecycle-lock paths. It rejects symlinks, wrong owners and types, rechecks device/inode identity around repairs, removes and rechecks macOS ACLs on owner-only paths, and rejects backup parents writable through mode bits or macOS ACLs.
- Removed the lifecycle lock's first-use filesystem/schema race. Every opener queries SQLite's schema, creates the table with `IF NOT EXISTS` when absent, and inserts the singleton with `OR IGNORE`. A deterministic two-process barrier regression forces both fresh-home openers past the absent-schema observation before either creates it.
- Hardened terminal and physical verification. Secure prompts process pasted and Unicode chunks, hide input, serialize concurrent Linux prompts, cancel on Ctrl-C/Ctrl-D/stream closure, and restore terminal state. The physical verifier packs and installs the current artifact itself, uses a disposable passphrase vault, requires Touch ID followed by a visible passphrase prompt for lock and unlock, requires cancellation status 2 with the exact cancellation-only `BLOCKED` bytes and no passphrase prompt, rejects unrelated failures, checks no child launched, and writes a `0600` transcript with artifact hashes.
- Documented forgotten passphrases, copied machine backups, unsupported authorization hosts, corrupt live keys, backup publication failure, restore retry behavior, metadata-only status, and explicit agent scope/selection rules. Software and hardware modules remain separate; hardware lifecycle operations remain status-only.

### Verification evidence

- `npm test` now builds before executing CLI tests. The final default-parallel run passed: 25 files, 402 tests passed, 1 macOS-only test skipped on this host. `npm run build`, `node --check scripts/verify-slice2-touch-id.mjs`, and `git diff --check` passed.
- Policy tests cover exact-secret, exact-scope, project-only, environment-only, both equal-specificity polarities and insertion orders, more-specific unlocks, future secrets, authenticated v1 upgrade, tampering, scope transplant, pair deletion, older-pair replay, same-generation forgery, forged pending rollback, commit cleanup, and crash recovery in fresh processes after both pre-commit publication boundaries.
- Runtime and platform tests cover passphrase and machine modes; named and broad runs; locked and unlocked selection; Linux one-prompt authorization/unlock; macOS Touch ID then passphrase ordering; `get`, policy, backup, and restore gates; wrong passphrases; Touch ID cancellation/unavailability; non-interactive and closed input; unsafe override; child failure; and zero unlock, decryption, mutation, recovery, or child launch after failed authorization. Source/mocked platform checks remain explicitly separate from physical Touch ID evidence.
- Recovery tests cover authenticated policy preservation, rehashed downgrade attempts, copied-machine rejection, passphrase portability, wrong backup passphrases, total loss, corrupt/absent live state, read-only pre-authorization inspection, pre-publication and indeterminate backup failures, every journal crash phase, fresh-process recovery, inherited ACL removal during backup and restore, unsafe parents, and unchanged live state after rejection. Lifecycle tests cover the deterministic two-process fresh-home race, explicit command-to-lock-mode assignment, shared concurrency, and exclusive waits beyond five seconds.
- Physical-verifier tests require status 2 and the exact cancellation-only stderr bytes and reject approval, denial, unavailable biometrics, helper, lifecycle-lock, syntax, spawn, extra stdout, extra blank stderr, and ordinary failures. Recorder tests verify a `0600` transcript with command results, timestamps, PASS/FAIL finalization, artifact identity, and printed evidence paths. These are source/mocked checks, not physical evidence.
- The final 63-file `keyclasp-0.1.1.tgz` has SHA-1 `1286226cae728256610606788af716cc23004f84`, SHA-256 `68c4c5d2d00b4778451d1836a883475455bf9f6a132ac2828f6707bba13eaba4`, and integrity `sha512-c7qvL2avJ0A7Hj+Hre2pJnaACETQJJaWeTGRUOJwqYWeSgYc7R/uC6Jo0/kkAttlO1NgNDr1eoHAxbDdnKf7KA==`. A clean isolated install includes `native/macos-biometric.js`, excludes `native/keyclasp-core/`, exposes exactly `checkUnsafeCommand,evaluateBiometricAuthentication,extractGlobalFlags,getVaultLocation,parseRunArgs,readContext,resolveContext,validateScopeName`, rejects `keyclasp/policy`, `keyclasp/vault`, `keyclasp/run`, and `keyclasp/software/runtime` with `ERR_PACKAGE_PATH_NOT_EXPORTED`, reports metadata-only `software-machine`/unlocked status, masks pasted input, and completes an unattended named run with the expected injected value.
- Independent correctness, simplicity, security, tests, and concurrency reviews found and drove fixes for status decryption, lifecycle-bypassing exports, pre-authorization policy validation, audit symlinks, restore permission mutation, all-unlocked status reporting, rename state preservation, duplicate auth paths, prompt chunking/closure, physical passphrase evidence, package-test false positives, stale dist, incomplete precedence ordering, and same-process-only crash tests. Final correctness, simplicity, and security re-reviews returned clean passes; the final concurrency findings were covered by explicit lock-mode and fresh-process recovery regressions.

### Remaining risks or blockers

- The current physical verifier has not run. Slice 3 must update it for two-key custody and run the final verifier against the exact Slice 3 artifact. Running the current command first is diagnostic only and cannot close the beta gate.
- Current lock rules are authorization policy only. Because one vault data key decrypts every record, the current artifact does not satisfy the final locked-secret custody guarantee.
- Machine-mode backups intentionally remain bound to the source machine identity. Passphrase backups are portable only with the correct passphrase. A forgotten passphrase has no bypass.
- A malicious same-user process that rewrites the complete database, key, and policy set remains outside the software-mode threat boundary. Partial policy-file rewrites are detected by the database commitment.
- Windows authorization and managed backup/restore remain deferred until the Slice 4 platform-support decision and owner-only Windows ACL verification. This is not a reason to weaken the macOS or Linux contract.
- The clean npm install succeeded, but npm warned that `prebuild-install@7.1.3` is deprecated and that Keyclasp and `better-sqlite3` install scripts need review under npm's evolving `allowScripts` policy. Slice 4 owns dependency/install-script qualification.
- Slice 3 has not started. No beta was published, and no hardware enrollment, key use, recovery, decryption, or launch operation was enabled.

## Slice 3: Separate machine and interactive custody

**Status:** pending; depends on the completed Slice 2 software foundations.

Deliver one migrated software vault in which the unattended machine path cannot decrypt records assigned to the interactive key.

### Implementation

- Introduce a versioned key bundle with two independent random 32-byte data keys:
  - the machine data key is wrapped by the existing machine-derived wrapping key;
  - the interactive data key is wrapped only by a non-empty passphrase-derived wrapping key;
  - the policy MAC key remains policy-only and cannot decrypt either record class.
- Add an authenticated `key_class` to each record and bind it into canonical AES-GCM associated data with the existing vault ID, record ID, scope, name, kind, and format version. A row moved between key classes without authorized re-encryption must fail authentication.
- Keep key access inside the software vault implementation. Runtime and public package contracts may request a named resolution under an already validated policy decision; they may not export either data key, a generic decrypt function, or a caller-asserted authorization result.
- Make `lock`, `unlock`, and `inherit` one exclusive lifecycle operation that atomically changes the authenticated rule, re-encrypts every affected existing record under the resulting key class, and sets the class for future matching records. A downgrade to machine custody requires the same operator authorization as a lock.
- Add the smallest passphrase lifecycle needed by the two-key model: set an absent interactive passphrase and rotate an existing one. Initial enrollment requires Touch ID plus new-passphrase confirmation on macOS; Linux uses an interactive new-passphrase confirmation because no prior operator credential exists. Rotation requires the normal platform authorization, the current passphrase, and confirmation of the new passphrase, then rewraps the interactive key without rewriting record ciphertext. Do not support passphrase removal in the beta.
- Extend `status` to report machine-only or dual-key software state plus locked/unlocked/mixed counts without loading either data key or decrypting a record.
- Migrate existing vaults backup-first under the exclusive lifecycle lock:
  - an existing passphrase-wrapped data key becomes the interactive key; create a fresh machine key and re-encrypt effectively unlocked records under it;
  - an existing machine-wrapped data key becomes the machine key; if any record is effectively locked, require interactive passphrase enrollment before migrating and leave the old vault byte-identical when enrollment is unavailable or cancelled;
  - record the new format before normal use so an older binary refuses it;
  - publish the key bundle, database, policy, and recovery metadata through one durable migration journal with an explicit commit point and retryable cleanup.
- Extend managed backup and restore to authenticate the complete key bundle and every record class. The manifest carries a domain-separated authenticator under every data key used by records, and restore verifies every required authenticator before replacement. Same-machine restore supports mixed vaults. A copied-machine restore fails closed when any machine-key record exists. When every record is interactive, restore may create a fresh target-machine key after the passphrase authenticates the interactive key; no record is reclassified. Never silently drop or reclassify an unavailable machine-key record.
- Preserve hardware modularity. `src/hardware/` and `native/keyclasp-core/` remain status-only and cannot import the software key bundle or receive either software data key.

### Verification

- Freeze the key-bundle encoding, record AAD, and migration states with independent test vectors before implementing the migration. The bounded spike passes only when a machine-key-only test reader cannot decrypt an interactive record and modified key-class metadata fails authentication.
- Cover fresh machine-only and dual-key initialization; passphrase set and rotation; locked, unlocked, inherited, mixed, and future-secret rules; multi-secret requests spanning both classes; broad run; `get`; rename; delete; backup; restore; and copied-machine failure.
- Inject faults before and after every durable boundary in policy mutation, record re-encryption, key-bundle publication, database commit, backup, and restore. Test retry in a fresh process, concurrent readers and writers, old-binary refusal, and byte-identical failure before commit.
- Prove zero interactive-key unwrap and zero interactive-record decrypt calls for an unlocked named machine request. Prove failed Touch ID or passphrase authorization causes zero key-class transition, decryption, mutation, or child launch.
- Update the physical verifier to pack and install the exact candidate, then prove on macOS: unattended unlocked named use; approved lock followed by passphrase; cancelled locked run with no passphrase prompt or child; approved locked run followed by passphrase; approved unlock followed by passphrase; and unattended use after unlock. Save the artifact hashes and owner-only transcript.
- Prove on Linux that one passphrase entry both authorizes and unlocks an interactive operation, while a machine-only or non-interactive gated operation fails before secret release.
- Run the complete build and test suite, packed-artifact install, export/deep-import checks, `git diff --check`, and fresh correctness, simplicity, security, tests, and concurrency reviews.

### Acceptance

The exact packed artifact passes walking-skeleton steps 1–5. Possession of the machine key and complete machine-key metadata is insufficient to decrypt an interactive-key record. Lock, unlock, inherit, migration, backup, restore, and interruption preserve the record's authenticated custody class. Physical macOS and interactive Linux receipts identify that exact artifact.

### Agent handoff

Execute this slice in a fresh task. Stop after the verified packed artifact and physical-evidence request; do not start release qualification, commit, push, tag, publish, or enable hardware operations. Record code, tests, artifact identity, review findings, physical evidence, and remaining risks here before handing Slice 4 to another fresh task.

## Slice 4: Qualify and ship the software beta

**Status:** pending; depends on Slice 3 including final physical authorization evidence.

Deliver one installable, supportable public prerelease for the software dual-key vault. Hardware mode remains unavailable.

### Implementation

- Freeze the support matrix before release work. Qualify macOS and Linux on the declared Node versions. Time-box verified owner-only Windows ACL and operator-authorization support; include Windows only if the same packed artifact passes those gates. Otherwise fail closed on Windows and publish macOS/Linux as the explicit beta matrix.
- Build the npm tarball once from a reviewed clean source revision. Inspect its contents and install that exact file into clean environments. Keep native experiments, hardware status binaries, development fixtures, vaults, transcripts, and release credentials outside the package.
- Exercise fresh initialization, migration from the last public one-key format, same-machine mixed backup/restore, all-interactive portable restore, uninstall/reinstall, spaces and Unicode in paths, shell metacharacters, child signals, cancellation, interrupted writes, and representative coding-agent workflows.
- Audit the exact lockfile and package lifecycle: `better-sqlite3` prebuilt and source-build paths, every install script, deprecated `prebuild-install`, licenses, advisories, native-addon ABI support, public exports, package contents, and reproducibility. Resolve blockers or record a bounded accepted risk with an owner and follow-up.
- Add software-beta CI that separates source tests from exact-tarball tests on every supported OS and Node version. A platform skip is acceptable only when the platform is explicitly unsupported and the package fails closed there.
- Reconcile README, command reference, getting started, FAQ, security model, agent skill, status/help text, migration and recovery guidance, and release notes with the exact two-key contract. State the same-user boundary, machine-key weakness, interactive-key portability, mixed-backup limitation, trusted-child behavior, output-redaction limit, unsupported Windows status if applicable, and hardware unavailability.
- Produce one release-candidate receipt containing source revision, dependency lockfile hash, tarball integrity and SHA-256, package manifest, SBOM/license inventory, test and review results, support matrix, physical authorization transcript, migration evidence, and known limitations.
- Prepare `0.2.0-beta.1` or the next available prerelease version, but stop before committing, pushing, tagging, creating a release, or publishing to npm until the user explicitly authorizes those actions.

### Verification

- Clean-install receipts identify the exact candidate hash and distinguish source, compiled, mocked-platform, physical-device, CI, and installed-package evidence.
- macOS and Linux repeat the named machine-key run, locked interactive-key run, broad run, `get`, lock/unlock/inherit, backup, restore, migration, cancellation, signals, and cleanup against that file. Excluded Windows fails before creating or mutating vault state.
- A final release review finds no unresolved critical or high-severity correctness, simplicity, security, test, concurrency, dependency, packaging, or documentation issue and no hardware, same-user-isolation, or zero-exposure claim.
- After explicit publication authorization, tag and publish the reviewed file without rebuilding it. Install from the registry, verify its integrity against the receipt, and repeat a narrow named-run/status smoke test. A mismatch stops the release.

### Acceptance

Walking-skeleton step 6 passes on the published support matrix. The tag, npm package, checksums, source revision, documentation, and receipts all identify the same artifact. A new user can initialize the software vault, keep selected secrets unattended, move selected secrets into interactive custody, recover an eligible backup, and understand every unsupported guarantee.

### Agent handoff

Use a fresh task after Slice 3. Qualification may prepare a release candidate without publication authority. Publication is a separate protected checkpoint requiring an explicit user instruction.

## Optional macOS hardware track

**Status:** deferred; independent of the software beta after the shared contract is stable.

Deliver hardware mode only if the exact implementation and distributed identity pass physical qualification. A failed experiment leaves the status-only boundary in place and does not change the software-beta claims.

### Gate A: Prove the persistence design

- Build a disposable CryptoKit Secure Enclave `dataRepresentation` spike without exposing enrollment or lifecycle operations in the public CLI.
- On a physical Apple Silicon Mac with Touch ID, prove create, process restart, representation reopen, non-interactive device-key use for an effectively unlocked exact named request, Touch-ID-gated broad and effectively locked use, tamper rejection, update continuity, and deletion semantics.
- Copy the complete test state to a second Mac and prove it cannot use the private key.
- Record the exact code identity, entitlements, OS/hardware versions, commands, hashes, prompts, and results.
- If the spike fails, require an accepted stable signing identity or defer hardware mode. Do not substitute a software key, unsafe cast, mock result, or account-free claim.

### Gate B: Implement behind the shared interfaces

- Add hardware mode as an explicit initialization choice, tentatively `keyclasp init --hardware`, only on qualified systems. Existing `keyclasp init` remains the software flow.
- Implement hardware operations under `src/hardware/` and `native/keyclasp-core/`. Hardware code may implement or extend shared command-level contracts but cannot import `src/software/`, `src/vault.ts`, or `src/biometric.ts`.
- Keep enrollment, key unwrap, vault decryption, recovery-secret input, authorization, environment construction, and child launch inside the short-lived native authority. Return only bounded status and exit information to Node.
- Preserve the same selection boundary as software mode while using the hardware provider's unlock: effectively unlocked named requests avoid Touch ID, broad requests require Touch ID, and effectively locked named requests require Touch ID.
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

The hardware walking skeleton passes from explicit initialization through unlocked named and locked runs, recovery, update, and copied-Mac rejection without exposing a vault key or secret plaintext to Node. Only then may `keyclasp status` report hardware mode as enabled and the project publish a hardware beta.

## Technical bets and bounded spikes

1. **Two global data keys rather than per-record wrapped keys.** Use one machine data key and one interactive data key because the vault is small and bulk transitions are operator-driven. Reject this bet before migration implementation only if the fault-injection spike shows that atomic record re-encryption cannot reuse the existing lifecycle and recovery journal safely.
2. **Authenticated custody transition.** Freeze the key bundle, `key_class` AAD, policy generation, and migration commit point together. The spike ends only when machine-key material cannot decrypt an interactive test record and every partial publication either restores the old generation or completes the new one.
3. **Cross-platform permissions.** Attempt verified owner-only Windows ACL handling within Slice 4. Excluding Windows with a tested fail-closed path is an acceptable beta result; silently applying Unix mode assumptions is not.
4. **Install-script and native-addon qualification.** Test `better-sqlite3` from both a prebuilt binary and source compilation on the candidate matrix. A successful local install alone does not qualify npm lifecycle behavior.

## Deferred decisions

- Developer ID signing, notarization, and the final macOS hardware GA installation channel.
- Optional hardware mode, Intel/T2 Macs, Windows TPM, Linux TPM, external hardware tokens, and mobile platforms.
- Software support for Windows when verified ACL and authorization work misses the Slice 4 cutline; the macOS/Linux beta must fail closed and document the exclusion.
- Interactive-passphrase removal. The beta supports enrollment and rotation only.
- A daemon, stored capabilities, workload identity, or resistance to a malicious same-user caller beyond explicit selection.
- A separately anchored manifest MAC, monotonic rollback counter, and cryptographic revocation of every retained local hardware representation.
- Remote stores, teams, synchronization, accounts, telemetry, and Bitwarden Agent Access.
- Hardware-mode support in the software-beta artifact; the public status probe may remain unavailable or explicitly experimental.

## Overall done criteria

The planned work is complete only when:

- Slices 1–4 are complete and their reviewed artifact has shipped as a tagged software beta with clean-artifact evidence and accurate limitations;
- every software beta claim is supported by tests against the published artifact, not only source or compiled checks;
- possession of the machine key cannot decrypt any record whose authenticated custody class is interactive;
- lock, unlock, inherit, passphrase rotation, migration, backup, restore, and interruption preserve or fail closed on key class;
- physical Touch ID and interactive Linux evidence identify the same candidate later published;
- Windows is either on the tested support matrix or fails closed and is documented as unsupported;
- optional hardware mode remains deferred with the status-only boundary intact;
- software and hardware implementations remain separate behind shared command-level interfaces;
- documentation distinguishes software binding, hardware custody, operator authorization, scoped disclosure, trusted-child behavior, and same-user limitations;
- the plan and security checklist link to the exact receipts for each satisfied release gate.
