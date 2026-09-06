---
title: "security: production readiness after the 2026-09-05 audit"
type: delivery
status: in-progress
date: 2026-09-05
packet: KC-P01
---

# Security production readiness after the 2026-09-05 audit

## Desired outcome

Repair F1-F6 from [`docs/security/audits/2026-09-05/audit.md`](../security/audits/2026-09-05/audit.md), make new software vaults safe for sensitive storage by default, and qualify one immutable software artifact for the stated macOS and Linux production boundary. Hardware custody remains unavailable and is not a dependency of this plan.

Completion has four distinct states:

1. **Local fixes verified:** every retained synthetic failure has become a regression that passes from source on temporary vaults.
2. **Final artifact qualified:** the immutable candidate passes clean installation, platform, physical authorization, recovery, package, dependency, and reproducibility gates.
3. **Independent assurance accepted:** an external reviewer assesses the exact candidate source and artifact, with no unresolved release-blocking finding.
4. **Operator rollout complete:** after separate authorization, the operator backs up and migrates the real vault, verifies readback, handles retained copies, and rotates credentials where revocation is required.

A source test pass does not satisfy states 2-4. An older receipt does not qualify changed source. Publication, installation into the operator environment, real-vault access, and hardware enrollment remain outside KC-P01.

## Evidence basis and current gap

The reviewed source is `d94189b30fb5e52ee5f4eb6435e96fe865c13142`, package `0.2.0-beta.1`. During planning, all 13 source hashes in [`receipt.json`](../security/audits/2026-09-05/receipt.json) matched that checkout. A fresh build and the three retained synthetic probes reproduced the audit results:

- F1: `secure_delete=0`; a fresh process recovered 50 of 500 machine-encrypted values after every current row had moved to interactive custody.
- F2: the self-overlapping value `abcd123a` reached stdout intact and the guarded child returned 0.
- F3: restore reported success while an old live WAL remained and readback returned the post-backup live value.
- F4: a second recovery rejected an already-restored file after rollback was interrupted and left the journal in place.
- F5: the CLI rejected a corrupt live key before dispatching restore, although the library restored the same valid backup.
- F6: machine-only backup passed synthetic authorization, then failed because the wrapper requested an unenrolled interactive key.

The audit's full source run remains historical evidence: 474 passed, 2 skipped, and 1 failed because the clean helper build used linker `27037.1` while the bundled binary recorded `27037.0`. The dependency audit reported no known vulnerability in the installed graph at that time. Neither result proves the corrected artifact.

The earlier [`software beta and optional hardware mode plan`](./2026-08-23-001-software-beta-and-optional-hardware-mode-plan.md) records completed software slices 1-4 and rc6 qualification. Preserve that plan, rc4-rc6 artifacts, physical receipts, CI runs, and failed helper/repack evidence as immutable historical records. None transfers to this remediation candidate. Its hardware Slice 5 stays deferred.

### Current implementation seams

- [`src/cli.ts`](../../src/cli.ts) acquires the lifecycle lock, runs recovery and migration before command dispatch, chooses new-record custody from policy, and wires backup authorization.
- [`src/lifecycle-lock.ts`](../../src/lifecycle-lock.ts) serializes Keyclasp processes, but it does not itself quiesce or publish the complete SQLite file set.
- [`src/recovery.ts`](../../src/recovery.ts) authenticates managed backups and journals replacement of managed files. It omits `vault.db-wal` and `vault.db-shm`, and its replacing-phase rollback validates staged content even after that content has already been replaced.
- [`src/vault.ts`](../../src/vault.ts) enables WAL opportunistically, defaults records to machine custody, updates custody in place, and clears key references without overwriting owned buffers.
- [`src/policy.ts`](../../src/policy.ts) commits the rule, record re-encryption, and database anchor together, but has no durable post-commit phase for removing obsolete ciphertext representations.
- [`src/run.ts`](../../src/run.ts) owns selection, environment injection, child supervision, and streaming output redaction. Its carry calculation can split a complete match before scanning it.
- [`src/biometric.ts`](../../src/biometric.ts) launches the absolute bundled helper but inherits the caller environment and does not independently verify the helper file or its parent path immediately before execution.
- [`native/macos-biometric/main.m`](../../native/macos-biometric/main.m) is a narrow LocalAuthentication UI agent. [`scripts/build-macos-biometric-helper.mjs`](../../scripts/build-macos-biometric-helper.mjs) does not pin or record the complete compiler, linker, and SDK identity.

## Resolved decisions

These choices are fixed for execution because changing them later would cause substantial rework.

1. **Treat SQLite as a file set with separate healthy-live and damaged-live restore branches.** The live state is `vault.db` plus any `vault.db-wal` and `vault.db-shm`, not `vault.db` alone. Both branches first obtain the Keyclasp exclusive lifecycle lock and authenticate and fully validate the backup before changing live files. If the live database opens and validates, the healthy-live branch proves that no observable external process holds the file set, copies the stable DB/WAL/SHM set into transaction-owned staging, and checkpoints and validates only that copy. The byte-identical raw live set remains closed until the durable publication journal and then becomes rollback material. If validation proves the copy is damaged, the damaged-live branch does not parse or checkpoint the raw live database; it quarantines the complete raw DB/WAL/SHM and managed-file set as rollback evidence before publishing the authenticated backup. `SQLITE_BUSY`, an observable file holder, a changing file identity, or another live-writer signal is not corruption: either branch stops before mutation.
2. **Use one internal file-publication authority.** Add `src/vault-files.ts` as a package-private deep module for SQLite quiescence, live-file-set inventory, staged publication, sidecar isolation, durable rename/cleanup, and post-publication open/readback. It accepts an explicit vault directory and contains no vault key, secret plaintext, policy semantics, or operator authorization. `src/recovery.ts` remains the owner of backup authentication and restore policy; `src/vault.ts`/`src/policy.ts` remain the owners of custody and cryptography.
3. **Make rollback intent and observed progress distinct.** A versioned restore journal records each file operation, its authenticated pre-operation locations/hashes, its authenticated post-operation locations/hashes or required absence, and whether completion has been persisted. Writing and fsyncing the intent precedes the mutation; it is not evidence that the mutation occurred. On recovery, each pending operation must accept and validate exactly one of two states: the complete pre-operation state, which it may execute, or the complete post-operation state, whose completion it may record. Any mixed or third state fails without further mutation. After the filesystem mutation and required sync, persist completion before advancing. Repeating recovery after interruption therefore converges without assuming the expected final location already exists.
4. **Restore from backup authority, not damaged live authority.** `keyclasp backup restore <directory>` is the emergency path; no extra unsafe flag is needed. The CLI recognizes it before ordinary live-vault recovery or migration, acquires the exclusive lock, and authenticates the operation and backup without parsing the live key or database. It then selects the healthy-live or damaged-live branch from Decision 1. Only the damaged-live branch may avoid live parsing, and only after backup authentication and validation; it quarantines damaged files, sidecars, and pending journals into the new transaction's rollback set. Every other command retains ordinary startup recovery and fails closed on damaged state. The Keyclasp lifecycle lock excludes Keyclasp processes, not arbitrary SQLite clients. Restore must detect and reject observable busy or changing state, and the runbook must require the operator to stop external clients; Keyclasp cannot guarantee exclusion for a client that ignores its lifecycle protocol and races raw file replacement.
5. **Default passphrase vaults to interactive custody.** Fresh `keyclasp init` requires a non-empty passphrase and creates an authenticated interactive fallback for new records. Unattended storage requires an explicit `keyclasp init --machine-only` choice or an authorized `keyclasp unlock --default`. `keyclasp lock --default` restores the interactive fallback. Existing vaults keep their current machine fallback during upgrade to avoid silently breaking unattended jobs, but `status` labels it `legacy machine default`; it is not production-qualified until the operator explicitly changes or accepts that default.
6. **Tightening is incomplete until stale representations are gone.** A machine-to-interactive transition remains pending and blocks normal vault use until secure deletion, compaction, WAL checkpoint/truncation, sidecar cleanup, and closed-file validation complete. Enable and verify `secure_delete=ON` on every writable vault connection before sensitive writes. The regression and qualification gates then inspect the closed files from a fresh process. If the final inventory has zero machine records, rotate and retire the live machine data key after cleanup; otherwise retain it for the remaining machine records and rely on verified file cleanup for transitioned rows. External snapshots and copied backups are not revoked by either action.
7. **Unlock only backup-required key classes.** Backup creation derives the required classes from a consistent authenticated inventory after operator authorization. A macOS machine-only backup uses only the machine key. Mixed or interactive backups also request the interactive key. Linux machine-only gated operations continue to fail closed under the existing platform authorization policy; F6 does not weaken that policy.
8. **Keep output protection streaming and fail closed.** Scan the full buffered candidate for complete matches before retaining any suffix that is only a possible future prefix. A detected selected value is replaced before any part reaches the caller, terminates the child/process group, and yields a nonzero leak outcome even if the child exits 0. Keep stdout and stderr stream order per stream and preserve incremental UTF-8 decoding.
9. **Harden the helper without enlarging its claim.** Launch it with a documented minimal environment; reject symlinks, unexpected owners, writable parent paths, manifest/hash mismatch, invalid signature, and unexpected designated requirement before prompting. Compile with warnings-as-errors and stack protection; sign with the hardened-runtime option and no unreviewed entitlement; record the complete toolchain. These are defense in depth. They do not defend against arbitrary code already running as the same user or replace the interactive passphrase.
10. **Preserve the software threat model.** The corrected software product relies on the OS user boundary and a trusted selected child. It does not claim protected memory, freshness against a complete copied snapshot, malicious-child confinement, or password-manager-equivalent same-user isolation. A stronger claim requires separately authorized broker or hardware work and does not block local remediation.

## Architecture

### Existing architecture artifacts

- [`docs/architecture/operator-authorization.md`](../architecture/operator-authorization.md) describes the software authorization flow, but its verification basis is historical rc6.
- [`docs/security.md`](../security.md) is the current detailed software boundary and limitations document; it is a product contract, not a C4 inventory.
- [`docs/plans/2026-08-23-001-software-beta-and-optional-hardware-mode-plan.md`](./2026-08-23-001-software-beta-and-optional-hardware-mode-plan.md) records the software/hardware split and historical delivery evidence.

### Required architecture artifacts

- **Slice 1 creates `docs/architecture/software-vault-lifecycle.md`.** It contains exactly one Mermaid Container diagram for CLI dispatch, lifecycle locking, backup validation, the internal file-publication authority, and the SQLite DB/WAL/SHM boundary. Text below the diagram describes the healthy-live and damaged-live branches, intent/pre-state/post-state journal protocol, restartable rollback, and post-publication validation; no second Mermaid sequence is needed.
- **Slice 2 creates `docs/architecture/system-context.md`.** It contains exactly one Mermaid system-context diagram naming the operator, coding agent, Keyclasp software CLI, OS authorization service, trusted child, local vault, and operator-managed backup storage. Text marks external snapshots, credential providers, hardware custody, and any remote secrets service outside the software system.
- **Slice 3 updates `docs/architecture/operator-authorization.md`.** It retains exactly one Mermaid authorization-flow diagram, replaces the rc6 basis only after the final implementation is inspected, and shows helper-path verification, minimal-environment launch, interactive-key unlock, runtime selection, and the trusted-child/output-containment boundary.
- **Slice 4 verifies all three architecture documents against the frozen candidate.** Architecture documents describe inspected current state, not intended code. Any implementation deviation must update the document before qualification can pass.

### Intended boundary changes and ownership

| Boundary | Current owner | Required change | Slice owner |
| --- | --- | --- | --- |
| Complete SQLite state | Split implicitly between `vault.ts` and `recovery.ts` | `vault-files.ts` owns DB/WAL/SHM quiescence and durable publication; callers own meaning and authorization | 1 |
| Backup and restore | `recovery.ts` | Authenticate required key classes, use restartable file-set transactions, verify published readback, expose live-independent restore entry | 1 |
| CLI recovery dispatch | `cli.ts` | Route emergency restore before live parsing; leave ordinary commands fail closed | 1 |
| Custody and defaults | `vault.ts`, `policy.ts`, `cli.ts` | Authenticated default state, explicit machine opt-in, pending cleanup phase, key retirement, best-effort buffer clearing | 2 |
| Child output | `run.ts` | Correct streaming multi-value matching and nonzero leak outcome | 3 |
| macOS authorization helper | `biometric.ts`, native helper, build script | Verify installed helper, minimize launch environment, harden and reproduce the built helper | 3 |
| Release evidence | workflows, release scripts, docs | Freeze and qualify one artifact; preserve source, artifact, physical, external-review, and rollout evidence separately | 4 |

### Preserved invariants

- Shared command contracts contain scope, names, command metadata, and bounded status, never a vault key or secret plaintext.
- Software and hardware implementations do not import each other. Hardware status remains unavailable and cannot enroll, decrypt, recover, or launch a secret-bearing child.
- AES-256-GCM record AAD continues to bind vault, record, scope, name, record kind, format, and custody class. Key classes remain independent.
- Complete selection validation and required authorization occur before selected-value decryption or child launch. Empty or invalid explicit selection never widens to a whole-scope run.
- Project/environment scoping is namespacing, not caller isolation. Agent guidance continues to require explicit project, environment, and named secrets.
- Broad run, `get`, policy/default mutation, backup, and restore remain operator-authorized. `--allow-unsafe` never bypasses authorization.
- Every state-changing lifecycle operation uses the exclusive lock and either produces one verified old or new state or leaves a restartable authenticated transaction.
- Owner-only path checks, no-shell child launch, zero network, zero telemetry, hardware deferral, and preservation of failed/historical evidence remain in force.

## Delivery slices

Four slices are the minimum cohesive set. Combining Slices 1 and 2 would mix file-publication correctness with custody/product migration, making failures harder to isolate. Splitting F3-F6 would duplicate the same recovery state machine. Slice 3 is independent at the code boundary and may proceed alongside Slice 1; Slice 2 depends on Slice 1; Slice 4 depends on all three.

### Slice 1: Make backup and recovery correct for the complete vault state

**Covers:** F3, F4, F5, F6, WAL-safe restore, restartable rollback, emergency CLI restore, and required-key backup authorization.

#### Implementation

- Add the internal `vault-files.ts` authority described above. Enumerate DB, WAL, and SHM explicitly; never use a broad directory glob. Verify ownership, type, link count where available, and owner-only modes before moving a file.
- After backup authorization and complete validation, classify live state without treating `SQLITE_BUSY` or file-identity movement as damage. For healthy live state, exclude observable external holders, copy the exact closed DB/WAL/SHM state into transaction-owned staging, checkpoint committed WAL content only in the copy, recheck the raw live inventory, and preserve those exact raw files as the rollback set. For proven damaged live state, do not parse or checkpoint the raw database; record and quarantine the complete raw DB/WAL/SHM and managed-file set. Failure to exclude an observable writer, close, inventory, hash, or sync stops before replacement.
- Extend the restore journal to authenticate the transaction ID, phase, every managed file and sidecar, and an ordered operation list. Each operation records its complete pre-state and post-state plus a completion marker. Persist and fsync intent before mutation; after mutation and sync, persist completion. On restart, validate both alternatives: execute from a complete pre-state or record completion from a complete post-state. Reject a mixed/unknown state without attempting another rename or unlink.
- Make staging cleanup, healthy/damaged rollback, committed cleanup, and rollback cleanup use the same idempotent transition function. Inject failure before the mutation, after the mutation but before completion is recorded, and after completion is recorded for every rename, unlink, and sync. Each retry validates observed state before advancing.
- After publishing backup files and before marking committed, rehash the published files against the authenticated manifest, open the restored DB with no old sidecar present, require `PRAGMA quick_check` to return `ok`, and verify vault ID, bundle generation, policy anchor, key-class inventory, manifest authenticators, and every record's schema/AAD/key-class authentication without logging or retaining plaintext. A mismatch rolls back. Focused tests and final qualification also require `PRAGMA integrity_check` to return `ok`; synthetic canary equality belongs only to those tests, never production restore logic.
- Dispatch `backup restore` through the live-independent CLI path. Authenticate against backup metadata and keys, not live metadata. Treat proven damaged current DB/key/policy/pending journals as rollback material only after backup authorization and validation. Treat busy or changing state as a writer-exclusion failure, not as permission to use the damaged-live branch.
- Document that the lifecycle lock coordinates Keyclasp only. The restore runbook requires all external SQLite clients to stop and uses observable busy/file-identity checks as fail-closed guards, but it cannot make an uncooperative raw-file client participate in the protocol.
- Refactor backup creation so authorization precedes key access and a consistent inventory determines required key classes. Preserve the current macOS Touch ID and Linux passphrase authorization rules.
- Upgrade the audit recovery probes into assertions under `tests/recovery.test.ts`, `tests/platform-authorization.test.ts`, and black-box CLI integration tests. Keep the original probe files unchanged as failure evidence.

#### Acceptance criteria

- A fresh writer process commits and exits without SQLite close; healthy-live restore proves the committed WAL state in a transaction-owned checkpointed copy, preserves the byte-exact raw DB/WAL/SHM set for rollback, leaves no attachable old WAL/SHM beside the restored DB, returns the exact backup value in a second synthetic process, and reports no success before authenticated record validation passes.
- A corrupt synthetic DB with arbitrary WAL/SHM bytes reaches the damaged-live branch only after backup authorization and validation, is quarantined without parsing/checkpointing, and remains available as bounded forensic/rollback evidence. A busy healthy database and a changing file identity stop before any quarantine or replacement.
- Fault injection at every stage copy, journal-intent publication, live-to-previous rename, sidecar isolation, staged-to-live rename, file/directory sync, validation, previous-file restore, staged cleanup, and previous cleanup covers three points: before mutation, after mutation before completion persistence, and after completion persistence. Fresh-process recovery validates the complete pre-state or post-state at each point; at least two consecutive recovery interruptions still converge to the complete old or new set with no manual edit, orphan transaction file, or mixed generation.
- `keyclasp backup restore` succeeds from valid machine-only, mixed, and all-interactive backups when live key, DB, policy, or ordinary recovery journal is individually corrupt or absent. Wrong/cancelled authorization, a corrupt backup, `SQLITE_BUSY`, and observable external file changes leave the complete live file set byte-for-byte unchanged.
- A macOS machine-only CLI backup performs one successful authorization, requests no interactive key, and produces a restorable authenticated backup. Mixed and all-interactive cases request exactly their required keys. Linux machine-only remains blocked before backup creation.
- Existing backup tamper, portability, permissions, migration, concurrent lifecycle, and policy-authentication tests remain green.
- `docs/architecture/software-vault-lifecycle.md` matches the accepted implementation and tests.

#### Regression check

Run the focused recovery, lifecycle-lock, platform-authorization, permissions, migration, and CLI integration suites first; then run the complete source suite. Re-run `recovery-probes.mjs` through a corrected assertion wrapper: every former vulnerability boolean must be false or replaced by an explicit safe-state assertion.

#### KC-W01 implementation record — 2026-09-05

**Outcome:** Slice 1 is implemented and locally verified from the required starting revision. The overall plan remains `in-progress`: Slices 2-4, immutable-artifact qualification, physical platform evidence, external assurance, publication, and operator rollout are separate gates and are not implied by this source result.

**Implemented boundaries:**

- Backup authorization now precedes key access. The consistent record inventory requests exactly the machine and/or interactive key classes it contains, and the manifest is authenticated by every required class.
- Emergency CLI restore is dispatched under the exclusive lifecycle lock before ordinary live-key parsing, migration, or journal recovery. Backup authorization and complete backup validation remain mandatory; there is no unsafe bypass.
- `src/vault-files.ts` owns strict owner/type/mode/link checks, exact present-and-absent inventories, observable external-client exclusion, stable SQLite-copy checkpointing, authenticated publication/rollback operations, and published SQLite validation.
- Restore uses transaction-specific journal keys, deterministic journal temporaries, authenticated v2 phases, exact pre/post hashes, and restartable staging, publication, rollback, and cleanup. Recognized older or interrupted recovery topology is bounded and retained as evidence during authorized emergency restore.
- Live classification never opens or mutates the raw SQLite files. It copies the stable DB/WAL/SHM set into transaction-owned staging, validates and checkpoints that copy, rechecks the raw inventory, and preserves the byte-identical raw set as rollback material. This deliberate implementation refinement supersedes the earlier wording that checkpointed the rollback database in place: it removes an unjournaled live mutation while still proving committed WAL semantics and preserving exact forensic bytes.
- Post-publication admission rejects old sidecars and requires authenticated file hashes, SQLite checks, vault and bundle identity, custody inventory, policy commitment, and every record's schema/AAD/GCM authentication without retaining plaintext.
- One indexed test harness covers every observed copy, journal publication, rename, unlink, file/directory sync, validation, and directory-cleanup primitive at the three required interruption points. Its fixture has distinct old/new vault IDs, keys, authenticated policies, and DB/WAL/SHM topology; recovery must byte-match one complete file-set generation before canary readback. Dedicated matrices cover reverse-order rollback operations and repeated recovery interruption.

**Verification and review:**

- `npm run build --silent` passed.
- The indexed primitive matrix passed all 597 fresh-process interruption/recovery cases: 199 observed primitives at three boundaries. Each case byte-matched the complete old or complete new managed-file inventory, admitted its corresponding synthetic canary, and left no transaction orphan.
- The preserved audit probes now report `restoreReplayedWrongLiveValue=false`, `secondRecoveryRejected=false`, `rollbackJournalStillPresent=false`, `cliRestoreRejectedCorruptKey=false`, and `machineBackupFailsAfterAuthorization=false`. F1 custody remanence and F2 output containment still reproduce and remain assigned to Slices 2 and 3.
- Five focused non-recovery files passed 99 tests with 3 host/platform skips. The serialized complete suite passed 29 files and 504 tests with 3 skips; its only failure was the pre-existing clean-helper reproducibility check. The check was neither weakened nor excluded.
- PR validation exposed Linux portability defects in external-client exclusion and one test fixture. Following every same-user `/proc/<pid>/fd` target with `stat`, then treating kernel-hidden descriptor links as fatal, made restore fail closed on unrelated GitHub runner processes. Linux inspection now reads descriptor links, skips `EACCES`/`EPERM` entries that are outside the documented observable-process guard, and compares only absolute managed-vault paths; exact observable live holders remain rejected. The Linux integration fixture now places its managed backup under a user-owned parent instead of root-owned `/tmp` and exercises authorization through a real pseudo-terminal. Six focused recovery, authorization, and CLI checks passed as an unprivileged user in a Node 24 glibc Linux container, including a regression that injects the runner's kernel-hidden descriptor condition.
- Independent concurrency review reported no material finding. Independent security review findings for cleanup journaling, nested pending evidence, operational-versus-semantic classification, transaction-key recovery, raw-live mutation, file-inventory races, malformed schemas, portable-conversion sidecars, and full-generation matrix fidelity were fixed with regressions. The final security and concurrency reviews reported no remaining material implementation or acceptance issue in KC-W01.
- Architecture verification inspected the accepted source boundaries and tests. `docs/architecture/software-vault-lifecycle.md` contains exactly one Mermaid `C4Container` diagram and matches the classification-copy/raw-rollback implementation.

**Intentionally unexecuted or blocked gates:** no real vault access, physical authentication, global installation, external assurance, immutable-artifact build, deployment, publication, operator migration, or Git mutation occurred. Linux-only black-box cases remain skipped on this macOS host. The existing arm64 helper clean-build byte mismatch remains a release-blocking Slice 3/4 reproducibility issue and was preserved unchanged.

### Slice 2: Make custody tightening durable and sensitive storage safe by default

**Depends on:** Slice 1.

**Covers:** F1, custody remanence, safe storage defaults, key retirement, memory limitations, backup/rollback limitations, and authenticity-versus-freshness documentation.

#### Implementation

- Version the authenticated policy/default contract. Add a vault-wide fallback custody state with exact-secret, exact-scope, project-only, and environment-only rules retaining their current precedence over it.
- Change fresh initialization to interactive-by-default. Require `--machine-only` for an empty-passphrase vault. Add authorized `lock --default` and `unlock --default` operations rather than another unrelated custody command.
- Migrate existing vault metadata without silently reclassifying it: record `legacy-machine` fallback, show it in `status`, and provide an authorization preview with affected machine/interactive counts before the operator changes the default. Normal existing named runs remain compatible until that explicit operation.
- Set and verify `PRAGMA secure_delete=ON` on every writable vault connection before record mutation. A custody-tightening operation commits policy, record AAD/ciphertext, and a durable `sanitization-required` phase, then checkpoints/truncates WAL, compacts the database, removes obsolete sidecars through Slice 1's file authority, and reopens the closed state for structural and cryptographic validation before clearing the phase or printing success. Fresh-process forensic inspection remains a test and qualification gate, not production code.
- Recovery of a pending custody transition performs the same sanitization before ordinary CLI dispatch. It may restore the pre-transition logical state or complete the new state according to the authenticated database commit point, but it may not clear the journal merely because policy and database generations match.
- When no machine records remain, generate a new machine key, update the authenticated bundle/key check and generation, clear the old Keyclasp-owned key buffers, and remove transaction material before completion. When machine records remain, prove those records still decrypt and transitioned records do not appear in readable DB/free-page/WAL/SHM bytes under the retained machine key.
- Overwrite Keyclasp-owned `Buffer` key material before replacement or cache clearing and minimize temporary decrypted buffers. Do not promise erasure of JavaScript strings, process environments, OS caches, swap, crash collectors, filesystem snapshots, or prior copies.
- Update security, backup, recovery, migration, help, README, getting-started, FAQ, and installed agent guidance. State that backup MACs prove authenticity, not newest-state freshness; copied snapshots and backups remain valid; locking and passphrase changes do not revoke copied credentials; retained copies need a declared retention policy; provider-side rotation is required when revocation matters.

#### Acceptance criteria

- [x] The retained 500-record forensic probe, run after a normal completed lock and after recovery from every cleanup boundary, finds zero complete transitioned plaintexts decryptable with the current machine key in closed `vault.db`, WAL, or SHM. Current rows are interactive and resolve only after interactive unlock.
- [x] A partial lock that leaves machine records proves those records still work while no transitioned record is recoverable from current files with the retained machine key. An all-interactive transition also proves the old machine key no longer authenticates the active bundle/key check.
- [x] No command reports a custody tightening complete while `sanitization-required` exists. Normal commands fail closed or resume under the exclusive lock.
- [x] Fresh `keyclasp init` cannot create a machine default from an empty response; `init --machine-only` is explicit. A passphrase vault stores new records as interactive unless a more-specific authorized unlock rule applies.
- [x] Existing vaults preserve unattended compatibility during format migration, display `legacy machine default`, and become production-eligible only after an explicit default decision. Default mutation previews and tests cover zero, partial, and whole-vault transitions.
- [x] Tests observe best-effort zeroing of owned key buffers on success and error paths while documentation states the untestable memory limits without claiming secure JavaScript-string erasure.
- [x] `docs/architecture/system-context.md` and all user-facing custody/backup text describe the same boundary.

#### Regression check

Run dual-key custody, key-bundle, key invariant, policy, migration, backup/restore, permissions, and CLI integration suites; then the complete source suite. Run `custody-probe.mjs` only as preserved historical reproduction and a new regression derived from it as the pass/fail gate.

#### KC-W02 implementation record — 2026-09-05

**Outcome:** Slice 2 is accepted from source on the working tree based on `c0d96fc9f4fc79db4da44d64d8c9e48421d24b9f`. This does not qualify or activate a release. The overall plan remains in progress because Slices 3 and 4 are not complete.

**Implemented boundaries:**

- Policy v3 authenticates a vault-wide `interactive`, `machine`, or migrated `legacy-machine` default while retaining the existing rule precedence. Fresh CLI initialization requires a passphrase unless `--machine-only` is explicit. Authorized `lock --default` and `unlock --default` preview affected custody counts before mutation.
- Every writable vault connection enables and verifies SQLite secure deletion. Tightening commits a durable sanitation phase with record custody and the policy anchor; completion closes the live database, checkpoints and truncates WAL, switches to delete journaling, compacts, removes named sidecars, syncs, runs full integrity validation, and authenticates all current records before clearing the phase.
- A versioned sanitation gate covers pre-KC-W02 dual-key vaults and legacy migrations even when the triggering command changes no record class. Machine-only inventories retain unattended operation. Mixed or all-interactive inventories require the interactive key for complete validation, and an all-interactive legacy migration carries its passphrase through sanitation and machine-key retirement in the first invocation.
- A whole-vault transition rotates the machine data key and advances the authenticated bundle/database generation only after cleanup. Partial transitions retain the machine key and prove remaining machine records still resolve. Keyclasp-owned machine, interactive, wrapping, and temporary plaintext buffers are overwritten on a best-effort basis on tested success and error paths.
- Startup gives an authenticated managed-restore journal priority over database-backed sanitation or older custody recovery. A corrupt-live/nested-custody fresh-process regression proves restore recovery is consumed before damaged live state is parsed.
- Documentation and the installed agent skill state the memory, same-user, backup-freshness, external-copy, retention, and provider-rotation boundaries without claiming revocation or protected memory.

**Verification and review:**

- `npm run build --silent` passed, and `git diff --check` passed.
- Eleven focused custody, key-bundle, key-invariant, policy, migration, CLI, format, lifecycle, and vault files passed 231 tests with 4 host/platform skips. After strengthening the acceptance fixtures without changing implementation, the 500-record custody file passed 12 tests and the policy file passed 46 tests.
- The complete serialized source suite ran 32 files: 529 tests passed and 5 host/platform cases skipped. Its only failure is the preserved pre-existing clean-helper byte-equality gate in `tests/biometric.test.ts`; the checked-in app still differs from a clean build. That release-blocking Slice 3/4 evidence was not weakened or excluded.
- The preserved historical `custody-probe.mjs` reported `secureDelete=1`, 500 interactive current records, an unavailable interactive key in the fresh process, and zero transitioned values recoverable without the passphrase or a pre-lock snapshot. The new gate additionally covers a normal completed lock, every cleanup interruption through post-clear validation, partial custody, pre-versioned vaults, legacy migration, key retirement, and fresh-process DB/WAL/SHM inspection.
- Independent concurrency review found the managed-restore startup-order defect; the ordering fix and fresh-process regression passed. Independent security review found the pre-versioned sanitation gap, machine-only upgrade prompt regression, and first-invocation passphrase-carry gap; all were fixed with regressions. Final security re-review reported no remaining material blocker, and concurrency review reported no other premature-success, mixed-generation, record-loss, or deadlock path.
- Architecture verification found exactly one Mermaid `C4Context` diagram in `docs/architecture/system-context.md` and exactly one Mermaid `C4Container` diagram in `docs/architecture/software-vault-lifecycle.md`; both match the accepted source and recovery ordering.

**Intentionally unexecuted or blocked gates:** no real vault or credential access, physical authentication, global install, immutable-artifact build, external assurance, deployment, publication, operator migration, or Git mutation occurred. The Linux passphrase-enrollment black-box case remains platform-gated on this macOS host. The existing macOS helper clean-build mismatch remains a separate release blocker for Slices 3 and 4.

### Slice 3: Repair streaming output containment and harden macOS authorization

**Dependency:** None for implementation; final acceptance joins Slices 1 and 2 in Slice 4.

**Covers:** F2, streaming redaction, trusted-child limitations, helper environment/path/signature hardening, and helper build reproducibility inputs.

#### Implementation

- Replace the carry decision with a streaming matcher that scans complete matches before calculating the longest suffix that is a strict prefix of any selected value. Specify deterministic precedence for duplicate and overlapping values without ever emitting a byte/character belonging to a possible complete match.
- Keep one decoder and matcher per output stream. Flush EOF only through the matcher. On a match, emit only the redaction marker, stop forwarding later output, terminate the entire supervised child process group, and return the documented nonzero leak result regardless of child exit timing.
- Add table/property tests for every split position of self-overlap, repeated characters, one selected value that prefixes/suffixes another, duplicate values, simultaneous stdout/stderr output, adjacent matches, large output, and Unicode split at every byte boundary. Add real-child EOF tests for `abcd123a` and repeated/overlapping canaries.
- Launch the helper with a fixed minimal environment required by the qualified macOS path. Explicitly remove `DYLD_*`, `LD_*`, `NODE_OPTIONS`, language/runtime injection variables, inherited credentials, and unrelated `KEYCLASP_*` values. The helper continues to receive only bounded reason text on stdin.
- Before launch, verify the expected regular file and bundle layout, no symlink, current-user/root ownership as selected by install mode, non-writable ancestors, executable mode, packaged manifest hash, strict code signature, and expected identifier/designated requirement. A mismatch is unavailable/blocked before any fallback, unlock, decryption, or mutation.
- Harden the Objective-C build with a pinned deployment target, warnings-as-errors, stack protection, explicit SDK, no packaged debug symbols, reviewed frameworks, `codesign --options runtime`, and no unreviewed entitlements. Record Xcode, clang, linker, SDK, codesign, architecture, and flags in generated release metadata. The real helper must still complete approval, cancellation, and timeout flows under that signature.
- Preserve the same-user statement: file/signature checks protect the distributed path and catch accidental replacement; they do not stop same-user source modification, library injection into Keyclasp itself, or a custom caller from bypassing the software helper.

#### Acceptance criteria

- Across every generated chunking and EOF case, no complete selected value reaches the captured stdout/stderr transcript; every detected leak returns nonzero and leaves no child or descendant running.
- The exact `abcd123a` reproduction is redacted, classified as a leak, and nonzero in both stdout and stderr variants.
- Helper tests prove injection variables and synthetic credentials are absent from its environment, valid reason input still reaches the real compiled helper, and each path/owner/mode/hash/signature/identifier failure blocks before helper execution or vault access.
- Two clean helper builds using the declared compiler/linker/SDK and flags are byte-identical before release signing. A toolchain mismatch, including linker `27037.0` versus `27037.1`, fails the reproducibility gate rather than skipping it.
- Existing unsafe-command, `--allow-unsafe`, authorization ordering, cancellation, timeout, signal, prompt, and no-shell tests remain green.
- `docs/architecture/operator-authorization.md` is updated only after these boundaries are verified.

#### Regression check

Run run/runtime, software-runtime, biometric, package-contents, authorization-matrix, and real-child integration suites; then the complete source suite. Convert `runtime-probes.mjs` scenarios into safe assertions while preserving the audit copy unchanged.

#### KC-W03 implementation record — 2026-09-06

**Local state:** implemented as uncommitted working-tree changes based on exact revision `c0d96fc9f4fc79db4da44d64d8c9e48421d24b9f`. The stream guard now evaluates complete matches before retaining possible prefixes, uses independent incremental UTF-8 decoders and matchers, rejects values whose UTF-8 representation would change before injection, stops both output streams on the first match, returns leak exit code 2, and supervises the signalable child process group through `SIGTERM` and bounded `SIGKILL`. An `EPERM` liveness result produces an explicit containment warning rather than being treated as successful termination.

The macOS CLI validates the packaged helper before any stateful-command lifecycle inspection, recovery, migration, or vault access, and revalidates immediately before authentication. Validation covers the exact bundle layout, file identity, ownership, modes, write-granting ACLs, links, hashes, arm64 architecture, strict code signature, identifier, designated requirement, hardened-runtime flag, and absence of entitlements. The helper receives only fixed path, locale, and temporary-directory environment values. The native build declares its SDK, deployment target, architecture, compiler flags, frameworks, signature options, and exact qualification toolchain. `--check` reproduced two byte-identical unsigned builds and matched the packaged ad-hoc hardened-runtime candidate and metadata. The candidate remains explicitly `qualified: false`.

Focused runtime, biometric, package, workflow-contract, and software-runtime checks passed 110 tests. A separate CLI integration run passed 37 tests with 3 host/platform skips. The complete source suite passed 31 files and 528 tests with 4 skips. The release inventory check passed, `git diff --check` passed, the architecture document retained exactly one Mermaid diagram, and the historical audit, biometric receipt, and release evidence remained byte-unchanged. The retained runtime probe now reports `rawSecretEscaped=false` and leak exit code 2; its custody and recovery fields remain the accepted Slice 1/base state and were not reclassified as Slice 3 evidence.

Independent security review found four connected failure modes across three boundary findings: malformed UTF-16 changed during child environment encoding, `EPERM` was mistaken for completed descendant termination, macOS write-granting ACLs were ignored, and helper preflight followed possible startup recovery. Each was reproduced, fixed, and covered by a regression. The review's final pass reported no remaining KC-W03 finding. `docs/architecture/operator-authorization.md` was then verified against `src/cli.ts`, `src/biometric.ts`, `src/owner-only-path.ts`, `src/run.ts`, the native helper/build inputs, candidate metadata, and focused tests.

**Intentionally unexecuted or blocked gates:** no real vault was accessed; no physical Touch ID approval, cancellation, unavailability, or timeout flow was performed; no real privilege-changing descendant was created; full Xcode was unavailable and the candidate records that fact; no Developer ID signing, notarization, immutable artifact freeze, clean installation, supported Linux-host qualification, external professional assurance, release, deployment, publication, operator rollout, or Git mutation occurred. These remain Slice 4 gates. Slice 2 custody work was not imported into this checkout.

### Slice 4: Qualify the final artifact, obtain assurance, and stage operator rollout

**Depends on:** Slices 1-3 accepted from source with no unresolved release-blocking finding.

**Covers:** reproducible builds, final-artifact/platform qualification, independent assurance, documentation, incident readiness, and production completion gates.

#### Implementation and evidence stages

1. **Freeze source and build inputs.** Choose the next prerelease version; freeze the source revision, lockfile, compiler/linker/SDK, Node/npm, locale/time inputs, native prebuild hashes, helper flags, workflow actions, and package allowlist. Build twice in independent clean environments with the same declared inputs. Require byte-identical unsigned helpers and npm tarballs. A canonical content match may diagnose a failure but cannot pass this gate. Remove or control each nondeterministic archive input; never waive a binary-content difference with disassembly or string similarity.
2. **Freeze one candidate.** Store its SHA-256, npm integrity, canonical path/mode/size/content manifest, helper unsigned and final signed hashes, signature identity, SBOM, licenses, dependency/build-script inventory, source tree manifest, and provenance. Publish and install only that file; never rebuild at publication time.
3. **Run source and exact-artifact gates.** Run the complete suite with no F1-F6 or helper-equality exclusion, static/type/format checks, dependency advisory and malicious-package checks, package/public-export checks, secret scanning, and install-script review. Run prebuilt and forced-source `better-sqlite3` paths.
4. **Run the supported platform matrix.** Against the same artifact, test macOS arm64 and glibc Linux arm64/x64 on Node 24 and 26. Repeat fresh init, explicit machine init, legacy-default migration, named/broad runs, lock/unlock/inherit/default transitions, backup creation, WAL-safe restore, emergency restore, interrupted recovery, uninstall/reinstall, paths with spaces/Unicode, signals, cleanup, and negative authorization. Unsupported macOS x64, musl, Windows, other Node versions, and hardware mode must fail before vault creation or mutation.
5. **Collect physical evidence.** On a supported physical macOS arm64 machine, exercise the exact packaged helper for approval, cancellation, unavailable biometry, locked/mixed operations, machine-only backup, emergency restore, and post-install signature/path checks. On physical or clean glibc Linux targets, exercise one-passphrase authorization/unlock, backup/restore, interruption recovery, and machine-only gated rejection. Restore backups on each supported target class and verify bounded metadata plus synthetic canary results without printing secrets.
6. **Reconcile architecture and product text.** Verify the three architecture documents against candidate source. Align CLI help, README, security model, support matrix, commands, getting started, FAQ, recipes, installed skill, release notes, recovery/runbooks, and receipt. State software memory limits, same-user and trusted-child boundaries, metadata exposure, backup portability/retention/freshness, external snapshots, credential rotation, helper distribution identity, unsupported platforms, and hardware unavailability.
7. **Commission independent assurance.** Give an external reviewer the immutable source, candidate, build recipe, F1-F6 regressions, fault matrix, architecture, threat model, and both old and new receipts. Scope review to custody transitions/remanence, SQLite concurrency and recovery, backup authorization, CLI emergency recovery, streaming output, helper/build chain, packaging, and documented residual risks. A source or artifact change in response creates a new candidate and repeats all affected gates.
8. **Prepare operator rollout without executing it.** Write a stepwise runbook for preflight, version/hash verification, owner-only backup destination, backup restore drill on an isolated supported host, process shutdown, install, explicit default decision, migration, status/readback, retained-copy inventory, credential rotation, rollback criteria, incident preservation, and uninstall. Separate commands that read the vault from those that mutate it and require explicit rollout authorization.

#### Acceptance criteria

- One release receipt links the exact source, lockfile, build environment, artifact hashes, manifests, complete test results, supported/unsupported matrix, physical receipts, independent-review report, architecture revision, residual limitations, and operator runbook. Evidence contains no credential values.
- Clean builds satisfy the reproducibility rule without excluding the helper equality test. The final signed helper and tarball used in every platform test match the candidate receipt immediately before and after testing.
- Every supported platform/Node/native-build cell passes; every unsupported cell fails closed before state creation. No platform skip is counted as supported evidence.
- Physical macOS authorization and Linux interactive/recovery receipts identify the same candidate. Synthetic source tests or a mocked authorizer are not substitutes.
- The independent review reports no unresolved P1/P2 or equivalent release-blocking issue. Its scope and limitations are published accurately; it is not described as proof of no vulnerabilities.
- Historical audit and rc receipts remain unmodified and are linked as prior evidence. New evidence uses a new dated directory and never overwrites a failure.
- The operator runbook has an explicit rollback point and explains that a pre-fix copy, filesystem snapshot, or retained backup may still contain machine-decryptable ciphertext. It requires provider-side rotation when those copies must be revoked.

## Consequential decisions and external gates

Local implementation can start without these answers. They must be resolved before the named completion state.

| Decision or gate | Required owner | Deadline | Effect if unresolved |
| --- | --- | --- | --- |
| Accept the OS-user/trusted-child software threat model, or require brokered/hardware same-user resistance | Product/operator | Before final production profile approval | Stronger isolation starts a separate design and qualification effort; do not enlarge this software release's claims |
| Choose whether existing production vaults move to interactive default or explicitly retain unattended machine default | Operator, after migration preview | Before real-vault rollout | Legacy machine default remains usable but not qualified as the secure production default |
| Define retained-backup/snapshot inventory, retention, and credential rotation scope | Operator/security owner | Before rollout completion | Local cleanup cannot revoke external copies; affected credentials remain potentially recoverable from retained state |
| Provide supported physical macOS and Linux targets | Release owner | Slice 4 platform stage | Source fixes may complete, but artifact qualification remains incomplete |
| Choose and provide the final macOS distribution signing identity; Developer ID/notarization is required for a general third-party distribution claim | Release owner | Before candidate freeze | A local/ad-hoc artifact may be qualified only for an explicitly local, same-user-trusted profile |
| Engage an independent security reviewer | Product/security owner | After candidate freeze, before production approval | No password-manager-equivalent or general high-value-credential assurance claim |
| Authorize Git, publication, installation, and real-vault migration separately | Operator | After all preceding gates | Candidate remains unshipped and production state unchanged |

## Production completion gates

The plan is complete only when all applicable gates below have durable evidence.

### Gate A: Local remediation complete

- F1-F6 fail on the frozen audit revision and pass as corrected regressions on the new source.
- Slices 1-3 acceptance and full-suite checks pass.
- No unresolved release-blocking correctness, security, concurrency, simplicity, or test finding remains.
- Architecture and user-facing documents match inspected implementation.

### Gate B: Artifact qualification complete

- One immutable candidate passes reproducible-build, dependency, package, clean-install, exact-artifact, supported-platform, unsupported-platform, physical authorization, backup/restore, and crash-recovery gates.
- Receipt hashes identify the same file throughout; no local or CI rebuild is substituted.
- Hardware remains disabled and excluded from claims.

### Gate C: Independent assurance complete

- The independent report covers the frozen source/artifact and targeted failure classes.
- Every release-blocking finding is fixed and the affected Gate A/B work repeated on a new candidate.
- Residual risks and the assurance scope are explicit.

### Gate D: Operator rollout complete

- Separately authorized backup, restore drill, install, default-custody decision, migration, readback, and rollback checks pass on the real target.
- Retained pre-fix files and backups are inventoried under an approved retention decision.
- Credentials are rotated where prior copies or actual output exposure must be revoked.
- Publication/registry verification, if authorized, uses the frozen artifact and records post-publication integrity and a narrow secret-safe smoke test.

Until Gates A-C pass, the 2026-09-05 **do not approve for general production storage** verdict remains in force. Until Gate D passes, the operator's production vault and installed runtime remain unchanged.

### KC-Q01 qualification record — 2026-09-06

**Outcome:** not qualified. KC-Q01 froze source `31aac732317e40597eeee02695b019a2045228ad` and built one unpublished candidate with SHA-256 `7fdf6c4fbd09a4e2d0e2d7203227ffa11f080658d58e379480f3761878042323`. Two clean temporary builds produced byte-identical unsigned helpers and npm tarballs. The candidate, manifests, inventory, receipt, platform matrix, assurance handoff, physical checklist, and operator runbook are under [`docs/releases/2026-09-06-security-qualification/`](../releases/2026-09-06-security-qualification/README.md).

**Passed evidence:** the TypeScript build, generated inventory check, JavaScript syntax checks, canonical 171-file package manifest, full and production-only npm advisory checks, macOS arm64 Node 24/26 prebuilt and forced-source installs, exact-candidate F1-F4/F6 regressions, package boundaries, hardware-disabled status, and musl arm64/x64 fail-closed checks passed. The 30 source-test files outside the two failing files passed 516 tests with 5 platform skips. All three architecture views match the frozen combined implementation and retain one Mermaid diagram each.

**Failed evidence:** Gate A fails because the packaged helper metadata at the frozen source still names pre-merge revision `c0d96fc9f4fc79db4da44d64d8c9e48421d24b9f`, and one status-copy assertion expects `not inspected` while the CLI prints `not displayed`. Aggregate isolated source results are 551 passed, 5 skipped, and 2 failed; the monolithic run was stopped after those failures while the long recovery matrix was still progressing, then the remaining 30 files completed separately. Gate B fails because every available glibc Linux arm64/x64 Node 24/26 artifact cell failed to finish guarded and raw wrapper process-group supervision within 10 seconds after `SIGTERM`. It also fails because Node 22 installation only warned and `init --machine-only` created a vault instead of rejecting the unsupported runtime before state creation. Shellcheck reported existing SC1007/SC2016 findings.

**Unavailable or unexecuted gates:** exact-host macOS x64 and Windows checks, physical macOS Touch ID, physical Linux authorization/recovery, Developer ID signing and notarization, a dedicated malicious-package scanner, external independent assurance, CI, publication, global installation, real-vault migration, credential rotation, and rollout were not executed. The package version remains `0.2.0-beta.1`; KC-Q01 is unique by candidate ID and hash, not by a new prerelease version. Gates A-D remain open, and the general-production denial remains in force.

### Post-KC-Q01 blocker remediation — 2026-09-06

Implementation `e6e2de43b7d6a4168ab7a16278487fe20eb3b100` fixes the three local blockers recorded above without changing the failed KC-Q01 candidate or receipt. The helper metadata now names the merged source, its clean-build check accepts that recorded revision only while it remains an ancestor of the current source, and status reports that values are not inspected. The complete source suite passed in one uninterrupted run: 32 files, 554 tests passed, and 5 platform cases skipped.

Linux process-group supervision now distinguishes a zombie-only group from one with a live member. One diagnostic package passed all eight glibc Linux Node 24/26 arm64/x64 prebuilt/source cells, including bounded guarded and `--allow-unsafe` signal relay. The x64 cells ran under local emulation. Node 22.23.2 failed in the install hook; after a forced scripts-disabled install, the runtime also rejected `init --machine-only` before creating the vault directory.

These are source and diagnostic-package results, not a new candidate. Gate A and Gate B remain formally open until the reviewed release revision has a new prerelease version, two clean builds produce one reproducible replacement artifact, and the affected checks pass against that exact artifact. Physical checks, independent assurance, signing, CI, publication, installation, and rollout remain separate gates.
