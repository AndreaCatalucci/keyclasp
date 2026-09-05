**Keyclasp security audit — 5 September 2026**

**Verdict: do not approve the reviewed implementation for general production storage of sensitive credentials.** Three reproduced high-priority defects affect confidentiality or restored-state integrity. Three additional recovery defects affect availability. The machine-custody default also falls below the expected protection of a passphrase-based password manager. Fixing these defects and repeating qualification is necessary before reconsidering this verdict.

Reviewed source: `d94189b30fb5e52ee5f4eb6435e96fe865c13142`, package version `0.2.0-beta.1`. The checkout was clean at audit start. This is a source review with synthetic adversarial tests, not a professional independent certification or proof that no other vulnerabilities exist. No production vault, stored credential, or physical authentication session was accessed. Application source and release artifacts were not changed; this directory contains the report and synthetic probes.

The review covered software key custody, cryptography, record/policy integrity, CLI authorization and selection, child execution and output, filesystem protections, concurrent lifecycle operations, migration and managed recovery, test quality, package/install verification, release workflows, and the disabled hardware boundary. Independent security, correctness/concurrency, and tests/supply-chain perspectives completed; the primary reviewer reproduced the retained findings. Native hardware custody is unavailable and was not qualified. Historical physical receipts were read as historical evidence, not repeated or transferred to this source revision.

**Confirmed implementation findings**

Priority P1 means fix before production approval; P2 means a material defect that must also be addressed for dependable credential storage. Priorities describe concrete consequences, not a numerical CVSS assessment.

| ID | Priority | Finding | Evidence |
| --- | --- | --- | --- |
| F1 | P1 | Locking leaves older, machine-decryptable copies in the database | Fresh process recovered 50 of 500 locked synthetic secrets from the closed database, without the passphrase or a pre-lock snapshot |
| F2 | P1 | Output protection can emit the entire selected secret and return success | A child printed synthetic `abcd123a`; raw output escaped and exit status was 0 |
| F3 | P1 | Restore can replay the old live WAL over the verified backup | Restore returned success with no cleanup warnings; readback returned the later live value instead of the backup value |
| F4 | P2 | Interrupted rollback cannot resume | Second recovery rejected an already-restored file and retained the blocking journal |
| F5 | P2 | CLI restore cannot repair a corrupt current key | CLI rejected the key before restore authorization; the same backup restored successfully through the library |
| F6 | P2 | Machine-only backup creation requests a nonexistent interactive key | Successful authorization followed by the CLI unlock precondition fails because no passphrase is enrolled |

**F1 — Lock does not remove the previous custody representation.**

[src/vault.ts:2017](/Users/andreacatalucci/Developer/keyclasp/src/vault.ts:2017) updates records in place during a custody transition. SQLite has `secure_delete=0`. Some old record bodies remain in database free space, and the vault retains the machine key that decrypts them. The probe created 500 machine records, performed the actual policy/custody transition, closed the database, cleared cached keys, and launched a separate process. All current rows were interactive, yet the separate process recovered 50 complete credentials from the post-lock database using the current machine key and current record metadata. It never unlocked the interactive key. The recovery count depends on page layout; one recoverable record is sufficient to demonstrate the defect.

The attacker needs read access to the post-lock vault files and source-machine identity. Neither a pre-lock copy nor live process memory is required. This exceeds the documented limitation that another same-user process may request an *unlocked* secret: these records have successfully transitioned to interactive custody.

Correction: custody tightening must eliminate older decryptable representations from readable SQLite free pages and sidecars before reporting completion. Evaluate secure deletion, compaction, WAL checkpoint/truncation, and retirement of old machine keys as one crash-consistent transition. Verify the resulting closed files using forensic readback in a fresh process. Filesystem snapshots, external backups, and previously copied credentials remain outside in-place cleanup; the corresponding service credentials must be rotated when prior exposure needs to be revoked. Merely rewrapping a data key does not revoke old copies.

**F2 — Prefix buffering splits a complete match before scanning it.**

[src/run.ts:269](/Users/andreacatalucci/Developer/keyclasp/src/run.ts:269) calculates a possible prefix suffix, retains it, then scans only the flushed part. If a complete secret ends with its own prefix, a complete match is cut into two pieces. Neither piece matches during scanning. With `abcd123a`, the first write emits `abcd123` and end-of-stream emits `a`; the caller receives the full secret, and no leak is reported. The same issue occurs with repeated characters and other overlaps.

An ordinary trusted child accidentally printing its environment value is enough. The value is eight characters, meeting the documented scanning threshold, and no unsafe override is used. Correction: account for complete matches before deciding which incomplete suffix to retain. Add real-child EOF regressions plus every chunk split for self-overlap, repeated values, overlapping selected values, and Unicode. Existing tests at [tests/run.test.ts:231](/Users/andreacatalucci/Developer/keyclasp/tests/run.test.ts:231) do not cover these cases. Output masking will still be accidental-leak containment; it cannot constrain a malicious authorized child.

**F3 — SQLite sidecars survive restore publication.**

[src/recovery.ts:604](/Users/andreacatalucci/Developer/keyclasp/src/recovery.ts:604) calls `closeDb()`, which only closes the current process's cached database handle, then replaces managed files. `vault.db-wal` and `vault.db-shm` are not part of that replacement. A previous process can exit after committing without closing SQLite. In a fresh restoring process, closing an absent cached handle does not checkpoint that WAL. Opening the restored database subsequently replays the old live WAL.

The probe used a consistent backup, then a child writer that committed a different value and exited without closing. Restore succeeded with zero warnings, but readback returned the child writer's newer value. No malicious actor or concurrent writer is required. Correction: handle the complete live SQLite state under the lifecycle lock before replacement, preserve a consistent rollback image, prevent old sidecars from attaching to the restored database, and verify readback after publication. Do not simply unlink a WAL before preserving any data needed for rollback. Test fresh-process restore after abrupt writer termination.

**F4 — Recovery is not itself restartable.**

[src/recovery.ts:239](/Users/andreacatalucci/Developer/keyclasp/src/recovery.ts:239) requires every staged candidate to match the staged hash. Later, [src/recovery.ts:252](/Users/andreacatalucci/Developer/keyclasp/src/recovery.ts:252) renames previous files back into place and removes staging files while leaving the journal in the replacing phase. Interrupt recovery after the first rollback rename and its next invocation compares the restored old database with the new staged hash. It fails with `Managed-restore staged file "vault.db" failed journal authentication.` The retained journal prevents normal CLI startup.

Correction: record rollback progress or recognize authenticated files already rolled back. Inject failure after each mutation within recovery, then rerun recovery until it succeeds without manual state edits. Existing restore crash tests do not establish this property for a second interruption during recovery.

**F5 — Startup migration prevents emergency restore.**

[src/cli.ts:463](/Users/andreacatalucci/Developer/keyclasp/src/cli.ts:463) performs recovery/migration before dispatching `backup restore`. A corrupt non-v5 current key is routed through legacy parsing and rejected before the valid backup can replace it. The probe used a valid backup and a current key containing only synthetic corrupt bytes: CLI exit 1, unsupported-format error. The same backup restored through the library and recovered the expected synthetic record. [tests/recovery.test.ts:262](/Users/andreacatalucci/Developer/keyclasp/tests/recovery.test.ts:262) covers library restoration, not this CLI path.

Correction: provide an authenticated restore path that does not require parsing or unlocking damaged live custody state. Preserve the exclusive lifecycle and validate the backup before replacing anything. Add end-to-end CLI tests for damaged keys, databases, and pending journals; do not solve this by silently discarding journals on ordinary startup.

**F6 — Machine-only backup cannot pass the CLI unlock precondition.**

[src/recovery.ts:492](/Users/andreacatalucci/Developer/keyclasp/src/recovery.ts:492) unconditionally invokes `ensureUnlocked()` after operator authorization. The actual CLI callback at [src/cli.ts:59](/Users/andreacatalucci/Developer/keyclasp/src/cli.ts:59) throws when an interactive passphrase is absent. Consequently, an otherwise authorized macOS machine-only backup cannot proceed, despite the lower-level backup format supporting it. This is separate from the intentional Linux machine-only authorization rejection.

Evidence is source tracing and the authorized wrapper with a successful synthetic authorizer and the identical first CLI unlock check; physical Touch ID was not exercised. Correction: request only the key classes required for the backup, retaining mandatory operator authorization. Test the actual CLI/wrapper integration for a machine-only macOS vault as well as mixed and all-interactive vaults.

**Comparison with established solutions**

These are documented design comparisons, not claims that the other products have no vulnerabilities or that Keyclasp needs their cloud/team feature sets.

| Control | Established reference | Keyclasp assessment |
| --- | --- | --- |
| Password-based key protection | 1Password documents PBKDF2 at 650,000 iterations and combines the account password with a Secret Key. Bitwarden documents PBKDF2-SHA256 at 600,000 and an Argon2id option. KeePass supports configurable Argon2. | Interactive wrapping uses PBKDF2-SHA256 at 600,000 with a random salt. This is a defensible baseline; lack of Argon2 alone is not a production blocker. Passphrase strength and custody selection matter more than the small iteration-count difference. |
| Encryption and integrity | KeePass 2 authenticates encrypted database data and encrypts stored usernames, URLs, and notes as well as passwords. | AES-256-GCM with random 96-bit IVs and 128-bit tags, independent data keys, and AAD binding to vault/record/scope/name/class are sound choices. Names, scopes, timestamps and policy metadata remain plaintext. F1 shows why correct primitives alone do not ensure custody. |
| Runtime delivery | 1Password `op run` injects secrets into a subprocess and masks stdout/stderr by default. It also documents service-account scoping. | Named injection and no-shell launch are useful. Projects/environments are namespaces, not caller access control. F2 breaks masking even for ordinary exact-value output. |
| Memory exposure | KeePass documents encrypted sensitive memory where supported, best-effort erasure, and unavoidable plaintext during some operations. | Software Keyclasp keeps plaintext in JavaScript strings and environment objects; key clearing drops references. No comparable memory-isolation guarantee is established. The authorized child must be trusted. |
| Independent assurance | 1Password publishes security assessments; Bitwarden publishes third-party audits including source review and penetration tests. | Good local tests and package checks exist, but there is no professional independent audit. This review does not provide the same assurance. |

The comparison uses current primary documentation: [1Password key derivation](https://support.1password.com/pbkdf2/), [Bitwarden key derivation](https://bitwarden.com/help/kdf-algorithms/), [KeePass security](https://keepass.info/help/base/security.html), [1Password runtime delivery](https://www.1password.dev/cli/reference/commands/run), [1Password security assessments](https://support.1password.com/security-assessments/), and [Bitwarden audits](https://bitwarden.com/compliance/). The Secret Key comparison concerns protection against a server-side data theft; 1Password itself notes that a good account password is still needed against data acquired from an enrolled device.

**Design and assurance requirements beyond the defects**

1. **Make sensitive storage secure by default.** Initializing with a passphrase only enrolls an interactive key. New records default to machine custody at [src/cli.ts:623](/Users/andreacatalucci/Developer/keyclasp/src/cli.ts:623). The probe stored a synthetic secret after passphrase initialization and read it through a fresh named CLI run without the passphrase. Machine wrapping derives from public identity; it is not a hidden key or hardware attestation. For the requested production profile, default to interactive custody and require an explicit decision for unattended machine storage. A stronger unattended boundary needs protected key custody or a separately authenticated secrets service. This is an intentional current design, not an AES failure.
2. **Keep the same-user boundary explicit.** Another process can request unlocked names. The policy MAC key and mutable policy commitments do not establish independent authorization against an attacker controlling the same user's files. The software biometric helper can also be bypassed under attacker-controlled execution: a synthetic library injection changed helper exit 64 to 0 without Touch ID. This does not obtain an unknown interactive passphrase, and arbitrary same-user code manipulation is already outside the model. Cleaning helper environment and hardened signing are useful defense in depth; they do not create a brokered same-user isolation boundary.
3. **Separate authenticity from freshness.** Record AAD and generation consistency detect selected substitutions and mixed state. They do not prove that a complete copied vault snapshot is the newest state. Define rollback and retained-backup behavior explicitly. Locking or changing a passphrase cannot revoke credentials already copied elsewhere.
4. **Close the reproducibility evidence gap.** The local suite failed the helper source/binary byte-equality test. The bundled binary matches its checked-in manifest. A fresh build records linker version 27037.1 versus 27037.0 in the bundle; inspected disassembly, strings, and plist/resources matched. This supports a toolchain variation, not a tampering finding, but does not turn the failed assertion into a pass. Pin and record the qualification compiler/linker. [The CI workflow](/Users/andreacatalucci/Developer/keyclasp/.github/workflows/software-beta.yml:58) intentionally excludes that equality test; [the existing release receipt](/Users/andreacatalucci/Developer/keyclasp/docs/releases/0.2.0-beta.1-rc-receipt.md:40) documents this class of mismatch.
5. **Qualify the final artifact.** After fixing the findings, require the applicable platform suite, crash/recovery regressions, package and dependency verification, physical macOS authorization checks, interactive Linux checks, and backup restoration on supported target machines. Commission an independent security review focused on custody transitions and recovery before claiming password-manager-equivalent assurance for high-value credentials.

Positive evidence includes strict key-bundle parsing, authenticated record identities, independent machine/interactive keys, owner-only paths and macOS ACL handling, selection validation before decryption, lifecycle serialization, authenticated backup manifests, a small bundled runtime dependency tree, checked native prebuild hashes, commit-pinned workflow actions, and a hardware path that consistently reports unavailable. No additional cryptographic primitive defect was established in this bounded review.

**Verification receipt and reproduction**

Host: macOS arm64, Node `v26.8.1`, OpenSSL `3.6.4`. `npm test` compiled successfully, then reported **474 passed, 2 skipped, 1 failed** across 30 files; the one failure is the helper equality test described above. `npm audit --json` reported **zero known vulnerabilities** for the installed dependency graph at audit time. An advisory scan does not rule out unknown defects or qualify bundled native code by itself. No registry installation, remote CI run, publication, physical Touch ID ceremony, Linux execution, or independent professional audit was performed during this review.

From the repository root, after building the source, run these synthetic probes:

```sh
npm run build
node docs/security/audits/2026-09-05/runtime-probes.mjs
node docs/security/audits/2026-09-05/custody-probe.mjs
node docs/security/audits/2026-09-05/recovery-probes.mjs
```

Each creates isolated temporary vaults and removes them on completion. They use only invented credentials and emit booleans/counts, never real secret values. They report observed vulnerabilities rather than asserting that unsafe behavior is desirable; convert the scenarios into regressions that demand the corrected behavior when implementing fixes. The custody probe uses a fixed synthetic machine identity and a new child process for recovery. Recovery probes simulate a committed writer exiting without close and an interruption inside rollback. The machine-backup probe models successful authorization, not a physical authentication result.

Captured custody result:

```json
{"secureDelete":0,"currentClasses":{"machine":0,"interactive":500},"interactiveKeyUnlocked":false,"recoveredWithoutPassphraseOrPreLockSnapshot":50}
```

Captured runtime result:

```json
{"outputGuard":{"rawSecretEscaped":true,"exitCode":0},"defaultCustody":"machine","freshProcessReadWithoutPassphrase":true,"cliRestoreRejectedCorruptKey":true,"sameBackupRestoresThroughLibrary":true,"machineBackupFailsAfterAuthorization":true}
```

All nine recovery observations were true: the writer exited before close; a WAL existed before and after restore; restore reported success; the later live value was returned; restore and rollback were interrupted; the second recovery was rejected; and the journal remained. These results establish the listed failures on this source/host, not complete platform coverage.
