# Keyclasp security hardening checklist

This checklist gates Slice 5, the optional macOS hardware-backed release described in [`docs/plans/2026-08-22-001-macos-hardware-beta-to-ga-plan.md`](plans/2026-08-22-001-macos-hardware-beta-to-ga-plan.md). The canonical release order and separate software-beta milestone are defined in [`docs/plans/2026-08-23-001-software-beta-and-optional-hardware-mode-plan.md`](plans/2026-08-23-001-software-beta-and-optional-hardware-mode-plan.md). Unchecked hardware controls do not block that software beta, and the software beta must make no hardware-custody claim.

The distribution assumption is explicit:

- **Beta (`B`)** requires a physically qualified pre-GA signing and persistence path. The tested ad-hoc artifact is not accepted: it failed permanent Secure Enclave creation with `errSecMissingEntitlement`. Developer ID and notarization remain general-availability requirements unless qualification proves they are needed earlier.
- **General availability (`G`)** uses Developer ID, hardened runtime, notarization, and direct distribution outside the Mac App Store.
- **Future (`F`)** covers brokered capabilities that constrain malicious same-user callers and Windows/Linux hardware modes. Exact machine-only hardware-mode `--env` runs are non-interactive and do not depend on those future capabilities.

An unchecked `B` item blocks a beta intended for real secrets. An unchecked `G` item blocks general availability. Mark an item complete only when the evidence link names the test, reviewed commit, physical-device result, or release artifact that proves it. A pre-GA signing choice changes the distribution trust model; it does not relax any cryptographic or authorization control.

## 1. Release boundary and claims

- [ ] **B** Hardware mode is available only on Macs whose Secure Enclave behavior passed the physical-device test matrix.
- [ ] **B** Portable passphrase mode and hardware mode have different names, status output, and documentation.
- [ ] **B** Hardware mode has no machine-fingerprint, hostname, machine-id, software-keyring, or empty-passphrase fallback.
- [ ] **B** `status` reports the active mode, hardware availability, enrollment state, recovery state, and native-core version without exposing secret metadata beyond the caller's explicit scope.
- [ ] **B** Documentation states that the approved child receives a usable credential and remains trusted.
- [ ] **B** Documentation makes no claim of protection from root, kernel compromise, an authorized malicious child, or a user approving a misleading Touch ID request.
- [ ] **B** Runtime networking and telemetry remain absent; tests fail if the native core introduces an unexpected network dependency.
- [ ] **G** Public claims distinguish encryption, hardware binding, user authorization, record integrity, rollback detection, and distribution identity.

## 2. Hardware key custody

- [ ] **B** The Secure Enclave creates independent non-exportable P-256 machine and interactive private keys for each hardware-mode vault; interactive private-key use is bound to `biometryCurrentSet`.
- [ ] **B** Files store only public material, opaque handles, salts, nonces, wrapped keys, and authenticated metadata.
- [ ] **B** Copying every Keyclasp file to a second physical Mac fails to unwrap either vault data key.
- [ ] **B** Possession of the machine private-key path and every machine-key metadata file cannot decrypt an interactive-class record.
- [ ] **B** Operations whose policy requires Touch ID fail closed on denial, cancellation, timeout, missing enrollment, or enrollment change. Deleted hardware keys and corrupted handles fail closed for every operation.
- [ ] **B** Hardware unavailability selects no weaker mode automatically. The user may explicitly create or recover into portable mode.
- [ ] **B** The Keyclasp-owned adapter verifies that the selected key is Secure Enclave-backed; a reported macOS hardware mode cannot use a software implementation.
- [ ] **B** Key deletion and replacement require authorization and a verified recovery path.
- [ ] **B** Tests prove whether an unchanged artifact, rebuild, update, and Developer ID transition retain or replace the enrolled code identity.

## 3. Key hierarchy and cryptography

- [ ] **B** A cryptographically secure RNG creates independent 256-bit machine and interactive data keys, salts, record UUIDs, and every GCM nonce.
- [ ] **B** Each hardware key wraps only its matching random data key; hardware keys are not used to encrypt the SQLite database directly.
- [ ] **B** HKDF or an equivalent reviewed construction derives separate content, metadata, lookup, manifest, audit, and policy keys where those domains exist.
- [ ] **B** AES-256-GCM uses a fresh 96-bit nonce and 128-bit tag for every encryption under a given key.
- [ ] **B** Tests detect nonce reuse, malformed lengths, truncated records, tag changes, and wrong-key decryption.
- [ ] **B** Key-wrap AAD binds the format magic, schema version, vault UUID, wrap type, KDF identifier, KDF parameters, and salt.
- [ ] **B** Record AAD binds the vault UUID, schema version, record UUID, project, environment, secret name or lookup token, and encrypted-metadata digest.
- [ ] **B** Moving a valid ciphertext tuple to another name or scope fails authentication before plaintext release.
- [ ] **B** Recovery uses a memory-hard KDF with versioned parameters, random salt, an enforced minimum, and calibration to a documented interactive target.
- [ ] **B** Wrong recovery passphrases return one generic failure and release no oracle about the key, record count, or secret names.
- [ ] **G** A manifest MAC authenticates the complete ordered record set and current vault generation.
- [ ] **G** A generation anchor outside SQLite rejects replay of an older otherwise valid vault.
- [ ] **G** Public documentation states that project, environment, and secret names remain discoverable metadata unless a later authenticated-list design encrypts them at rest.
- [ ] **G** A cryptography review approves algorithms, parameter floors, domain separation, serialization, and migration compatibility.

## 4. Authorization and operation policy

- [ ] **B** The native core owns authorization; the TypeScript CLI cannot assert `operatorAuthenticated` or an equivalent trusted boolean.
- [ ] **B** The native core evaluates authorization and releases secrets in one operation: machine-only named `--env` requests are non-interactive, while broad requests and every selection containing an interactive record complete Touch ID before either selected class is unwrapped, any record is decrypted, or a child is spawned.
- [ ] **B** When policy requires Touch ID, the authorization prompt shows the operation, project, environment, selected secret names or whole-scope request, executable, and arguments before approval.
- [ ] **B** `init`, enrollment, `set`, `get`, export, delete, bulk delete, rename, rekey, migration, recovery, mode changes, `lock`, `unlock`, `inherit`, and every `run` pass through native authorization appropriate to the operation. Named runs require an exact non-empty `--env` selection; broad and interactive-containing named runs require Touch ID.
- [ ] **B** An explicit `--env` selection with a missing value, malformed mapping, duplicate target variable, or unresolved secret fails without decrypting, spawning, or falling back to whole-scope injection.
- [ ] **B** Authenticated lock/unlock/inherit rules support project-only, environment-only, exact-scope, and exact-secret selectors with the shared precedence contract. Mutations always require Touch ID and atomically re-encrypt affected records under the resulting hardware custody class while assigning that class to future matching records.
- [ ] **B** `list`, `projects`, `environments`, and scoped `status` are the only unauthenticated metadata operations; secret names are explicitly classified as discoverable metadata, and these operations cannot mutate storage or reach a value-decrypt function.
- [ ] **B** Whole-scope access is operator-only and never available to agent mode.
- [ ] **B** Every agent operation requires explicit project, environment, and secret names; persisted context grants no authority.
- [ ] **B** Cancellation and authorization errors happen before vault-key release, secret resolution, mutation, or child spawn.
- [ ] **B** No debug flag, environment variable, library import, direct IPC request, recovery path, or `--allow-unsafe` option bypasses authorization.
- [ ] **B** The interactive recovery path bounds concurrent attempts and memory use; the memory-hard KDF remains the defense against offline guesses from copied files.
- [ ] **F** Any future claim that constrains a malicious same-user caller beyond explicit named-secret selection requires an exact broker-stored capability binding scope, secret IDs, executable, arguments, working directory, workload digest, delivery method, lifetime, and use count.

## 5. Native authority and package boundary

- [ ] **B** One short-lived native core exclusively opens the hardware key, live vault, and recovery state.
- [ ] **B** The core reads new secret values and recovery passphrases directly from inherited terminal or pipe descriptors.
- [ ] **B** Node sends only bounded typed requests containing names, scope, operation, and child metadata.
- [ ] **B** Node never receives the vault root key, derived keys, recovery passphrase, or secret plaintext through IPC, stdout, return values, exceptions, or environment variables.
- [ ] **B** The published package exports no raw key, generic decrypt, plaintext resolver, SQLite handle, privileged mutation, or authentication-helper bypass.
- [ ] **B** The protocol has a fixed version, operation allowlist, per-field size limits, strict UTF-8 handling, request timeout, cancellation, and stable error codes.
- [ ] **B** Unknown fields, duplicate fields, malformed frames, oversized messages, version mismatch, and partial messages fail before vault access.
- [ ] **B** The core accepts no generic SQL, filesystem path, arbitrary key operation, or caller-selected plugin.
- [ ] **B** The installed core resides in an owner-controlled location and rejects symlinks, unexpected ownership, and writable parent directories.
- [ ] **G** The CLI verifies the packaged core version, digest, and Developer ID designated requirement before first use and after updates.

## 6. Secret memory and error handling

- [ ] **B** Native key and plaintext buffers use zeroizing containers and the shortest practical lifetime.
- [ ] **B** The core clears secret buffers on success, denial, child failure, timeout, cancellation, panic, and normal shutdown.
- [ ] **B** Core dumps and crash reports are disabled or configured so secret-bearing memory is not captured.
- [ ] **B** Logs, audit records, metrics, assertions, panic messages, test snapshots, and errors contain identifiers and outcomes only.
- [ ] **B** Secret values never enter command arguments, filenames, URLs, diagnostic bundles, clipboard history, or shell history.
- [ ] **B** Secret comparison and authentication decisions avoid distinguishable error details and unnecessary data-dependent behavior.
- [ ] **B** Tests use unique canary secrets and scan Node memory-visible protocol data, logs, stdout, stderr, temporary files, and crash artifacts for those values.

## 7. Vault storage and filesystem hardening

- [ ] **B** Keyclasp creates and repairs the vault directory to owner-only `0700` permissions.
- [ ] **B** The database, WAL, SHM, key metadata, recovery metadata, backups, locks, temporary files, and audit files use owner-only `0600` permissions.
- [ ] **B** Permission tests begin with an existing `0755` directory and verify the exact repaired mode of every created file.
- [ ] **B** The core rejects unexpected owners, symlinks, hardlinks where detectable, non-regular files, and path traversal.
- [ ] **B** Existing vault opens use SQLite `fileMustExist`; only authorized `init` may create a live database.
- [ ] **B** Initialization, migration, restore, rekey, recovery, and publication share one exclusive vault lock.
- [ ] **B** Sensitive state publishes through owner-only temporary files, file `fsync`, atomic rename, and directory `fsync`.
- [ ] **B** Backups contain only encrypted state, have explicit retention, and never become an untracked portable key copy.
- [ ] **B** SQLite busy handling, WAL lifecycle, abrupt termination, disk-full behavior, and partial writes yield one valid old or new state.
- [ ] **B** Restore verifies the complete snapshot before replacing live state.
- [ ] **G** Delete, rename, restore, and migration update record AAD, manifest, and generation atomically.

## 8. Child-process execution and delivery

- [ ] **B** The native core, not Node, resolves all requested secrets from one authenticated SQLite snapshot and launches the child without a shell.
- [ ] **B** The core resolves the executable to an absolute path and displays that path whenever policy requires an authorization prompt.
- [ ] **B** The child starts with a minimal environment; inherited credentials, loader variables, runtime injection controls, and every unrelated `KEYCLASP_*` value are removed.
- [ ] **B** A named request injects only its explicit `--env` selection. A whole-scope request injects the complete resolved scope only after Touch ID. Black-box tests give every scope a distinct variable name and prove that named requests exclude unrelated variables.
- [ ] **B** File-descriptor or ephemeral-file delivery is preferred where the child supports it; environment delivery is labeled compatibility mode.
- [ ] **B** Delivery descriptors are close-on-exec except for the intended child, bounded to one read where supported, and unavailable to later unrelated processes.
- [ ] **B** The core supervises the complete process group, forwards cancellation, enforces time and output limits, and terminates descendants after a leak or timeout.
- [ ] **B** Output scanning covers stdout and stderr in order, backpressure, UTF-8 boundaries, every chunk split, duplicate values, prefixes, and self-overlapping values such as `token-token`.
- [ ] **B** One-chunk and split-chunk regressions prove that no complete injected value reaches the operator transcript.
- [ ] **B** Hardware mode has no flag that disables output protection. Exceptional commands use a separately confirmed operator-only path.
- [ ] **B** The security documentation states that output scanning cannot stop an approved child from encoding, persisting, or transmitting its credential.

## 9. Recovery, migration, and updates

- [ ] **B** Enrollment requires the operator to create and confirm a recovery passphrase before real secrets are stored.
- [ ] **B** Keyclasp proves the recovery wrap by reopening the root key before reporting initialization complete.
- [ ] **B** Recovery never sends the passphrase through Node, command arguments, environment variables, or a shell.
- [ ] **B** Device recovery creates a new hardware key and wrap before invalidating the old enrollment.
- [ ] **B** An interrupted recovery or update retains at least one verified path to the previous vault.
- [ ] **B** Beta updates detect code-identity changes and require recovery verification before replacing an enrollment that may stop working.
- [ ] **B** Migration is versioned, locked, backup-first, resumable or rollback-safe, and verifies every record before publishing the new state.
- [ ] **B** Old binaries refuse newer vault formats without mutating them.
- [ ] **G** Beta-to-Developer-ID migration preserves the vault and retires the selected pre-GA enrollment only after the Developer ID enrollment succeeds.
- [ ] **G** Certificate rotation changes the release identity without creating an unrecoverable vault transition.

## 10. Dependency and build security

- [ ] **B** The Keyclasp-owned Rust, Swift, C, Security.framework, and CryptoKit boundary and every native dependency are pinned or tied to the reviewed source and SDK; the rejected `hardware-enclave` crate is absent from the release graph.
- [ ] **B** Review covers platform fallback logic, unsafe Rust, Swift/C FFI, key deletion, user-presence semantics, error paths, and transitive build scripts.
- [ ] **B** The repository records dependency licenses, provenance, security contacts, and the reason each native dependency is required.
- [ ] **B** Lockfiles are committed; CI rejects unexpected lockfile or generated-bridge changes.
- [ ] **B** Native and Node builds run formatting, static analysis, tests, dependency audit, secret scanning, and malicious-package checks.
- [ ] **B** Release artifacts build from an immutable tag in public CI and carry source-linked provenance and SHA-256 checksums.
- [ ] **B** The release process compares the packaged file list with an allowlist and rejects debug symbols, test keys, local paths, credentials, and unreviewed dynamic libraries.
- [ ] **G** General-availability artifacts include an SBOM and reproducible-build comparison or a documented account of every nondeterministic input.
- [ ] **G** Signing and notarization credentials live in a protected release environment with approval, least privilege, rotation, revocation, and audit procedures.

## 11. Pre-GA beta distribution

- [ ] **B** Physical qualification proves one supported pre-GA signing and persistence path before packaging begins; the failed permanent-Keychain ad-hoc path remains rejected.
- [ ] **B** CI verifies the selected pre-GA code identity, capabilities, and signature. If the accepted path is ad-hoc, it also records the expected Gatekeeper block and successful **System Settings → Privacy & Security → Open Anyway** flow on a clean Mac.
- [ ] **B** Installation instructions never use `spctl --master-disable`, global policy changes, `xattr -dr`, disabled quarantine, or `sudo` to bypass Gatekeeper.
- [ ] **B** The release page states the exact publisher and notarization status. If the artifact is ad-hoc, it says Apple cannot identify the publisher or confirm notarization.
- [ ] **B** The release page provides checksum and provenance verification before the user approves the artifact.
- [ ] **B** Each beta build is tested as a new download; documentation states that a new version may require another Gatekeeper approval and recovery-backed re-enrollment.
- [ ] **B** `keyclasp doctor` distinguishes Gatekeeper blocking, unsupported hardware, missing Touch ID, damaged enrollment, and recovery-required update.
- [ ] **B** Managed Macs that prohibit user overrides receive an explicit unsupported-beta result rather than instructions to weaken policy.
- [ ] **B** Uninstall removes the executable and non-secret integration files but preserves the encrypted vault unless the user separately confirms vault deletion.

## 12. Developer ID general availability

- [ ] **G** The release owner has an active Apple Developer Program membership and a documented Developer ID certificate owner and recovery process.
- [ ] **G** CI signs nested code from the inside out with stable identifiers, hardened runtime, secure timestamps, and only reviewed entitlements.
- [ ] **G** CI verifies each nested executable and the top-level bundle with strict code-signing checks, then verifies the final designated requirement on the packaged artifact.
- [ ] **G** `notarytool` returns `Accepted`; the ticket is stapled to the supported distributable container.
- [ ] **G** `spctl` on a clean supported Mac reports acceptance from Notarized Developer ID without **Open Anyway**.
- [ ] **G** Notarization failure publishes no macOS artifact and does not block independently releasable Windows or Linux artifacts.
- [ ] **G** The immutable release set contains the signed artifact, checksum, SBOM, provenance, source tag, commit, and notarization evidence.
- [ ] **G** No Mac App Store submission, receipt, sandbox profile, or review dependency is required by the release workflow.
- [ ] **G** Certificate expiry and revocation drills document how users verify safe existing builds and receive a newly signed update.

## 13. Verification matrix

- [ ] **B** Unit tests cover every key, serialization, protocol, policy, and error transition through injected adapters.
- [ ] **B** Tests exercise the real compiled macOS authorization helper or core decision logic; a status-zero mock alone cannot prove authorization.
- [ ] **B** Black-box CLI tests prove machine-only named runs are non-interactive; broad, interactive, and mixed-class runs require Touch ID; machine-key material cannot decrypt an interactive record; and every denied `get`, `run`, custody mutation, recovery, or migration releases no plaintext and spawns no child.
- [ ] **B** Package tests run against the packed artifact and public exports rather than privileged source imports.
- [ ] **B** Property tests cover encryption round trips, unique nonces, state-machine transitions, migration, rename, and concurrent operations.
- [ ] **B** Fuzzing covers the native protocol, vault headers, encrypted records, manifests, recovery metadata, and malformed SQLite rows.
- [ ] **B** Fault injection covers termination and disk failure at every write, rename, `fsync`, rekey, recovery, and migration boundary.
- [ ] **B** Permission, symlink, hardlink, ownership, path traversal, oversized input, and resource-exhaustion tests fail closed.
- [ ] **B** Physical acceptance runs on two distinct Macs and proves copied-file failure.
- [ ] **B** A clean-Mac beta acceptance run starts from a quarantined download and ends with a successful named-secret child execution.
- [ ] **G** A clean-Mac general-availability run verifies signature, notarization, enrollment, update, recovery, and copied-file failure.
- [ ] **G** An independent security review finds no unresolved critical or high-severity issue in the shipped boundary.

## 14. Documentation and incident readiness

- [ ] **B** `docs/security.md`, CLI help, README, getting started, FAQ, and the installed agent skill describe the same authorization and platform behavior.
- [ ] **B** Documentation identifies beta distribution trust separately from vault cryptography.
- [ ] **B** Security claims name the exact supported macOS hardware and the fallback behavior.
- [ ] **B** The private vulnerability-reporting route works and has a response owner.
- [ ] **B** A credential-exposure runbook covers containment, affected-secret rotation, forensic preservation, disclosure, and release revocation without collecting secret values.
- [ ] **B** A lost-device runbook covers recovery, new hardware enrollment, old-device retirement, and provider-side credential rotation where appropriate.
- [ ] **G** A signing-key incident runbook covers certificate revocation, release withdrawal, user notification, and re-signing.
- [ ] **G** Release notes state whether the change affects the native boundary, vault format, recovery, code identity, or required re-enrollment.

## Evidence record

For every completed gate, record:

```text
Control:
Release gate: B | G | F
Commit or tag:
Test or review artifact:
Physical machines or clean image:
Reviewer:
Date:
Residual limitation:
```

The release owner signs off only after every applicable gate has linked evidence. A passing test suite without physical-device, packaged-artifact, and clean-install evidence does not complete this checklist.
