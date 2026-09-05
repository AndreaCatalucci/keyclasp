# Software beta security model

This document describes the `0.2.0-beta.1` dual-key software vault. Hardware mode is unavailable and status-only.

## Supported boundary

The beta supports macOS `arm64` and glibc Linux `arm64` or `x64` on Node.js 24 or 26. macOS `x64` and Windows fail closed. Owner-only Unix modes are enforced as `0700` for directories and `0600` for files; macOS ACL entries are removed and rechecked. Windows remains unsupported because equivalent ACL ownership and operator authorization have not passed qualification.

Keyclasp relies on the operating-system user boundary. It does not defend against root, a compromised kernel, memory inspection of a running authorized process, physical keyloggers, or another process running as the same user and requesting a known unlocked secret.

## Dual-key custody

The canonical v5 key bundle holds two independent random 32-byte data keys and a separate policy MAC key:

- The machine data key is AES-256-GCM wrapped under a key derived from local machine identity. The identity is not secret or hardware-attested.
- The interactive data key is AES-256-GCM wrapped under PBKDF2-HMAC-SHA256 with a random 32-byte salt, 600,000 iterations, and a non-empty passphrase.
- The policy key authenticates rules and cannot decrypt a record.

Every record is encrypted with its assigned data key. AES-GCM associated data binds the format version, vault ID, stable record ID, project, environment, secret name, record kind, and custody class. Moving ciphertext or changing `key_class` without authorized re-encryption fails authentication.

`lock`, `unlock`, and `inherit` update authenticated policy and re-encrypt matching existing records inside one exclusive lifecycle operation. Fresh passphrase vaults use interactive fallback custody; machine-only initialization requires the explicit `--machine-only` choice. Existing vaults migrate without reclassification to a labelled `legacy-machine` fallback until the operator explicitly runs `lock --default` or `unlock --default`. Exact-secret, exact-scope, project-only, and environment-only rules retain precedence over that fallback.

A machine-to-interactive database commit also records `custody_sanitization_required`. Normal dispatch cannot report the change complete while that phase exists. Recovery repeats secure deletion, WAL checkpoint/truncation, database compaction, explicit WAL/SHM cleanup, closed-file integrity checking, and cryptographic record validation. When no machine records remain, the active bundle and database key check advance to a fresh machine key before the phase clears. If machine records remain, their existing key stays active and those records are revalidated after cleanup.

Vaults created before this sanitation contract, including legacy vaults upgraded to dual-key storage, enter the same one-time pending phase before their first ordinary command. A machine-only inventory completes without an interactive prompt; an inventory containing interactive records requires the passphrase so every current record can be authenticated, and an all-interactive inventory retires the obsolete machine key in that invocation.

## Authorization

Broad runs, `get`, custody changes, passphrase rotation, backup, and restore require operator authorization. A named run requires authorization when any selected record is interactive.

- macOS evaluates Touch ID in a short-lived, ad-hoc-signed `Keyclasp.app` helper with no passphrase-only fallback, then requests the interactive passphrase when that key is needed. For a run, the dialog identifies Keyclasp and shows the command, scope, complete selected secret-name mappings, and output-protection state. The helper receives metadata only, never a secret value, passphrase, or data key.
- Linux requires one non-empty passphrase entry that both authorizes and unlocks the interactive key. A machine-only or non-interactive gated request fails before decryption, mutation, or child launch.

First Linux enrollment confirms a new passphrase because no previous interactive credential exists. This protects future interactive custody but does not authenticate enrollment against another same-user process with terminal access.

Policy resolution prefers exact secret, exact project/environment, project-only or environment-only, then the authenticated vault-wide fallback. Locked wins when project-only and environment-only rules conflict at equal specificity. Rules cover future records. The version 3 policy document authenticates its fallback, rules, vault identity, and generation and is committed into the database.

## Child-process boundary

Keyclasp validates the complete selection before decrypting any selected value and launches the child without a shell. Explicit `--env SOURCE[:TARGET]` mappings limit disclosure; they do not authenticate the caller.

The default guard blocks common environment-dump commands and scans stdout and stderr for injected values of at least eight characters. A match is redacted and the child receives `SIGTERM`, followed by `SIGKILL` if needed. Shorter values cannot be scanned reliably. `--allow-unsafe` disables command preflight and output scanning, but never authorization.

The selected child is trusted. It can deliberately send, persist, transform, or indirectly disclose its credentials. Keyclasp cannot make untrusted code safe.

## Storage, migration, and recovery

Secret names, scopes, timestamps, custody classes, and policy metadata are plaintext. Secret values are individually encrypted in SQLite.

One-key vault migration creates a consistent backup before mutation. A passphrase-wrapped legacy data key becomes the interactive key; effectively unlocked records move to a fresh machine key. A machine-wrapped legacy key remains the machine key; locked records require interactive enrollment before migration. Older binaries refuse the new format.

Managed backups authenticate the database, complete key bundle, policy, manifest, record-class inventory, and every encrypted record. Creation requests only the data-key classes required by the consistent snapshot and always follows operator authorization. Mixed or machine-only backups restore only with the source machine identity. All-interactive backups can restore on another supported machine with the passphrase; they receive a fresh target-machine key and remain interactive.

Managed restore treats `vault.db`, WAL, and SHM as one live state. Healthy state is copied, then checkpointed and validated without mutating the raw live files; those exact raw bytes become rollback material. Damaged raw state and recognized pending journals are quarantined without using them as restore authority. The authenticated backup is reopened and fully validated before commit. Repeated interruption of publication, rollback, or cleanup resumes from authenticated pre/post file states.

Backup authentication proves origin and internal consistency, not that a backup is newer than another valid copy. Locking, passphrase rotation, live-file sanitization, and machine-key retirement do not invalidate external filesystem snapshots, copied backups, or credentials copied by an authorized child. Operators must define retention for every saved copy and rotate the credential at its provider when prior access must be revoked.

Keyclasp overwrites Keyclasp-owned machine, interactive, wrapping, and temporary plaintext buffers on a best-effort basis when their lifetime ends. It cannot reliably erase JavaScript strings, child-process environments, OS caches, swap, crash collectors, filesystem snapshots, or prior copies, and it makes no protected-memory claim.

The lifecycle lock excludes cooperating Keyclasp processes, not arbitrary SQLite clients. Restore rejects observable busy or changing state, but an operator must stop every external client before starting it. Direct same-inode overwrite of an open SQLite database remains unsupported.

## Package boundary and dependencies

The public package exports parsing, context, biometric-result classification, path reporting, and scope validation only. It does not export data keys, generic decryption, policy mutation, plaintext resolution, or child launch.

`better-sqlite3@13.0.3` is the only direct runtime dependency; `node-addon-api` is its only production transitive dependency. Their complete reviewed production tree, including native prebuilds, is bundled in the Keyclasp tarball. The default install verifies the selected prebuild against the packaged OS-and-architecture SHA-256 allowlist, so it downloads no native code. An explicit `npm_config_build_from_source=true` request compiles the bundled source with npm's `node-gyp`, removes the target prebuild, and verifies that the compiled path will be loaded. The package also carries the thin arm64 `Keyclasp.app` Touch ID helper and a reviewed source/bundle hash manifest. Package qualification covers both SQLite paths, helper identity and signature, install scripts, lockfile advisories, licenses, N-API support on Node 24 and 26, public exports, package contents, and exact tarball contents. Native hardware experiments, tests, vaults, transcripts, and release credentials are excluded from the npm package.

## Explicit limitations

- Machine custody is software-bound and weaker than passphrase custody.
- Interactive custody is portable with its passphrase when a backup contains no machine record.
- Authenticated backups provide authenticity, not newest-state freshness or revocation of older valid copies.
- Best-effort owned-buffer cleanup does not establish erasure from JavaScript strings, process environments, swap, crash data, snapshots, or prior copies.
- The same-user boundary permits another local process to request an unlocked known secret.
- Output scanning is accidental-leak containment, not an exfiltration boundary.
- `get` prints plaintext into terminal scrollback after authorization.
- Hardware mode, Windows, passphrase removal, registry-install evidence, and publication are unavailable or unverified at this checkpoint.
- Keyclasp has not received a professional third-party security audit.

## Cryptographic inventory

| Primitive | Use |
|---|---|
| AES-256-GCM | Record encryption and data-key wrapping |
| PBKDF2-HMAC-SHA256, 600,000 iterations | Interactive wrapping key derivation |
| HMAC-SHA256 | Authenticated policy and lifecycle metadata |
| SHA-256 | Machine-wrap derivation, hashes, and domain separation |

Node's built-in `crypto` module supplies these primitives. No third-party cryptographic library is used.
