# Software beta security model

This document describes the dual-key software vault. Hardware mode is unavailable and status-only.

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

A machine-to-interactive change completes only after obsolete live SQLite data is cleaned up and the remaining records are authenticated. If no machine records remain, Keyclasp also retires the old machine key. Interrupted cleanup resumes before ordinary commands. Older vaults undergo this cleanup during upgrade; interactive records require the passphrase even when the requested command is `status` or `list`.

## Authorization

Broad runs, `get`, custody changes, passphrase rotation, backup, and restore require operator authorization. A named run requires authorization when any selected record is interactive.

- macOS uses Touch ID through a packaged helper, with no passphrase-only fallback for operator authorization. It then requests the passphrase if an interactive key is needed. Before stateful vault access and again before authorization, Keyclasp checks the helper's path, ownership, permissions, ACLs, hashes, signature, identity, architecture, and entitlements. The helper runs with a fixed minimal environment and receives operation metadata only. The run dialog shows the command, scope, selected names and mappings, and output-protection state.
- Linux uses one non-empty passphrase entry to authorize and unlock. A machine-only or non-interactive gated request fails before the requested operation proceeds. macOS can authorize machine-only operations with Touch ID when no interactive key is needed.

First Linux enrollment confirms a new passphrase because no previous interactive credential exists. This protects future interactive custody but does not authenticate enrollment against another same-user process with terminal access.

Policy resolution prefers exact secret, exact project/environment, project-only or environment-only, then the authenticated vault-wide fallback. Locked wins when project-only and environment-only rules conflict at equal specificity. Rules cover future records. The version 3 policy document authenticates its fallback, rules, vault identity, and generation and is committed into the database.

## Child-process boundary

Keyclasp validates the complete selection before decrypting any selected value and launches the child without a shell. Explicit `--env SOURCE[:TARGET]` mappings limit disclosure; they do not authenticate the caller.

The child inherits the caller's environment, with the selected vault variables added or replaced. `--env` does not remove credentials already exported by the caller.

The default guard rejects values containing null bytes or text that cannot round-trip through UTF-8, blocks common environment-dump commands, and scans stdout and stderr for exact injected values of at least eight characters. Matching works across output chunks. On a match, it emits `[KEYCLASP_REDACTED]`, stops forwarding both streams, signals the supervised process group with `SIGTERM` and then `SIGKILL` if needed, and returns exit status 2 even if the child succeeds. If OS permissions prevent signaling a descendant, Keyclasp reports that termination could not be confirmed.

Fragments, transformed values, shorter values, files, and network traffic are outside the scan. `--allow-unsafe` disables command preflight and output scanning, but never authorization.

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

`better-sqlite3@13.0.3` is the direct runtime dependency; `node-addon-api` is its production transitive dependency. The package bundles their production source and native prebuilds. Installation verifies the selected binding's hash and downloads no separate native code. An explicit source build compiles the bundled source with npm's `node-gyp`.

The macOS Touch ID helper is ad hoc signed with hardened runtime, without Developer ID signing or notarization. Integrity checks can detect a damaged package; they cannot establish publisher identity or defend against coordinated replacement of Keyclasp and its metadata. The [release notes](releases/0.2.0-beta.2.md) retain qualification limits and artifact details.

## Remaining limits

- A child that changes privilege may become impossible for Keyclasp to terminate.
- `get` deliberately prints plaintext after authorization; agents must not use it.
- Hardware mode, Windows, and passphrase removal are unavailable.
- Keyclasp has not received a professional third-party security audit. Publication does not establish production-security certification; physical authorization and fresh-machine onboarding remain unverified in this documentation pass.

## Cryptographic inventory

| Primitive | Use |
|---|---|
| AES-256-GCM | Record encryption and data-key wrapping |
| PBKDF2-HMAC-SHA256, 600,000 iterations | Interactive wrapping key derivation |
| HMAC-SHA256 | Authenticated policy and lifecycle metadata |
| SHA-256 | Machine-wrap derivation, hashes, and domain separation |

Node's built-in `crypto` module supplies these primitives. No third-party cryptographic library is used.
