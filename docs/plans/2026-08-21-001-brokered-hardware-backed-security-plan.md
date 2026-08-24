---
title: "security: Brokered hardware-backed vault"
type: security
status: superseded
date: 2026-08-21
---

# security: Brokered hardware-backed vault

**Policy correction (revised 2026-08-24):** This brokered capability model is not required for the first hardware-backed release. Effectively unlocked named `run --env ...` requests use normal vault-mode behavior; broad and effectively locked named runs require Touch ID. Explicit selection scopes disclosure but does not authenticate against another same-user process. Retain this plan only as a future option if Keyclasp promises stronger same-user resistance than that contract provides.

## Desired outcome

Keyclasp can make these claims for its supported secure-agent mode:

1. Copying `vault.db` and every file beside it to another machine does not enable decryption.
2. `get`, whole-scope access, policy changes, export, delete, rename, rekey, and migration require user presence or an already authorized capability appropriate to that operation.
3. An agent can invoke only the project, environment, secret names, executable, arguments, working directory, delivery method, and lifetime that an operator approved.
4. Moving, renaming, deleting, modifying, or replaying encrypted records is detected before Keyclasp releases plaintext.
5. The TypeScript CLI, package imports, and child processes never receive the vault data-encryption key.

The design below describes a future high-assurance secure-agent mode. It is not the first-release architecture. Windows and Linux retain portable passphrase vaults and do not advertise device binding until equivalent hardware support ships.

An authorized child necessarily receives a usable credential. Keyclasp can restrict which child runs and how it receives the credential, but it cannot make arbitrary malicious software trustworthy. Public documentation must keep that boundary explicit.

## Relevant current codebase

- [`src/vault.ts`](../../src/vault.ts) owns the key file, in-process data key, SQLite connection, encryption, and every vault mutation.
- [`src/biometric.ts`](../../src/biometric.ts) performs a separate LocalAuthentication check and passphrase fallback.
- [`src/run.ts`](../../src/run.ts) resolves plaintext in the Node process, builds the child's environment, spawns it, and scans output.
- [`src/cli.ts`](../../src/cli.ts) duplicates authorization decisions before calling `runCommandWithSecrets`.
- [`src/index.ts`](../../src/index.ts) exports key, plaintext, mutation, parsing, and execution functions from the npm package.
- [`native/macos-biometric.js`](../../native/macos-biometric.js) proves Touch ID can be invoked, but it does not own or release the cryptographic key.
- [`scripts/migrate-vault-key-wrap.mjs`](../../scripts/migrate-vault-key-wrap.mjs) is the existing offline migration seam.
- [`docs/plans/2026-08-13-001-fix-passphrase-key-wrap-plan.md`](./2026-08-13-001-fix-passphrase-key-wrap-plan.md) established the random-DEK envelope and portable passphrase mode. This plan supersedes its machine-only security boundary.

The existing AES-256-GCM row encryption, direct child spawning without a shell, explicit project/environment scope, and transactional collision checks remain useful implementation patterns.

## Gap

The current Node process combines presentation, authorization, key custody, storage, and command execution. A caller that reaches an exported function can bypass decisions made elsewhere. The machine wrap derives authority from clonable host data, row encryption authenticates values without their logical identity, and unattended execution has no durable operator-approved policy.

The target design needs one security authority: a signed native broker that owns the device keys, vault data key, SQLite store, authorization policy, audit state, and child lifecycle. The TypeScript CLI becomes an untrusted presentation client.

## Security invariants

- Only the broker opens the live vault, unwraps the data key, or decrypts a secret.
- The broker treats every CLI field, environment variable, context value, database field, and IPC message as untrusted input.
- User presence is part of the cryptographic key-release operation for human plaintext and administrative operations.
- Unattended execution uses a broker-stored capability created after user presence; it never reuses the raw `get` path.
- A capability is fail-closed and exact by default. Any change to its command or scope requires new approval.
- The broker verifies the complete vault state before releasing plaintext.
- Secure-agent mode has no fingerprint, hostname, machine-id, or empty-passphrase fallback.
- Portable passphrase mode is named and documented as portable. Possession of the vault files still requires the passphrase.
- Output scanning remains defense in depth. Authorization, sandboxing, credential lifetime, and executable policy are the disclosure controls.

## Resolved design decisions

### Native boundary

Add a signed and notarized macOS broker plus a small native bridge invoked by the Node CLI. The bridge forwards bounded typed requests and terminal file descriptors; the broker makes every authorization and storage decision. A versioned IPC protocol uses fixed operation identifiers and per-field size limits. It exposes no generic SQL, filesystem, key, or decrypt operation.

The broker runs from an owner-protected installation path, verifies its own signature at startup, accepts connections only from the local user, and records the peer process identity. Peer identity is audit evidence, not authorization: raw and administrative operations still require user presence, and unattended runs still require a capability.

### Key hierarchy

Each vault has a random UUID and random 256-bit root key. HKDF derives separate content, metadata, lookup, manifest, audit, and policy keys.

The root key can have three explicit wraps:

- **Operator device wrap:** a Secure Enclave P-256 private key with `biometryCurrentSet`, `privateKeyUsage`, and `ThisDeviceOnly`. Opening this wrap prompts Touch ID and authorizes human plaintext and administration.
- **Automation device wrap:** a `ThisDeviceOnly` Keychain key accessible only to the signed broker. The broker may use this wrap only after an exact stored capability matches the request.
- **Recovery wrap:** Argon2id derives a key from an operator passphrase. This wrap supports recovery and portable interactive mode; it does not create an unattended capability.

Removing or changing enrolled biometrics invalidates the operator device key. Recovery requires the passphrase and creates a new operator key after explicit confirmation.

### Capability model

The broker stores capabilities in its authenticated policy store. A capability contains:

- vault UUID and policy generation;
- project, environment, source secret IDs, and target variable or file names;
- executable realpath plus SHA-256 and macOS signing identity when present;
- exact argument vector for the first release;
- a workload manifest covering every script, module, configuration file, or repository tree that an interpreter will execute;
- working-directory realpath;
- delivery method: one-shot file descriptor by default, environment compatibility mode only when approved;
- stdin policy, network profile, filesystem profile, expiry, and maximum uses.

Creating, widening, renewing, or revoking a capability requires the operator device wrap or recovery passphrase. The agent receives only a policy identifier. The broker re-resolves and verifies every field at execution time. A policy for `node script.js`, `npm test`, a shell, or another interpreter binds the interpreted workload, not only the interpreter binary. Mutable code invalidates the capability when its approved digest changes.

### Vault format v4

Metadata is no longer a plaintext lookup key:

- `lookup_token = HMAC(lookupKey, canonical(project, environment, name))`;
- encrypted metadata contains project, environment, name, and record UUID;
- metadata AAD contains vault UUID, schema version, record UUID, and lookup token;
- value AAD contains those fields plus a digest of the encrypted metadata;
- a manifest MAC covers the generation and the ordered record identifiers and ciphertext digests;
- the Keychain stores the latest accepted generation outside SQLite to reject rollback.

Rename decrypts and re-encrypts the affected metadata and value in one transaction. Delete and bulk delete update the manifest in the same transaction. The broker verifies the manifest and generation before any plaintext operation.

Argon2id parameters are stored in the wrap header and have enforced minimums. The broker calibrates above that floor to a documented interactive target. PBKDF2 remains available only as an explicit compatibility or FIPS profile.

### Reference constraints

- Apple: [protecting keys with the Secure Enclave](https://developer.apple.com/documentation/security/protecting-keys-with-the-secure-enclave) and [`ThisDeviceOnly` Keychain accessibility](https://developer.apple.com/documentation/security/ksecattraccessiblewhenunlockedthisdeviceonly).
- 1Password: [CLI app-integration security](https://www.1password.dev/cli/app-integration-security) for signed local IPC, per-session authorization, and activity records.
- SOPS: [authenticated metadata and file MAC design](https://github.com/getsops/sops) for the v4 AAD and manifest model.
- OWASP: [Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html) for the Argon2id floor and versioned KDF parameters.

## Walking skeleton

Build one macOS end-to-end path before migrating the full CLI:

1. A signed test broker creates one hardware-bound test vault and one encrypted record.
2. `keyclasp authorize-run` prompts Touch ID and stores a one-use capability for a fixed test executable and exact arguments.
3. `keyclasp run --policy <id>` asks the broker to verify the request, spawn the executable, deliver the secret over a one-shot descriptor, supervise the process tree, and record a metadata-only audit event.
4. `keyclasp get` without Touch ID fails; the same call after Touch ID returns the value through an operator-only terminal path.
5. Copying the vault files to a second Mac fails because its Secure Enclave and Keychain lack the device keys.

Use injected in-memory key, policy, storage, and process adapters in unit tests. The release test runs on two physical Macs because a simulated device identity cannot prove hardware binding.

## Vertical delivery slices

### Slice 1: Close the package boundary and establish the broker

**Outcome:** the Node package can request operations but cannot access keys, plaintext resolvers, SQLite, or privileged mutations.

**Implementation areas:**

- Add `native/macos/KeyclaspBroker/` and `native/macos/KeyclaspBridge/` with a shared protocol module.
- Add the hardware client under `src/hardware/`; route one `status` call and one synthetic `get` denial through it.
- Replace `package.json` `main` with an explicit `exports` map containing only supported non-sensitive types, or make the package CLI-only.
- Remove privileged exports from `src/index.ts`. Keep direct source imports only inside tests until the Node vault implementation is retired.
- Add protocol version negotiation, request-size limits, stable error codes, timeouts, cancellation, peer metadata, and broker lifecycle handling.
- Package the signed broker and bridge as immutable notarized release artifacts; the npm package verifies their digest and signature before first use.

**Acceptance:** importing the published package cannot open the vault or return plaintext; modified clients cannot bypass broker authorization; incompatible protocol versions fail before any vault access.

### Slice 2: Hardware custody, user presence, and exact capabilities

**Outcome:** device-bound and recovery key release occurs only inside the broker, and every unattended run is bound to an approved policy.

**Implementation areas:**

- Implement the three root-key wraps and broker-side key lifetime limits.
- Move LocalAuthentication into the same broker operation that opens the operator wrap; remove the JXA pre-check.
- Show the operation, scope, requesting process, and affected records in native UI before Touch ID. Collect recovery passphrases in the native broker UI so they never traverse Node or command arguments.
- Add capability create, inspect, revoke, and execute operations with an authenticated policy generation and metadata-only audit chain.
- Route `get`, whole-scope access, export, delete, rename, rekey, migration, and policy changes through operator authorization.
- Remove the caller-controlled `operatorAuthenticated` field and the generic `--allow-unsafe` path. Provide an interactive, one-use operator run for exceptional commands.
- Disable secure-agent mode when the signed broker or hardware store is unavailable. Offer portable interactive mode as a separately named choice.

**Acceptance:** direct IPC, CLI, package import, replayed policy, widened arguments, changed executable, changed working directory, expired policy, and exhausted use count all fail closed. Denied or unavailable Touch ID releases no operator key and does not silently select automation or recovery.

### Slice 3: Vault v4, Argon2id, and atomic migration

**Outcome:** vault theft exposes no plaintext values or names, record identity is authenticated, rollback is detected, and concurrent lifecycle operations cannot mix keys or formats.

**Implementation areas:**

- Implement the v4 key hierarchy, encrypted metadata, lookup tokens, AAD, manifest MAC, and external generation anchor in the broker store.
- Open existing databases with `fileMustExist`; allow creation only inside broker `init`.
- Enforce owner and mode checks for the directory, database, WAL, SHM, key metadata, policy, audit, temporary, backup, and migration files. Reject symlinks, hardlinks, and unexpected ownership.
- Serialize init, migration, restore, rekey, and policy-generation changes with one exclusive vault lock.
- Publish key and database state with temporary files, `fsync`, atomic rename, and directory `fsync`. Bind an empty database to its root key through the authenticated manifest.
- Restore an older authenticated snapshot by importing it as a new generation after operator approval; never lower the external generation anchor.
- Add a signed, version-matched v3-to-v4 migrator. It takes the lock, verifies a snapshot, creates a recoverable backup, re-encrypts every row, verifies v4, advances the external generation, and publishes with compare-and-swap.
- Statically link a pinned Argon2id implementation after the KDF spike establishes provenance, licensing, parameters, and performance.

**Acceptance:** ciphertext, metadata, row order, row deletion, row substitution, vault UUID, manifest, and generation mutations fail before plaintext release. Concurrent init, migrate, restore, and rekey tests produce one valid result or a clear retryable error, never mixed-key state.

### Slice 4: Capability-bound process execution and release proof

**Outcome:** the broker launches only approved commands, delivers the minimum secret set, and removes the complete process tree when the run ends or violates policy.

**Implementation areas:**

- Resolve all requested secrets in one authenticated SQLite snapshot after capability validation.
- Verify the executable, argument vector, working directory, and workload-manifest digest immediately before spawning. Reject interpreters or mutable code that the policy does not bind.
- Start from a minimal environment. Strip inherited credentials, loader/runtime control variables, and every `KEYCLASP_*` variable.
- Prefer a one-shot descriptor or ephemeral file with a maximum read count. Keep environment delivery as an explicitly approved compatibility mode.
- Default agent stdin to closed. Pass a terminal only when the capability allows it.
- Spawn a supervised process group, forward cancellation, terminate all descendants, enforce time and output limits, and wait for the group to exit.
- Replace separate stream scanners with one ordered, backpressure-aware multi-pattern matcher. Cover self-overlap, every chunk boundary, UTF-8 boundaries, and both output streams.
- Apply a broker-selected execution profile. Network is denied for offline policies; broader network or filesystem access requires a separately approved profile and remains visible in `keyclasp policy show`. Arbitrary mutable code with network access remains trusted-child mode unless a provider proxy or short-lived credential restricts what that code can do.
- Update `docs/security.md`, CLI help, and the agent skill so every claim matches the broker and capability model.
- Add signed releases, SBOM and provenance, pinned native dependencies, full dependency audit, secret scanning, and two-Mac hardware acceptance to the release workflow.

**Acceptance:** unapproved executables, changed workload files, and request variations never spawn; leaked output terminates the whole process group; descendants cannot retain the delivery descriptor; denied network and filesystem operations fail under the selected profile; logs contain identifiers and outcomes but no secret values.

## Technical bets and bounded spikes

1. **IPC and terminal relay, two days.** Prove that the bridge can pass stdin/stdout/stderr safely while the broker remains the parent and supervisor of the real child. Reject designs that return plaintext or the root key to Node.
2. **Secure Enclave wraps, one day.** Prove ECIES wrapping, `biometryCurrentSet`, enrollment-change invalidation, recovery re-enrollment, and noninteractive broker-only automation wrapping on two Macs.
3. **Execution profile, two days.** Prove the strongest supported macOS sandbox for arbitrary developer tools. If macOS cannot enforce the requested network/filesystem profile without private APIs or unstable tooling, scope v1 to trusted approved children and move stronger isolation to a container or separate-user runner.
4. **Argon2id supply chain, one day.** Select a maintained implementation that can be pinned, statically linked, signed, and built reproducibly for supported macOS architectures. Record the chosen floor and calibration method in `docs/security.md`.

Each spike ends with a small executable test and an accepted or rejected decision in this plan. Spike code does not enter the release artifact until its dependency and signing path pass review.

## Deferred decisions

- Windows Hello/TPM broker and Linux TPM2 broker. Their future implementations must satisfy the same broker contract and hardware-copy acceptance test; they may not emulate secure-agent mode with public machine identifiers.
- Provider-specific exchange of long-lived credentials for short-lived tokens. The capability and delivery interfaces should admit this later without adding it to the first broker.
- Multi-device synchronization, team policy, remote revocation, and enterprise audit export.
- Domain-level network allowlists when the operating-system execution profile provides only coarse network control.

## Done criteria

- The npm package exposes no raw key, decrypt, storage, or privileged mutation function.
- The signed broker is the only process that can access device keys, the root key, the live database, and the policy store.
- A second physical Mac cannot open copied vault and key metadata files.
- Raw and administrative operations require Touch ID or recovery passphrase inside the broker operation.
- Every unattended run matches an unexpired, unrevoked, exact capability and consumes its allowed use count atomically.
- Vault v4 authenticates record identity, metadata, the complete row set, vault UUID, schema version, and generation.
- Argon2id protects recovery wraps with versioned parameters and enforced minimums.
- Migration is signed, locked, resumable or rollback-safe, and verified before v4 becomes live.
- The broker provides one-snapshot secret resolution, minimal environment construction, one-shot delivery, process-group supervision, bounded output, and metadata-only audit records.
- Unit, integration, property, fuzz, concurrency, migration, package, signature, and two-device hardware tests pass.
- A third-party security review finds no unresolved critical or high-severity issue in the broker, key hierarchy, vault v4, capability policy, IPC protocol, migration, or process runner.
- Documentation limits the secure-agent claim to the platforms and execution profiles that passed these tests.
