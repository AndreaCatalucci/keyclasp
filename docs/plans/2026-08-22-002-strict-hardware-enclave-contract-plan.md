---
title: "security: qualify a strict hardware-enclave contract"
type: security
status: rejected
date: 2026-08-22
parent: 2026-08-22-001-macos-hardware-beta-to-ga-plan.md
---

# security: qualify a strict hardware-enclave contract

**Policy clarification (revised 2026-08-24):** “Strict” in this rejected experiment means mutation-free key lifecycle and fail-closed storage validation; it is not the public authorization-policy name. The current product contract keeps effectively unlocked named `--env` runs on normal vault-mode behavior, requires Touch ID for broad runs, and requires Touch ID for effectively locked named runs.

## Implementation outcome — 2026-08-22

The bounded correction experiment ended in **reject**. An isolated checkout added strict lifecycle entry points, an explicit `.biometryCurrentSet` bridge value, structured code identity, typed lifecycle errors, and focused contract tests. The focused tests and library-only lint passed, but review showed that the tests did not model the macOS Keychain and cache behavior that controls the real guarantee.

The attempted strict paths still reached legacy helpers that can repair cached state, migrate a wrapping-key item, or succeed after metadata-integrity setup fails. Strict open also read authenticated metadata twice, did not retain strict verification for later encryption and decryption, and did not prove that the wrapped handle and Keychain item were usable. Locks scoped to `keys_dir` could not serialize the globally shared Keychain identity when two callers used different directories. Path-based `codesign` inspection could race executable replacement and did not establish the identity of the running code object.

These findings invalidate the one-day “smallest dependency correction” bet. The experiment remains local and uncommitted; no fork was published and Keyclasp was not re-pinned. A later replacement slice removed the rejected dependency from the status-only probe. No Secure Enclave key or Keyclasp vault was touched.

The next plan must compare replacing the dependency with a narrow Keyclasp-owned macOS adapter against a deeper upstream redesign. Either direction must own one canonical Keychain identity and transaction boundary, authenticate metadata from one byte snapshot, retain strict mode for every operation, and inspect the running code through Security.framework.

## Desired outcome

Produce one corrected, immutable `hardware-enclave` revision that is safe to take into physical Secure Enclave testing. The revision must give Keyclasp explicit current-set biometric policy, strict create-new and open-existing operations, and a code-identity result that distinguishes development, ad-hoc, and Developer ID artifacts.

This is the corrective slice between the rejected dependency audit and the original plan's physical-device matrix. It does not enroll a hardware key, touch a Keyclasp vault, add secret-bearing native operations, or make the dependency production-ready. Passing this slice means only that the dependency is eligible for physical qualification.

## Relevant current codebase

- [`native/keyclasp-core/`](../../native/keyclasp-core/) is now a status-only Keyclasp-owned adapter. Its pinned RustCrypto Argon2id dependency serves only the private recovery envelope; the rejected `hardware-enclave` dependency remains absent. Revision `3b4ac1bcb637fb60ac18d4cd9877dba989c46dba` (`v0.2.10`) remains evidence only. The probe's command parser rejects create, wrap, unwrap, destroy, export, and shell operations.
- [`docs/security/2026-08-22-hardware-enclave-spike-evidence.md`](../security/2026-08-22-hardware-enclave-spike-evidence.md) records the three adoption blockers and owns the evidence matrix.
- [`docs/solutions/architecture-patterns/secure-enclave-beta-requires-current-set-biometry.md`](../solutions/architecture-patterns/secure-enclave-beta-requires-current-set-biometry.md) records the failed assumptions that must not return through another API.
- The upstream `AccessPolicy::BiometricOnly` variant maps to `.biometryAny` in `crates/hardware-enclave/swift/bridge.swift`.
- Upstream `create_encryptor()` reaches `AppEncryptionStorage::init()`, which creates a missing key, accepts an existing key with missing metadata, and deletes then recreates a policy-mismatched key.
- Upstream `is_binary_signed()` reduces code identity to a Boolean and invokes `codesign` through `PATH`, so an ad-hoc artifact is indistinguishable from a Developer ID artifact.

## Gap

Keyclasp cannot safely test an enrolled key while inspection and opening can change the evidence being inspected. It also cannot enforce enrollment-set invalidation through a policy whose name hides `.biometryAny`, or plan the beta-to-GA identity transition from a signed/unsigned Boolean.

The dependency needs a small durable-key contract before the physical matrix can begin:

1. `create new` creates exactly once and fails when state already exists;
2. `open existing` never creates, repairs, deletes, rekeys, or accepts incomplete metadata;
3. biometric current-set is an explicit policy distinct from any-enrolled-biometric;
4. code identity reports development, unsigned, ad-hoc, Developer ID, or unknown without searching `PATH`; and
5. no strict operation silently downgrades a requested hardware, access-control, or entitlement requirement.

## Experiment decisions

- Correct the selected dependency before replacing the architecture. Keep the patch narrow enough to propose upstream, but pin Keyclasp to a full commit in a Keyclasp-controlled fork until an accepted upstream release provides the same contract.
- Preserve the existing `create_encryptor()` behavior only as a documented legacy compatibility path. Add two unambiguous public entry points backed by one internal state machine: `create_new_encryptor()` and `open_existing_encryptor()`.
- Add an explicit `BiometricCurrentSet` policy with a new FFI value. Do not silently change the existing serialized or FFI meaning of `BiometricOnly`; Keyclasp must never request the legacy policy.
- Add a structured code-identity classification while retaining `is_binary_signed()` only as a compatibility projection. On macOS, use the fixed system tool path or Security framework APIs; never resolve identity tooling through `PATH`.
- Make strict-mode metadata absence, corruption, policy mismatch, backend mismatch, and entitlement loss hard errors. Repair is a separate future administrative operation and cannot be triggered by open.
- Keep Keyclasp's probe status-only throughout this slice. Contract tests use injected or temporary backends and inspect call traces and filesystem snapshots; they do not create a real Secure Enclave key.
- Treat an upstream merge as helpful, not as an adoption prerequisite. The pinned fork becomes Keyclasp's security-update responsibility for as long as the beta depends on it.

## Walking skeleton

One macOS build proves the complete non-mutating contract:

1. A dependency test opens a complete fake key and records zero generate, delete, or metadata-write calls.
2. The same test opens missing, incomplete, corrupted, wrong-policy, and wrong-backend fixtures; every case returns a typed error and leaves both the call trace and a byte-for-byte state snapshot unchanged.
3. A create-new test creates one key from empty state, then proves that a second create fails without deleting or replacing it.
4. A Swift bridge test pins `BiometricCurrentSet` to `.biometryCurrentSet` and keeps the legacy biometric value distinct.
5. macOS identity tests classify Cargo, unsigned, and ad-hoc fixtures separately; Developer ID-shaped output is covered by a parser fixture until a real Developer ID artifact exists.
6. Keyclasp re-pins the corrected commit and its status probe reports the structured identity and required current-set policy without opening key storage.

## Vertical delivery slices

### Slice 1: Lock the strict contract with failing tests

**Status:** attempted but not accepted. Adding the tests to `3b4ac1b` produced the expected compile-time red state because the strict APIs and errors did not exist. The experimental patch made the focused suite pass, but it compiled out strict integrity verification and replaced the mutating macOS behavior with a read-only fake. It therefore did not prove the blocker-specific negative paths required by this slice.

**Outcome:** the intended durable-key semantics are executable and independent of a physical Mac's enrolled state.

**Implementation areas:**

- Add dependency-level tests around one internal open-mode state machine: legacy create-or-repair, strict create-new, and strict open-existing.
- Give the fake encryption backend counters for generate, delete, public-key lookup, encrypt, decrypt, and metadata writes.
- Snapshot temporary metadata directories before and after every strict negative path.
- Add typed errors for already exists, not found, incomplete metadata, policy mismatch, backend mismatch, and unsupported identity.
- Add source or bridge tests for the new current-set FFI value and fixture-based tests for code-identity parsing.

**Acceptance:** tests fail against `3b4ac1b`; every failure names one of the three recorded blockers; no test needs Touch ID, a real Keychain item, or a Keyclasp vault.

### Slice 2: Implement the smallest dependency correction

**Status:** rejected after implementation and review. The correction could not meet the strict lifecycle acceptance criteria without replacing legacy Keychain, cache, metadata, and code-identity behavior.

**Outcome:** the dependency passes the strict contract without changing its legacy callers by surprise.

**Implementation areas:**

- Route `create_new_encryptor()` and `open_existing_encryptor()` through the shared state machine; keep deletion and regeneration unreachable from both modes.
- Require complete, integrity-valid metadata before strict open returns a handle.
- Add `BiometricCurrentSet` end to end through Rust types, serialization, bridge protocol, and Swift `.biometryCurrentSet` access control.
- Add structured macOS code-identity classification and remove relative `codesign` invocation. Keep unknown or malformed identity output fail-closed.
- Update dependency documentation and its supported-version statement, or record explicitly that the pinned fork owns beta support.
- Run the dependency's formatting, lint, unit, and macOS build checks with default features disabled and only the encryption feature enabled where Keyclasp consumes it.

**Acceptance:** the contract suite passes; strict open has no generate, delete, or write edge; strict create cannot replace state; ad-hoc and Developer ID are distinct values; current-set policy is explicit and has no software or weaker-policy fallback.

### Slice 3: Re-pin Keyclasp and renew the adoption gate

**Status:** not started. The rejected correction was not published or pinned; the replacement adapter was selected outside this rejected dependency plan.

**Outcome:** Keyclasp contains a reproducible, non-mutating probe for the corrected contract and a precise decision about entering physical testing.

**Implementation areas:**

- Publish or otherwise make immutable the reviewed correction, then update [`native/keyclasp-core/Cargo.toml`](../../native/keyclasp-core/Cargo.toml) and `Cargo.lock` to its full commit SHA. Publishing a fork or upstream pull request is a separate authorized ship action.
- Replace the Boolean `binary_codesign_check_passed` status field with structured identity output and report `required_access_policy=biometric_current_set`.
- Keep the probe command surface status-only and retain the npm package-contents regression test.
- Extend the evidence record with the corrected revision, patch diff, tests, dependency support owner, and an **eligible for physical qualification** or **reject** decision.
- If any strict guarantee requires Keyclasp to call a legacy mutating or downgrade-capable API, reject the revision and re-plan rather than wrapping the behavior in another abstraction.

**Acceptance:** a clean checkout resolves the exact revision, builds the ad-hoc probe, runs the contract suite, and packs npm without native spike sources; status performs no key-storage mutation; the evidence record does not call the dependency production-ready.

## Technical bets and bounded spikes

1. **Strict lifecycle split, one day.** Prove the current storage implementation can expose strict create/open semantics through one state machine without forking its encryption format. If not, reject the candidate rather than copy its internals into Keyclasp.
2. **Current-set policy, half day.** Add a distinct FFI value and compile the Swift bridge. Physical enrollment-change behavior remains a later test; this slice proves only that the dependency requests the correct Apple flag.
3. **Code identity, one day.** Produce structured identity for Cargo, unsigned, and ad-hoc artifacts and a fixture for Developer ID. If parsing system-tool output is unstable, use Security framework signing information instead of adding heuristics.

Each spike ends in tests or a reject decision. The timebox is for choosing the next direction, not for weakening a failed control.

## Deferred decisions

- Secure Enclave key creation, Touch ID success/denial/cancellation, biometric enrollment changes, T2 hardware, and second-Mac copying remain in the parent plan's physical matrix.
- Recovery-passphrase wrapping and re-enrollment remain prerequisites before any enrolled test key is deleted or replaced.
- The full Swift/FFI, unsafe-code, transitive-dependency, and build-script audit remains required before production adoption.
- Vault format, native request protocol, Node boundary removal, child launch, packaging, signing, and notarization remain blocked Slices 2–4 of the parent plan.
- Upstream merge timing does not block the next physical test, but Keyclasp must not publish a beta from an unsupported or mutable dependency reference.

## Done criteria

**Result:** not met. The evidence record ends in **reject**, so this plan does not unblock physical qualification.

- The corrected dependency is pinned by full immutable commit and its ownership/support status is explicit.
- Keyclasp can call strict create-new and strict open-existing APIs without any implicit create, repair, delete, rekey, downgrade, or incomplete-metadata acceptance.
- Current-set biometric policy is a distinct Rust, protocol, and Swift value that maps to `.biometryCurrentSet`.
- Code identity distinguishes development, unsigned, ad-hoc, Developer ID, and unknown states without `PATH` lookup; unknown fails closed.
- Contract tests prove strict negative paths make no backend mutation and no metadata byte changes.
- The Keyclasp probe remains status-only, contains no secret operation, and stays outside the npm package.
- No real Secure Enclave key or Keyclasp vault is created, changed, or deleted during this slice.
- The evidence record ends with either **eligible for physical qualification** or **reject**. Only the first result unblocks the parent plan's remaining Slice 1 work.
