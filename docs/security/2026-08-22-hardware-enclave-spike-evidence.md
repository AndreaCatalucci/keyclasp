# `hardware-enclave` Slice 1 evidence

## Candidate

- Repository: `https://github.com/godaddy/hardware-enclave`
- Revision: `3b4ac1bcb637fb60ac18d4cd9877dba989c46dba`
- Tag: `v0.2.10`
- Commit date: 2026-06-26
- License: MIT, copyright Jay Gowdy
- Maintainer provenance: the pinned release commit is authored by Jay Gowdy through the `jgowdy-godaddy` GitHub account; the repository belongs to the GoDaddy organization.
- Security contact: GitHub private vulnerability reporting or the maintainer, with a documented 72-hour acknowledgement target.
- Context7 coverage: no matching library entry on 2026-08-22; the audit used the pinned upstream repository.

## Dependency boundary

The spike enables only the crate's `encryption` feature with default features disabled. That feature includes the signing and platform key-management dependencies needed by the macOS CryptoKit bridge. `Cargo.lock` is the executable dependency graph once generated.

The crate's build script compiles `swift/bridge.swift` with the active Xcode toolchain and links CryptoKit, Security, LocalAuthentication, SwiftCore, and SwiftFoundation. The checked macOS dependency graph contains `unsafe` around the Swift C ABI, protected-memory implementation, process hardening, and libc or pthread operations. A complete inventory and line-by-line review of every cfg-compiled unsafe block and transitive build script remains open.

## Source-audit results

| Control | Result | Evidence |
| --- | --- | --- |
| macOS backend selection | Source audit shows that the macOS target dispatcher reports `BackendKind::SecureEnclave`; the probe prints that report but does not prove hardware availability | upstream `factory.rs` and the probe's `status` output |
| Non-exportable private key | Candidate uses `SecureEnclave.P256.KeyAgreement.PrivateKey`; only CryptoKit's opaque data representation and public key leave the bridge | upstream `swift/bridge.swift` |
| Biometric-only use | Rejected: `BiometricOnly` maps to `.biometryAny`, which does not invalidate the key when enrollment changes | upstream `makeAccessControl()` |
| Ad-hoc identity classification | Needs physical proof: the crate treats `codesign --verify --no-strict` success as signed outside Cargo's `target` path | upstream `internal/core/signing.rs` |
| Fixed identity-tool path | Rejected: signing detection invokes `codesign` through `PATH`; entitlement inspection uses `/usr/bin/codesign` | upstream `internal/core/signing.rs` and `capabilities.rs` |
| Read-only open semantics | Rejected: public `create_encryptor()` creates a missing key and replaces a policy-mismatched key, so an evidence check can mutate enrollment | upstream `factory.rs` and `AppEncryptionStorage::init()` |
| Software fallback on macOS | No macOS software backend is selected by the candidate's platform dispatcher | upstream `factory.rs` and app-storage macOS initialization |
| Plaintext lifetime | Candidate returns decrypted bytes in `Zeroizing<Vec<u8>>`; the Swift bridge and FFI copy path still require detailed review | upstream `EncryptorHandle::decrypt()` and Swift bridge |
| Dependency support statement | Needs clarification: the checked-out security policy lists `0.1.x` as supported while the pinned tag is `v0.2.10` | upstream `SECURITY.md` |

## Executable matrix

The repository now contains a non-production build/status probe at `native/keyclasp-core/`. It has no key or secret operations. Record results without secret values.

| Test | Apple Silicon Mac | T2 Mac | Second physical Mac | Result |
| --- | --- | --- | --- | --- |
| Build and ad-hoc signature verification | Passed on macOS 27 with matching Xcode beta and isolated module caches | Pending | Not applicable | `codesign --verify --strict` passed; artifact reports `flags=0x2(adhoc)` |
| Interactive status capability probe | Passed | Pending | Not applicable | The user-run artifact reported Secure Enclave and Touch ID available with ad-hoc code identity |
| Secure Enclave key creation | Blocked at signing identity | Pending | Not applicable | Interactive ad-hoc run reached `SecKeyCreateRandomKey`, which returned `errSecMissingEntitlement`; no key reference or receipt was returned |
| Touch ID success | Pending | Pending | Not applicable | Pending |
| Touch ID denial | Pending | Pending | Not applicable | Pending |
| Touch ID cancellation | Pending | Pending | Not applicable | Pending |
| Missing biometric enrollment | Pending | Pending | Not applicable | Pending |
| Enrollment-set change | Pending | Pending | Not applicable | Expected rejection from source audit |
| Corrupted recovery envelope | Local contract passed | Pending | Not applicable | Wrong passphrase and ciphertext tampering return the same authentication failure; physical vault-root recovery remains pending |
| Deleted key | Pending | Pending | Not applicable | Pending |
| Complete state-directory copy | Source | Source | Pending | Pending |
| Unchanged artifact | Pending | Pending | Not applicable | Pending |
| Rebuilt ad-hoc artifact | Pending | Pending | Not applicable | Pending |
| Updated artifact | Pending | Pending | Not applicable | Pending |

The ad-hoc artifact's non-mutating `status` operation reported:

```text
reported_backend=Secure Enclave
hardware_presence_available=false
binary_codesign_check_passed=true
effective_app_name=keyclasp-core-spike-v1
```

This process had no usable Touch ID authorization context, so no enrolled-key operation was run. The result also confirms that the candidate classifies an ad-hoc signature as signed. `reported_backend` comes from target-platform selection and does not prove that an enrolled Secure Enclave operation succeeded.

The user then ran the staged Keyclasp-owned artifact from an interactive Apple Silicon session. On 2026-08-22 it reported:

```text
protocol_version=1
adapter=keyclasp_macos_v1
reported_backend=secure_enclave
hardware_presence_available=true
touch_id_available=true
code_identity=ad_hoc
required_access_policy=biometric_current_set
current_set_policy_available=true
lifecycle_operations=disabled
enrollment_state=unavailable
```

This result proves that the ad-hoc status artifact sees Secure Enclave and Touch ID from the user's interactive session. The status command creates no key and cannot prove Touch ID-bound use, enrollment invalidation, recovery, or copying behavior.

## Adoption decision

### Bounded correction experiment

An isolated, uncommitted upstream checkout added strict create/open entry points, a distinct `BiometricCurrentSet` value mapped to `.biometryCurrentSet`, typed lifecycle errors, and structured code identity. The following local checks passed without creating a Secure Enclave key or touching a Keyclasp vault:

- 11 focused strict-contract tests;
- 2 current-set policy tests;
- the code-identity parser test;
- the storage-error conversion test;
- library-only Clippy with `--no-default-features --features encryption -- -D warnings`;
- `git diff --check`; and
- an ad-hoc-signed copied example verified by `/usr/bin/codesign --verify --strict` and classified as `ad_hoc`.

Independent review found that these checks gave false confidence about the production paths:

- strict-open tests compiled out the production integrity verifier, and strict-create tests stopped before macOS persistence and rollback;
- strict create/open called `public_key()`, which can restore the public-key cache and migrate Keychain state;
- strict create could return success after metadata-HMAC setup failed, leaving state that strict open would reject;
- strict open authenticated metadata and then reparsed a second filesystem read, and the returned handle resumed legacy fail-open integrity checks;
- open could succeed from the `.pub` cache without proving that the wrapped handle and Keychain item were usable;
- `keys_dir` locks did not serialize the global Keychain service/account identity across callers, and cache identity omitted access group and Keychain domain;
- entitlement validation used substring matching, while the public `OtherSigned` state treated unrecognized verified signatures as trusted; and
- path-based `codesign` subprocesses did not establish the identity of the running code object and could observe different executable generations.

The test-only red run against `3b4ac1b` was a compile failure caused by the missing strict APIs and typed errors. It was not a captured blocker-by-blocker failure run and does not satisfy the contract plan's Slice 1 acceptance criterion.

### Decision

**Reject revision `3b4ac1b` and the bounded correction for hardware mode.** The attempted correction cannot meet the non-mutating lifecycle contract through a small wrapper around the existing state machine. The fork was not published and Keyclasp was not re-pinned to the experiment.

## Replacement adapter feasibility

The status probe now uses a Keyclasp-owned Rust, Swift, and C adapter. Its only direct Rust dependencies are pinned RustCrypto `argon2` 0.5.3 and `zeroize` 1.8.2 for the private recovery envelope; the rejected `hardware-enclave` dependency is absent. Its executable still exposes only `status`. A hidden create/open backend is compiled for contract testing but is unreachable from the command line; wrapping, deletion, export, vault, and child-launch operations remain absent.

The adapter:

- reports `SecureEnclave.isAvailable` for the current process;
- constructs access control with exactly `.privateKeyUsage` and `.biometryCurrentSet`;
- obtains the running process through `SecCodeCopySelf`, checks strict validity, and applies the Developer ID Application leaf-certificate requirement directly to that running code object;
- reads development and ad-hoc flags from the kernel's runtime code-signing status rather than an executable pathname;
- compiles an explicit `ad_hoc` build marker only for the reviewed beta build, after which runtime code-signing flags must still prove an ad-hoc signature; and
- builds in a clean explicit host-target directory, verifies and runs the temporary signed candidate, then atomically replaces the staged artifact only when it reports `code_identity=ad_hoc` and `required_access_policy=biometric_current_set`.

The following checks passed:

- 52 Rust contract tests across the library and status binary, including lifecycle ordering, committed-envelope reopening before backend creation, passphrase recovery in a separate process, bounded and versioned Argon2id parameters, dual-wrapped disposable vault-key state, independent fixed binary-format vectors, authenticated policy and public-key state, logical uniqueness, exact rollback, one-snapshot read-only open, stable FFI errors, private runtime boundaries, a four-symbol status-adapter export allowlist, a mutating-API denylist, identity classification, permissions, ACLs, and separate-process lock contention;
- native C and Swift compilation with warnings denied;
- a lockfile-pinned Argon2id graph with default password-hash and randomness features disabled, permissive licenses throughout, explicit work-memory zeroization, and no OSV advisory returned for any of the 13 locked external packages on 2026-08-23;
- the npm package-contents regression test; and
- clean ad-hoc build, strict signature verification, runtime status verification, and atomic staging.

The hidden lifecycle backend generates a random 32-byte challenge, signs it with the new private Secure Enclave key, and verifies the signature locally before create can return success. Open validates the authenticated identity without a separate signature prompt, then obtains private-key authorization through the ECIES decrypt itself. Both paths make denied biometric authorization and a key invalidated by biometric enrollment changes observable as failed lifecycle operations. No command can call this code yet.

The staged artifact reported:

```text
adapter=keyclasp_macos_v1
reported_backend=secure_enclave
hardware_presence_available=false
code_identity=ad_hoc
required_access_policy=biometric_current_set
current_set_policy_available=true
```

`hardware_presence_available=false` is process-scoped evidence from this Codex session, not proof that the Mac lacks a Secure Enclave. Developer ID classification uses Apple's leaf-certificate requirement but remains fixture-only until a real Developer ID artifact exists.

**Select the Keyclasp-owned adapter for the next lifecycle slice.** This selection did not make the adapter eligible for physical qualification. The hidden backend and authenticated vault-key lifecycle store now compile and pass local contract tests, but rollback, Touch ID behavior, recovery, and two-Mac behavior remain unverified on physical hardware.

## Strict lifecycle contract

The owned adapter now contains an internal transaction contract and a hidden Security.framework backend without exposing a new command.

The contract:

- canonicalizes the selected vault home, derives the Keychain application tag from those exact bytes, and derives a stable per-user lock name from that tag so vault-directory replacement cannot split the lock domain;
- supplies only `BiometricCurrentSet` during creation and accepts only a `SecureEnclave` record with the exact application tag and label plus a canonical, on-curve, uncompressed P-256 public key;
- restores the enrollment-authentication root from an owner-only, versioned passphrase envelope before it authenticates the expected public key and required policy;
- rejects a vault home not owned by the current user with mode `0700` or one carrying an extended ACL, then serializes create and open through a no-follow lock in a separately validated owner-only per-user directory;
- calls one locked backend `create_new` operation whose exact read-only application-tag preflight is internal to the platform boundary, with no repair, update, broad delete, or fallback method in the backend interface;
- creates a permanent Secure Enclave P-256 key with `WhenUnlockedThisDeviceOnly` accessibility and `BiometryCurrentSet | PrivateKeyUsage` access control, then inspects the returned key, its stored identity, access-control witness, accessibility class, and logical singleton before returning it;
- supplies that backend operation with a Rust validator it must call before success, deletes the exact returned key through `kSecMatchItemList` after any post-create failure, and surfaces cleanup failure as partial state;
- maps duplicate, missing, denied, unsupported, and backend failures to typed lifecycle errors; and
- calls one backend `open_existing` operation and records zero writes in every success and rejection test.

Apple's Security regression suite demonstrates the platform flow: `SecKeyCreateRandomKey` creates a permanent Secure Enclave key with access control, and `SecItemCopyMatching` retrieves it later. Apple's Keychain source describes the application label as the public-key hash and exposes the application tag separately, so this backend does not assume that the logical tag is a physical uniqueness field. The interprocess lock, an exact zero-match preflight, and an exact one-match postcondition enforce Keyclasp's logical create-new contract for cooperating Keyclasp processes. The postcondition detects an external writer only when its conflicting key exists before the final count; Keychain provides no transaction that excludes an unrelated process. Sources: [Apple Secure Enclave Keychain regression](https://github.com/apple-oss-distributions/security/blob/main/OSX/shared_regressions/si-44-seckey-aks.m) and [Apple Keychain item attributes](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_keychain/lib/SecItem.cpp).

The lifecycle and bridge suite now passes 52 tests across the library and status binary. The suite covers canonical identity, durable recovery-envelope creation and authenticated reopening before backend work, rejection of orphaned lifecycle metadata before recovery reinitialization, Argon2id v1.3 at 64 MiB, three passes, and one lane, AES-256-GCM, independent fixed recovery and vault-key vectors, distinct roots and envelopes for two vaults using the same passphrase, wrong-passphrase and ciphertext-tamper equivalence, restoration in a separate process, recovery-envelope-only restart resumption, recovery-wrapped vault-key persistence before hardware creation, one authenticated pending-to-active transition binding policy, public key, and both wrappers, mismatch rejection between hardware and recovery copies, safe stale-temporary-file cleanup, hard links, symlinks, extended ACLs, exact directory and file permissions, rejection of insecure files before the KDF runs, failed-create recovery state, atomic create and wrap, duplicate preservation, one-snapshot read-only open, bridge error-code stability, incomplete or off-curve public keys, a different valid enrolled key, vault-directory replacement, bounded metadata reads, and separate-process lock contention. Source-contract checks require secure random generation, HMAC-SHA256, `timingsafe_bcmp`, key zeroization, the variable-IV X9.63/SHA-256/AES-GCM ECIES algorithm, encrypt and decrypt support checks, an authenticated public-key match before private-key use, a random challenge, local signature verification, logical preflight and singleton validation, Rust validation, atomic hardware wrapping, and exact rollback. Open-existing contains no persistent mutation. The command parser still rejects create, wrap, unwrap, destroy, export, and shell operations. No automated test calls the hidden Security.framework backend, so the suite created, opened, changed, or deleted no Keychain item or Secure Enclave key.

**Dual-wrapped disposable vault key compiled; physical qualification pending.** The private transaction creates a random 32-byte enrollment-authentication root and writes it once in `.hardware-recovery.v2`, wrapped under Argon2id v1.3 and AES-256-GCM. Its authenticated header stores the fixed 64 MiB memory cost, three passes, one lane, 32-byte output, 16-byte minimum, 1,024-byte maximum, salt length, and nonce length. Restore rejects any changed parameter before allocating memory. The implementation allocates exactly 65,536 one-kibibyte blocks and explicitly clears each block after success or failure. Initialization clears its original root, reopens the committed envelope through the owner-only file checks, and returns only the reopened root; an unreadable envelope therefore blocks the hardware backend. A legacy `.hardware-recovery.v1` marker blocks initialization and remains byte-identical; the private spike performs no silent PBKDF2 migration. A later process restores the same root only after the passphrase authenticates. The transaction derives a domain-separated recovery wrap key, generates a disposable 32-byte vault data key, and durably creates one pending `.hardware-vault-key.v1` record with an AES-256-GCM recovery copy before it calls the permanent-key backend. After backend validation, it wraps that same data key with variable-IV X9.63/SHA-256/AES-GCM ECIES using the canonical public key. One atomic replacement activates the record and authenticates the application tag, current-set policy, public key, hardware ciphertext, version, algorithms, nonce, recovery ciphertext, and tag. Open-existing authenticates the recovery envelope and vault-key record, derives the expected enrollment from that single record, validates the exact Keychain item, performs one hardware decrypt, and compares the hardware result with the recovery result in constant time before discarding both key buffers. A backend error leaves authenticated recovery-required state, so retry cannot create or replace another hardware key. Reads reject symlinks, hard links, extended ACLs, extra permissions, wrong passphrases, malformed lengths, trailing bytes, and authentication changes. Apple exposes no public accessor for the internal constraints of a persisted `SecAccessControl`, so the enrollment-change run must still prove current-set invalidation. No normal hardware-only bootstrap path or replacement-key recovery operation is exposed.

The fixed recovery format matches an independent Node 26 `crypto.argon2Sync` and AES-256-GCM vector. An optimized test that performs one encode and one decode completed in 0.19 seconds on the development Apple Silicon Mac, about 95 ms per derivation. The same parameters still require calibration on the supported T2 floor. RustCrypto `argon2` is pinned to 0.5.3 with default features disabled and only its zeroization feature enabled; `zeroize` is pinned to 1.8.2. The lockfile contains 13 external packages across supported target graphs. Every declared license is MIT, Apache-2.0, or BSD-3-Clause, and an OSV batch query returned no advisory for those exact versions on 2026-08-23. This is a bounded manifest, feature, license, and advisory review; the Slice 3 line-by-line dependency and build-script audit remains open.

## Residual blockers

- Generate a recovery credential with at least 128 bits of randomness, or enforce a reviewed text-aware strength policy in the beta enrollment flow. The 16-byte format floor rejects short input but cannot distinguish a strong phrase from a common repeated word.
- Beta block 3 is blocked on a reviewed bounded disposable-key harness and user-authorized interactive testing. The public artifact remains status-only, so no command can create a test key, unwrap a data key, or expose a generic decrypt operation. Do not turn on lifecycle operations just to collect evidence.
- Obtain an interactive Apple Silicon session with an enrolled Touch ID user, a T2 Mac, and a second physical Mac. The status probes below establish only capability visibility; they do not establish authorization, enrollment state, or any Secure Enclave private-key operation.
- Physically prove Secure Enclave create, authorized use, denial, cancellation, exact rollback, current-set enrollment invalidation, interruption/recovery, update-identity behavior, and copied-vault failure. The block-2 ECIES qualification uses an in-memory software test key and a fake transaction backend; it does not prove hardware custody, Touch ID, or Keychain behavior.
- Kill the physical qualification process during the Touch ID prompt and confirm the authenticated pending record blocks retry until recovery resumes the transaction.
- Run the compiled signature proof before and after a biometric enrollment-set change; the post-change private-key operation must fail. Keep bound stored ACLs out of fresh-template comparisons.
- Inventory and review every macOS-compiled unsafe Rust block, the Swift FFI, transitive dependencies, and build scripts.
- Prove that the permanent Secure Enclave key uses the canonical application tag, that logical duplicate creation never replaces or multiplies it, and that open-existing performs lookup and validation only.

## Beta block 1: native secret-buffer ownership and capture containment

**Completed locally on 2026-08-23.** The private native lifecycle boundary now installs the capture guard before it takes an owned file descriptor and reads the recovery passphrase into an owned `RecoveryPassphrase` buffer, which zeroizes on drop. The status-only executable does not expose that descriptor path; block 4 must bind it to a terminal or inherited descriptor rather than route passphrases through Node. `VerifiedRecovery`, `VaultDataKey`, Argon2 work blocks, recovery wrapping keys, and temporary hardware-unwrapped data-key arrays are native-owned and explicitly cleared.

Apple documents [`SecKeyCreateDecryptedData`](https://developer.apple.com/documentation/security/seckeycreatedecrypteddata%28_%3A_%3A_%3A_%3A%29) as returning decrypted `CFData` that the caller releases. [`CFRelease`](https://developer.apple.com/documentation/corefoundation/cfrelease) documents deallocation/destruction, not secure clearing; `CFData` is immutable unless separately created mutable. The bridge therefore does not use an unsafe const-cast or assert that `CFRelease` wipes bytes. Its only framework-owned plaintext `CFData` is scoped to the decrypt helper, copied once into Rust-owned zeroizable storage, and promptly released. Before either hidden create or open lifecycle operation can accept recovery state or call the decrypt helper, the C bridge sets and reads back `RLIMIT_CORE = 0` for the short-lived process. This suppresses traditional core files, but cannot attest to or disable an administrator-configured external macOS crash collector. Accordingly, `lifecycle_operations=disabled` remains required until block 3 physical/crash-capture review; no command can unwrap today.

### Commands and results

- `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer CLANG_MODULE_CACHE_PATH=<fresh /private/tmp cache> cargo test --manifest-path native/keyclasp-core/Cargo.toml --locked` — passed: 51 library tests plus 1 status-binary test (52 total). New source contracts pin moved passphrase ownership, the pre-lifecycle capture guard, zero initialization of the Rust destination, single `CFData` copy, and prompt `CFRelease`.
- `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer CLANG_MODULE_CACHE_PATH=<fresh /private/tmp cache> cargo clippy --manifest-path native/keyclasp-core/Cargo.toml --locked -- -D warnings` — passed.
- `native/keyclasp-core/scripts/build-adhoc.sh /private/tmp/keyclasp-core-block1 qualification` — passed: clean build, strict ad-hoc signature verification, runtime status/capability check, and atomic staging. This is a compiled artifact check, not physical enrollment or unwrap evidence.
- `npm run build` — passed after `npm ci` restored this worktree's missing dependencies.
- `npm test -- --reporter=dot --silent` — passed: 15 files and 243 tests. An earlier run immediately after dependency restoration observed a transient `API_KEY` integration failure; the final clean run passed without changing Node code.
- `NPM_CONFIG_CACHE=/private/tmp/keyclasp-npm-cache npm pack --dry-run --json` — passed with an isolated writable cache; the package contains 39 expected files and excludes the status-only native spike. The native package-contents regression also passed in the Node suite. An earlier default-cache attempt was blocked by pre-existing root-owned files in `/Users/andreacatalucci/.npm/_cacache`; no ownership repair was attempted.

### Learnings

- Apple supplies a releasable decrypted `CFData`, not a caller-wipeable one. The supported design is to keep it scoped, copy it once into owned zeroizable memory, and leave secret-bearing operations disabled until the physical crash-capture and unwrap evidence exists; `CFRelease` is not a wiping claim.
- A zero core-file limit is a necessary precondition for the short-lived native core, but it is not proof about external macOS crash collectors. Keep that distinction in release claims and physical qualification.

## Beta block 2: bounded ECIES qualification and post-backend rollback

**Completed locally on 2026-08-23.** The private `ecies_qualification` operation has no input and returns no cryptographic material. It restores Apple’s documented in-memory P-256 private-key representation for the fixed scalar `1` through `SecKeyCreateWithData`, derives its public key, runs `kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM`, checks the 32-byte fixed test vector after decrypt, and requires a one-bit ciphertext change to fail. The test key, cleartext, and temporary buffers are cleared before return. The operation is `pub(crate)`, its C symbol is hidden, and the status-only command does not call it. It creates no Keychain item, uses no Secure Enclave key, and cannot export a vault key or plaintext.

`HardwareKeyBackend` now has an exact rollback operation for the interval after `create_new` returns. The platform backend retains its trusted canonical tag, label, and public key from creation; it never uses a returned record that failed Rust validation as cleanup input. If Rust validation fails, or `VaultKeyStore::activate` fails before its atomic rename, the still-locked transaction asks the platform backend to locate exactly one private Keychain item with that trusted identity, validates it, then deletes that exact value reference. A rollback failure returns `CleanupFailed`; it is never hidden by the original error. A failed directory sync after rename is distinct: activation is indeterminate, so the transaction retains the hardware key and returns `VaultKeyActivationIndeterminate` for recovery rather than deleting a key that active metadata may already reference. Failure-injection tests cover post-return validation rollback, pre-rename activation rollback, cleanup failure, and post-rename indeterminate activation. This fixes the lesson recorded in [`secure-enclave-permanent-create-validates-after-persistence.md`](../solutions/architecture-patterns/secure-enclave-permanent-create-validates-after-persistence.md).

### Commands and results

- `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer CLANG_MODULE_CACHE_PATH=<fresh /private/tmp cache> cargo test --manifest-path native/keyclasp-core/Cargo.toml --locked` — passed: 56 library tests plus 1 status-binary test (57 total). The ECIES qualification ran against `Security.framework`; rollback tests used injected backends and did not create a Keychain item.
- `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer CLANG_MODULE_CACHE_PATH=<fresh /private/tmp cache> cargo clippy --manifest-path native/keyclasp-core/Cargo.toml --locked -- -D warnings` — passed.
- `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer CLANG_MODULE_CACHE_PATH=<fresh /private/tmp cache> native/keyclasp-core/scripts/build-adhoc.sh /private/tmp/keyclasp-core-block2-final qualification` — passed: release build, strict ad-hoc signature verification, designated requirement, capability/status check, and atomic staging. An initial invocation without `DEVELOPER_DIR` failed because the selected Command Line Tools Swift compiler did not match its SDK and could not write its default module cache; the explicit Xcode-beta invocation is the valid compiled result.
- `npm run build` — passed.
- `npm test -- --reporter=dot --silent` — passed: 15 files and 243 tests.
- `NPM_CONFIG_CACHE=/private/tmp/keyclasp-npm-cache-block2-final npm pack --dry-run --json` — passed: 39 files, 214,579 unpacked bytes, and the status-only native spike remains outside the package boundary.
- `git diff --check` — passed.
- `ae-review` — completed across correctness, security, tests, simplicity, and concurrency perspectives. Review found and this slice fixed two P1 rollback gaps: post-rename directory-sync indeterminacy and use of a malformed returned record during rollback. The final re-reviews were clean.

### Learnings

- A bounded compiled ECIES check must not depend on Keychain or Secure Enclave availability. Apple’s in-memory P-256 representation makes the algorithm and tamper path testable without turning a qualification run into enrollment evidence.
- Platform rollback inside `create_new` is insufficient when Rust activation follows it. Keep trusted-creation-token rollback open through all pre-rename activation failures, preserve a distinct cleanup failure for partial state, and retain the key when a post-rename directory sync makes activation indeterminate.

### Integration review correction

The main-checkout review found one release-blocking ownership gap before lifecycle enablement: recovery roots, vault data keys, and HMAC outputs were first produced in plain Rust stack arrays and then moved into drop-zeroized owners. Rust moves do not guarantee that the abandoned source stack slot is cleared. The integrated correction stores those secrets in stable heap-backed owners, writes random, decrypted, or derived bytes directly into the final allocation, and makes HMAC generation fill caller-owned output. Moving an owner now moves only its pointer; dropping it clears the one secret allocation. Regression tests pin allocation identity and observed clearing across owner moves, plus the comparison-MAC owner. Source-contract tests bound each capture-guard entrypoint and require zero core limits, singleton exact-key lookup, validation-before-retain/delete, and all three backend-owned creation-token fields.

This correction does not change the current exposure boundary: `lifecycle_operations=disabled` remains in force. It removes the stale-stack-copy blocker before any future lifecycle command can be reviewed for enablement.

Integrated verification passed 59 library tests plus 1 status-binary test, `rustfmt --check`, Clippy across all targets with warnings denied, the ad-hoc qualification build with signature and designated-requirement verification, the status/capability check, and `git diff --check`. The unchanged Node boundary had already passed 243 tests and the 39-file package dry run in this integration turn. Correctness, security, simplicity, tests, and concurrency reviews were clean after the corrections.

## Beta block 3: physical Secure Enclave and Touch ID matrix

**Blocked safely on 2026-08-23; no physical matrix result is claimed.** The host is a MacBook Air (Mac14,2) with Apple M2 running macOS 27.0 (build 26A5416b). `system_profiler` reports Apple Silicon, while `ioreg` reports a booted `AppleSEPManager` and an active `AppleBiometricSensor`/Apple Mesa driver. Those are hardware/driver observations only; neither command reveals enrollment nor authorizes a Secure Enclave private-key use.

**Policy correction (revised 2026-08-24):** this matrix no longer assumes a biometric prompt for every secret-bearing run. The required product matrix is: effectively unlocked exact named `--env` runs reopen the device-bound key without Touch ID; broad and effectively locked named runs require Touch ID; and invalid explicit selections fail without decryption or child launch. Existing current-set-biometry evidence applies only to operations whose policy requires Touch ID.

The fresh ad-hoc status artifact was built with the Xcode beta toolchain and ran from the Codex process with `hardware_presence_available=false`, `touch_id_available=false`, and `lifecycle_operations=disabled`. This does not contradict the user-run interactive status observation recorded above: availability is process/session scoped.

The user then authorized a separate feature-gated disposable prototype. It passed 62 Rust tests across the library and status binary, feature-aware warnings-denied Clippy, strict ad-hoc signature verification, required Security-framework import checks, and `git diff --check`. Running it from the user's Terminal session reached the permanent-key call but failed closed: `SecKeyCreateRandomKey` returned `errSecMissingEntitlement`. A diagnostic attempt to self-assert an application identifier and Keychain access group on the ad-hoc signature was killed by macOS before `main`; that invalid configuration was removed. `security find-identity -v -p codesigning` found zero valid identities on this host. The disposable directory remained empty. No key reference or receipt was returned, so there is no known test key to clean.

Independent review then found that the prototype was not safe to retain for later signing: its namespace could address the production key; its receipt did not cryptographically prove continuity with prepare; and a crash after permanent creation but before the receipt commit could orphan the key. The prototype source was removed. The status executable still accepts only `status`, and no physical matrix success is claimed.

Apple's current Security headers state that `kSecAccessControlBiometryCurrentSet` requires an enrolled biometric and invalidates an item when the enrolled biometric set changes. Apple Security regression code separately demonstrates permanent Secure Enclave P-256 creation, lookup, use, and deletion. These sources define the required observations; they do not substitute for them. Sources: [SecAccessControl header](https://github.com/apple-oss-distributions/security/blob/main/keychain/headers/SecAccessControl.h) and [Secure Enclave Keychain regression](https://github.com/apple-oss-distributions/security/blob/main/OSX/shared_regressions/si-44-seckey-aks.m).

### Commands and results

- `sw_vers`, `uname -m`, and `system_profiler SPHardwareDataType SPiBridgeDataType` — observed macOS 27.0 build 26A5416b on arm64 Apple M2. No T2 Mac or second Mac was available.
- `ioreg -l -w0 -r -c AppleBiometricSensor` and `ioreg -l -w0 -r -c AppleSEPManager` — observed the Apple biometric driver and `sep-booted=Yes`. This is physical-device capability evidence only, not a Touch ID or key-use result.
- `DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer CLANG_MODULE_CACHE_PATH=/private/tmp/keyclasp-block3-status-cache native/keyclasp-core/scripts/build-adhoc.sh /private/tmp/keyclasp-core-block3-status qualification` — passed strict ad-hoc signing, designated requirement, capability/status validation, and atomic staging. This is a compiled artifact check.
- `/private/tmp/keyclasp-core-block3-status status` — returned `hardware_presence_available=false`, `touch_id_available=false`, and `lifecycle_operations=disabled` in the Codex process. No Keychain item, Secure Enclave key, recovery envelope, vault key, plaintext, or child process was created.
- `npx ctx7@latest docs /apple-oss-distributions/security ...` — current Apple source confirms the current-set invalidation requirement and the permanent Secure Enclave creation/lookup/use/delete sequence. It is source documentation, not physical evidence.
- The feature-gated disposable prototype built and passed its local suite, then ran from interactive Terminal. It failed at `SecKeyCreateRandomKey` with `errSecMissingEntitlement`; no Touch ID prompt occurred and no receipt remained. The unsafe prototype was removed after independent review.
- `security find-identity -v -p codesigning` — reported zero valid code-signing identities. Apple Development signing with an accepted Keychain entitlement is the next local path to test; Developer ID remains the GA identity.

### Matrix status

| Required observation | Apple Silicon | T2 Mac | Second Mac |
| --- | --- | --- | --- |
| Device/driver capability | Observed only | Blocked: unavailable | Blocked: unavailable |
| Default named device-bound use without Touch ID | Blocked: supported persistence path and safe harness unavailable | Blocked | Not applicable |
| Broad and effectively locked Touch ID success, denial, and cancellation | Blocked before prompt | Blocked | Not applicable |
| Enrollment-set change, interruption/recovery, update identity | Blocked before enrollment | Blocked | Not applicable |
| Copied-vault failure | Blocked before enrollment | Not applicable | Blocked: second Mac unavailable |

### Learnings

- A visible SEP and biometric driver are prerequisites, not evidence of user authorization or a non-exportable key operation. Keep process-scoped status results separate from the interactive physical matrix.
- An ad-hoc signature can support the non-mutating status probe without being accepted for permanent Secure Enclave Keychain creation. The next local attempt should test Apple Development signing with an accepted Keychain entitlement; that path is not yet verified. Developer ID and notarization remain GA work.
- Self-issued Keychain entitlements do not turn an ad-hoc signature into a trusted identity. The operating system killed that experiment before `main`, so it must not become an installer workaround.
- A safe retryable harness needs a qualification-only namespace, a receipt authenticated by the Secure Enclave key, and durable pending state before permanent creation. Without all three, it can delete production state, accept forged continuity evidence, or orphan a key after interruption. Its behavioral checks must separate effectively unlocked named use from broad and effectively locked biometric use.
