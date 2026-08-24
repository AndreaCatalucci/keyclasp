---
title: "release: macOS hardware-backed beta to general availability"
type: security
status: supporting
date: 2026-08-22
---

# release: macOS hardware-backed beta to general availability

> **Release-ordering note (revised 2026-08-24):** [`2026-08-23-001-software-beta-and-optional-hardware-mode-plan.md`](./2026-08-23-001-software-beta-and-optional-hardware-mode-plan.md) is the canonical delivery map. Its optional hardware work is **Slice 5**, which starts only after Slice 4 and an explicit user decision. The first public beta is software-only; this document supplies the internal hardware work blocks, evidence requirements, and beta-to-GA path for Slice 5.

## Desired outcome

Keyclasp first aims to ship a local, offline macOS hardware mode that users can try without an Apple Developer Program subscription. The accepted pre-GA signing and persistence path is unresolved: the tested ad-hoc artifact could run the status probe but could not create the permanent Secure Enclave item. General availability later uses the same vault and native boundary with a Developer ID signature and Apple notarization, distributed directly rather than through the Mac App Store.

**Trajectory correction (2026-08-23):** The tested macOS 27 host rejected permanent Secure Enclave creation from the ad-hoc artifact with `errSecMissingEntitlement`. Ad-hoc signing is proven only for the status probe. The subscription-free beta outcome and its signing decision must be revised or physically proven through a different supported path before hardware block 2.

**Custody correction (revised 2026-08-24):** Hardware mode must preserve the software beta's dual-key invariant, not implement one hardware vault key plus a prompt policy. Machine-only named `--env` runs use a device-bound hardware machine key without Touch ID. Interactive records use a distinct hardware key whose private-key use is cryptographically bound to `biometryCurrentSet`. Broad requests and any selected set containing an interactive record require Touch ID before any unwrap, decryption, or child launch. The existing private backend binds every unwrap to `.biometryCurrentSet`, so it cannot implement this two-class design and remains evidence only.

Both stages provide the same cryptographic boundary:

- two independent Secure Enclave keys bind the vault's machine and interactive custody classes to the Mac that enrolled them;
- explicit named `--env` runs containing only machine-class records are non-interactive;
- broad requests and any selection containing an interactive-class record require Touch ID before any secret is decrypted;
- possession of the hardware machine key and its metadata cannot decrypt an interactive record;
- `lock`, `unlock`, and `inherit` always require Touch ID and atomically migrate affected records between hardware custody classes;
- a short-lived native core owns vault opening, decryption, and child launch;
- the TypeScript CLI receives neither the vault data key nor secret plaintext;
- copying the vault and its adjacent files to another Mac does not enable decryption without the recovery passphrase;
- recovery passphrase protection covers both custody classes and supports deliberate migration and device-loss recovery.

The beta makes only the distribution claims supported by the selected pre-GA identity. Every beta must include project-published checksums and build provenance. If qualification eventually accepts ad-hoc signing, macOS cannot identify Keyclasp as a registered publisher. General availability adds Developer ID publisher identity, notarization, stable release signing, and clean Gatekeeper acceptance.

This map implements the first macOS hardware-backed scoped-run release described in [`docs/concepts/2026-08-21-simpler-secure-onboarding.md`](../concepts/2026-08-21-simpler-secure-onboarding.md). It supersedes the broker and stored-capability requirement in [`docs/plans/2026-08-21-001-brokered-hardware-backed-security-plan.md`](./2026-08-21-001-brokered-hardware-backed-security-plan.md). A broker remains future work only if Keyclasp later promises stronger resistance to a malicious same-user caller than explicit secret selection provides.

Release readiness is governed by [`docs/security-hardening-checklist.md`](../security-hardening-checklist.md). The beta may defer Developer ID and notarization only after another accepted signing path proves the selected device-binding persistence design. Every beta-marked cryptographic, authorization, storage, recovery, process, dependency, and verification control remains mandatory.

## Relevant current codebase

- [`src/vault.ts`](../../src/vault.ts) owns the SQLite vault, software-wrapped data key, row encryption, and plaintext resolution inside Node.
- [`src/biometric.ts`](../../src/biometric.ts) performs Touch ID as a separate authorization check.
- [`src/run.ts`](../../src/run.ts) resolves plaintext in Node and launches the trusted child.
- [`src/cli.ts`](../../src/cli.ts) routes `get` and `run` through those independent paths.
- [`src/index.ts`](../../src/index.ts) now exports only reviewed metadata, validation, and read-only context helpers; package exports block deep imports of vault internals.
- [`native/macos-biometric.js`](../../native/macos-biometric.js) proves the current Touch ID prompt but does not control hardware-key release.
- [`native/keyclasp-core/`](../../native/keyclasp-core/) now contains a status-only executable backed by a Keyclasp-owned Rust, Swift, and C adapter. It reports process-scoped Secure Enclave availability, constructs `.biometryCurrentSet` access control, classifies development, ad-hoc, and Developer ID code, and contains an internal strict lifecycle contract with one canonical application tag and interprocess lock. Recovery uses pinned RustCrypto Argon2id; the rejected `hardware-enclave` crate is absent. A hidden Security.framework backend implements strict create-new and read-only open-existing operations, but the command line cannot reach either operation.
- [`package.json`](../../package.json) still publishes one platform-neutral Node package and excludes the status-only native spike until the hardware release gates pass.
- [`.github/workflows/macos-release.yml`](../../.github/workflows/macos-release.yml) can build qualification, beta-candidate, and GA-candidate artifacts, but release evidence and native-capability gates currently block beta and GA. It does not publish a public release.

Useful seams to preserve are the explicit project/environment/secret selection, AES-256-GCM vault encryption, shell-free child launch, and trusted-child contract.

## Gap

Keyclasp needs one native authority that combines user presence, two independent Secure Enclave custody classes, vault decryption, and child launch. It also needs two explicit macOS distribution states:

1. a beta that remains cryptographically hardware-backed under a physically qualified pre-GA code identity and documents the exact platform approval that identity requires; and
2. a general-availability artifact whose Developer ID signature and notarization pass Gatekeeper without that override.

The vault format and native protocol must remain identical across those states. Buying Developer ID must change the release pipeline and code identity, not require another security architecture or destructive vault migration.

## Resolved decisions

- Ship macOS hardware mode before Windows and Linux hardware modes.
- Use one short-lived Rust `keyclasp-core` with a reviewed Keyclasp-owned macOS adapter. Revision `3b4ac1b` and its bounded correction remain rejected and absent. The next design must own two independent Secure Enclave keys: one device-bound machine key and one interactive key with `biometryCurrentSet`. Do not add a daemon for the first release.
- Reuse the shared `lock`, `unlock`, and `inherit` selectors and precedence rules, but keep hardware key custody, record encryption, and plaintext handling independent of `src/software/` and `src/vault.ts`.
- Keep machine-only named `run --env ...` non-interactive. Treat the exact secret list as scoping, not as caller authentication, and never widen an empty or invalid list to broad injection.
- Require Touch ID for broad `run`, human `get`, sensitive administrative operations, `lock`, `unlock`, `inherit`, and every request selecting at least one interactive record. Complete authorization before unwrapping either selected class, decrypting any selected record, or launching a child.
- Make custody transitions authenticated and atomic: update the policy rule, re-encrypt all affected existing records under the resulting hardware class, and set the class for future matching records as one exclusive lifecycle operation.
- Keep stored capabilities and unattended policy machinery out of this release. Existing portable mode remains separately named and must not be advertised as hardware-bound.
- Re-decide beta signing before hardware block 2. The ad-hoc artifact can run the status probe but failed permanent Secure Enclave enrollment on the tested host.
- Publish beta checksums and build provenance. Treat them as channel-integrity evidence, not as a substitute for registered publisher identity.
- Require recovery-passphrase verification before replacing a beta artifact whose changed code identity requires Secure Enclave re-enrollment.
- Revisit Apple Developer Program timing after testing Apple Development signing with the required Keychain entitlement.
- Distribute general availability directly through Keyclasp's existing channels. Do not submit Keyclasp to the Mac App Store.
- Gate only the macOS artifact on Apple notarization. Future Windows and Linux artifacts may publish independently.

Apple's supported distribution references are [Open Anyway](https://support.apple.com/guide/mac-help/open-an-app-by-overriding-security-settings-mh40617/mac), [Developer ID distribution outside the Mac App Store](https://developer.apple.com/support/developer-id/), and the scriptable [`notarytool` workflow](https://developer.apple.com/documentation/security/customizing-the-notarization-workflow).

## Walking skeleton

Prove one complete macOS path before porting the rest of the CLI:

1. A legitimately signed `keyclasp-core` creates independent Secure Enclave machine and interactive keys and uses them to protect distinct disposable data keys; the accepted pre-GA signing identity is still unresolved.
2. `keyclasp run --project test --environment local --env TEST_SECRET -- node -e 'process.exit(process.env.TEST_SECRET ? 0 : 1)'` sends only a typed exact-secret request to the core and runs without Touch ID when every selected record is machine-class.
3. The same core rejects an invalid or empty explicit selection and requires Touch ID before a broad request or any selection containing an interactive record. A mixed request decrypts nothing and launches no child before approval.
4. `lock`, `unlock`, and `inherit` require Touch ID and atomically migrate affected records between the hardware custody classes. The hardware machine key cannot decrypt an interactive record.
5. After the applicable policy passes, the core decrypts only the selected values, launches the child, and clears its secret buffers after exit.
6. The Node parent can neither obtain either data key nor request a generic decrypt operation.
7. The same request fails after the vault files are copied to a second physical Mac.
8. Recovery restores both custody classes and re-enrolls replacement hardware without silently downgrading an interactive record.
9. A freshly downloaded beta artifact follows the clean-Mac approval path established for its selected pre-GA identity and never requires `sudo`, global Gatekeeper changes, or quarantine removal. If the accepted path is ad-hoc, that approval is **Open Anyway**.
10. Replacing the beta artifact exercises recovery-passphrase re-enrollment without losing the vault.

This skeleton is disposable spike code until the dependency audit, physical-device tests, and authorization-path review pass.

## Vertical delivery slices

### Hardware block 1: Prove the hardware and update boundary

**Integration review correction (2026-08-23):** An independent review found that by-value Rust arrays could leave abandoned stack copies of recovery roots, vault data keys, derived wrapping keys, and comparison MACs. These secrets now live in stable heap-backed owners, and generation, decryption, and HMAC derivation write directly into the final allocation. Moving an owner moves only its pointer; dropping it clears the one secret allocation. Exact Keychain lookup and validation are shared by open and rollback, and rollback consumes only its backend-owned creation token. Integrated verification passed 59 library tests plus 1 status-binary test, formatting, warnings-denied Clippy, and the ad-hoc build/signature/capability checks. The executable remains status-only.

**Implementation status (2026-08-23):** Beta blocks 1 and 2 are complete locally. The private Keyclasp-owned adapter takes recovery passphrases as a moved native `RecoveryPassphrase` buffer and zeroizes it on drop; all long-lived recovery roots and disposable vault-data-key buffers remain native-owned and zeroized. Every hidden create/open path first installs and verifies a process-wide zero `RLIMIT_CORE`; this is a necessary core-file containment control, not a claim that it controls administrator-configured crash collectors. Apple documents `SecKeyCreateDecryptedData` as returning a framework-owned `CFData` that callers release, not as a wipeable buffer. The bridge limits that opaque copy to one C function and one immediate copy into Rust-owned zeroizable storage, then releases it. No const-cast or unsupported attempt to clear the `CFData` is used. The private qualification operation creates an in-memory fixed P-256 test key through `SecKeyCreateWithData`, runs the exact variable-IV ECIES round trip, rejects a tampered ciphertext, and returns only status. It does not use Keychain or Secure Enclave state and is unreachable from the command line. If post-backend Rust validation or metadata activation fails before metadata replacement, the transaction uses the platform backend’s retained canonical tag, label, and public key to reopen and delete only the exact created key; deletion failure becomes `CleanupFailed`. If rename succeeded but the directory sync fails, active metadata may have committed, so the transaction retains the hardware key and returns a distinct indeterminate activation error for recovery. The executable remains status-only and cannot unwrap through a public command. This block passed 57 native Rust tests, warnings-denied Clippy, and a compiled ad-hoc signature/capability check. It is source/compiled evidence only: no physical Secure Enclave unwrap, crash-reporter configuration, Touch ID, or T2 result is claimed. The [evidence record](../security/2026-08-22-hardware-enclave-spike-evidence.md) contains commands and limitations.

**Blocked-slice implementation status (2026-08-22):** Safe prerequisites for hardware blocks 2–4 are implemented without enabling hardware mode. The published TypeScript boundary no longer exports raw keys, plaintext resolution, vault mutation, authentication state, or child execution. Whole-scope injection authenticates inside the runner and no longer accepts caller-asserted authentication. A versioned, status-only broker client and `keyclasp doctor` classify unavailable hardware, missing Touch ID, Gatekeeper execution denial, and protocol mismatch; the protocol defines fail-closed damaged-enrollment and recovery-required identity states, but the current status-only core reports enrollment unavailable rather than claiming to inspect nonexistent enrollment metadata. Release tooling uses immutable action pins, protected beta/GA environments, evidence gates, exact tagged clean source, checksums, SPDX metadata, provenance candidates, an ephemeral GA keychain, Developer ID hardened-runtime signing, notarization, stapling, and Gatekeeper assessment. The provisional direct-archive beta and DMG GA paths cannot package a release until the checked-in evidence gates pass and the native core reports `lifecycle_operations=enabled`. No hardware block 2, 3, or 4 acceptance criterion is marked complete: recovery, physical testing, clean-Mac testing, beta evidence, independent review, Apple credentials, notarization, migration, and public release remain external or blocked work.

**Remaining-work snapshot (2026-08-23):** Beta block 3 is blocked, not complete. A feature-gated disposable prototype built, passed local checks, and ran from the user's interactive Terminal session on the Apple Silicon M2 host. macOS reached permanent Secure Enclave creation and rejected `SecKeyCreateRandomKey` with `errSecMissingEntitlement`. A self-entitled ad-hoc experiment was killed before `main` and was removed. The host has no valid code-signing identity.

Independent review found three design gaps: the prototype needed a separate qualification namespace, authenticated receipts, and durable pre-creation state. Without them, the harness could delete a production key, accept false continuity evidence, or orphan a key after interruption. The unsafe prototype was not retained; the normal artifact remains status-only. The next attempt should test Apple Development signing with an accepted Keychain entitlement, but that path is not yet verified. The new harness must also fix all three design gaps before physical use. No key reference or receipt was returned, so there is no known test key to clean. A T2 Mac and second physical Mac are still unavailable.

After those blockers, collect machine-only named-run success without Touch ID; broad, interactive, and mixed-class Touch ID success, denial, and cancellation; machine-to-interactive wrong-key failure; lock/unlock/inherit transitions; enrollment change; recovery of both classes; interruption; update identity; and copied-vault evidence. Hardware block 2 cannot start before that matrix completes. After genuine beta acceptance, hardware block 3 stabilizes representative workflows, fuzz/property/concurrency/permission/process/update evidence, and independent review; hardware block 4 completes Developer ID/notarized GA and recovery-safe migration.

**Outcome status:** unmet. The private adapter and recovery contract compile, but the tested ad-hoc identity cannot create the permanent Secure Enclave key.

**Implementation areas:**

- Keep the executable under `native/keyclasp-core/` status-only and the lifecycle modules private. The Argon2id passphrase recovery envelope, authenticated pending-to-active store, and dual wrapping for one disposable vault data key are historical evidence, not the Slice 5 two-key design. Do not expose that current biometric-bound unwrap. Qualify independent device-bound machine and `biometryCurrentSet` interactive keys.
- Keep the native dependency graph narrow. RustCrypto Argon2id replaces a bespoke memory-hard KDF, uses only its zeroization feature, and is pinned in `Cargo.lock`; inventory the Rust, Swift, C, FFI, transitive dependency, build-script, and platform boundaries before key enrollment.
- Reject software or Keychain-only fallback when macOS hardware mode is requested.
- Test Apple Silicon and one T2 Mac when hardware is available; report unsupported hardware as portable-mode-only.
- Measure machine-only named-run behavior; broad, interactive, and mixed-class Touch ID denial and cancellation; lock/unlock/inherit; machine-to-interactive wrong-key failure; enrollment change; missing biometry; key deletion; corrupted handles; and device-copy behavior.
- Compare the selected pre-GA artifact, a same-identity rebuild, and an updated artifact to establish when code identity changes force re-enrollment.
- Prove recovery before deleting or invalidating any enrolled test key.

**Acceptance:** two-Mac copying fails; machine-only named requests run without Touch ID; Touch ID denial blocks broad, interactive, mixed-class, and custody-transition requests before any decryption; the machine key cannot decrypt an interactive record; neither private hardware key is exportable; fallback fails closed; recovery restores both classes and enrolls replacement hardware; update behavior is documented from observed results.

### Hardware block 2: Ship the supported pre-GA hardware-backed scoped-run beta

**Outcome:** a technical user can install Keyclasp, complete the platform approval required by the selected pre-GA identity, enroll hardware mode, and run a named secret without exposing it to Node.

**Implementation areas:**

- The shared `lock`, `unlock`, and `inherit` policy model is resolved. This hardware block remains blocked until the selected pre-GA signing and two-key persistence path passes physical hardware qualification.
- Replace the spike with one short-lived core that owns the live SQLite connection, key unwrap, row decryption, authorization, and child lifecycle.
- Extend the shared command-level contracts in `src/runtime.ts` only when hardware mode needs another operation. Keep passphrase and machine implementations under `src/software/`, hardware client code under `src/hardware/`, and native custody under `native/keyclasp-core/`. The CLI selects an implementation and contains no operation-specific hardware branches.
- Add a narrow, versioned hardware protocol under `src/hardware/`; pass names and command metadata only. Shared contracts and protocol responses cannot carry a data key or secret plaintext.
- Route hardware-mode `init`, `set`, `get`, `delete`, `rename`, rekey, recovery, `lock`, `unlock`, `inherit`, and every secret-bearing `run` through the core. The core, not Node, resolves each selected record's authenticated custody class.
- Implement one device-bound machine key and one `biometryCurrentSet` interactive key. The default remains non-interactive only for exact named selections containing machine-class records. Any interactive record makes the complete request Touch-ID-gated.
- Reuse the software mode's selectors, rule precedence, future-record behavior, and transition semantics through shared command contracts. Keep the two hardware keys, recovery wraps, record encryption, and plaintext path entirely hardware-owned.
- Let the core read new secret values and recovery passphrases directly from inherited terminal or pipe descriptors; Node must not relay either plaintext value.
- Remove raw key and plaintext functions from the published package boundary before enabling hardware mode.
- Build the physically qualified pre-GA artifact in public CI from the tagged source, verify its accepted code identity and capabilities, generate SHA-256 checksums and provenance, and attach them to the beta release. Use ad-hoc signing only if a later physical test proves the selected persistence path supports it.
- Select the least surprising beta install channel with one packaging spike: bundled npm artifact, Homebrew formula, or direct archive. Choose the first path that preserves the exact reviewed binary and makes the Gatekeeper flow reproducible.
- Add `keyclasp doctor` output that distinguishes unsupported hardware, Gatekeeper blocking, missing Touch ID, damaged enrollment, and recovery-required update.
- Document only the Apple-supported approval workflow for the selected pre-GA identity. If the accepted path is ad-hoc, use **System Settings → Privacy & Security → Open Anyway** and state that managed Macs may prohibit it.

**Acceptance:** a clean test Mac completes install, the platform approval appropriate to the selected pre-GA identity, dual-key enrollment, `set`, `get`, recovery of both classes, a machine-only named run without Touch ID, Touch-ID-approved broad, interactive, and mixed-class runs, and Touch-ID-approved lock/unlock/inherit transitions; the machine key cannot decrypt an interactive record; Node memory and IPC contain no data key or plaintext; a modified core, protocol mismatch, unavailable hardware, or denied required Touch ID fails before decryption or child launch; beta documentation states the exact publisher and notarization status.

**Architecture acceptance:** contract tests run against every enabled implementation. Import-boundary tests prove that `src/software/` and `src/hardware/` do not import one another, and the hardware implementation cannot import software key or plaintext helpers.

### Hardware block 3: Stabilize the security boundary with beta evidence

**Outcome:** general-availability signing is applied to a proven native boundary rather than masking unresolved security or lifecycle behavior.

**Implementation areas:**

- Run the beta across representative agent workflows and verify that machine-only named runs do not prompt. Measure broad, interactive, and mixed-class Touch ID frequency, lock/unlock/inherit behavior, cancellation, terminal behavior, child cleanup, and upgrade recovery.
- Complete the native dependency audit, fuzz the request parser, property-test key/vault state transitions, and test concurrent init, run, rekey, and recovery attempts.
- Verify owner-only permissions for the vault, native metadata, temporary files, backups, and SQLite sidecars.
- Keep the child environment minimal, supervise the process group, and retain output scanning as defense in depth.
- Commission an independent review of the native boundary, key lifetime, fallback behavior, packaging, and recovery flow; resolve every critical or high-severity finding before general availability.
- Freeze the native protocol and vault-wrap version only after update and rollback drills succeed.

**Acceptance:** beta telemetry remains absent; test reports contain metadata only; recovery and rollback drills lose no vault; changed or interrupted updates fail recoverably; no unresolved critical or high-severity security finding remains.

### Hardware block 4: Add Developer ID and notarized general availability

**Outcome:** users install the same hardware-backed design without an unidentified-developer override or Mac App Store submission.

**Implementation areas:**

- Enroll in the Apple Developer Program and create a Developer ID Application identity for the Keyclasp release owner.
- Add a protected macOS release environment in CI. Import signing material into an ephemeral keychain, restrict release-secret access, and erase the keychain after signing.
- Sign every nested executable from the inside out with hardened runtime, a secure timestamp, stable identifiers, and the minimum entitlements established by the hardware spike.
- Verify the signature and designated requirement before packaging.
- Submit the release archive with `notarytool`, require an accepted result, staple the ticket to the distributable artifact, and verify Gatekeeper with `spctl` on a clean Mac.
- Publish the signed and notarized artifact, checksum, SBOM, provenance, tag, and source commit as one immutable release set.
- Keep notarization outside the Mac App Store and isolate its wait from other platform artifacts.
- Migrate beta users by verifying their recovery passphrase, enrolling the Developer ID-signed code identity, and preserving their existing encrypted vault.

**Acceptance:** a clean Mac reports the artifact as accepted from Notarized Developer ID and launches without **Open Anyway**; altered artifacts fail signature or checksum verification; a notarization failure publishes no macOS artifact; beta-to-GA migration preserves the vault and invalidates obsolete beta enrollment only after the new enrollment succeeds.

## Technical bets and bounded spikes

1. **Owned-adapter physical proof, two days.** Confirm creation and persistence of both Secure Enclave keys, non-interactive machine-key unwrap, cryptographically biometric interactive-key unwrap, machine-to-interactive wrong-key failure, mixed-class pre-decryption authorization, lock/unlock/inherit transitions, fail-closed fallback, key deletion, enrollment change, recovery of both classes, and two-device copying before exposing the Keyclasp-owned adapter.
2. **Ad-hoc identity upgrade, one day.** Determine exactly how macOS treats the hardware handle and access control across identical artifacts, rebuilds, and Developer ID migration. The recovery design must cover the observed behavior.
3. **Beta packaging, one day.** Compare npm, Homebrew, and direct archives on clean Macs. Select one path using install steps, exact-binary preservation, Gatekeeper behavior, update behavior, and uninstall completeness.
4. **Release automation, one day after enrollment.** Sign, notarize, staple, verify, and install a disposable artifact through the future CI path before applying it to a real Keyclasp release.

Each spike ends with a recorded accept/reject decision and executable evidence. Failed spikes change the plan before production code depends on them.

## Deferred decisions

- The exact beta packaging channel, until the one-day clean-Mac comparison produces evidence.
- Windows Hello/TPM and Linux TPM2 hardware modes.
- Broker-stored capabilities that constrain malicious same-user callers, a persistent broker, repository manifests, and execution sandboxes. Default explicit `--env` runs remain non-interactive without that machinery.
- Vault-format v4 metadata confidentiality, whole-vault manifests, and external rollback anchors from the broader security plan.
- Store distribution, enterprise deployment, and automatic updating. Direct Developer ID distribution is the general-availability path.

## Done criteria

- Hardware mode uses distinct non-exportable Secure Enclave machine and interactive keys and fails closed on unsupported Macs or unavailable hardware.
- Machine-only named `--env` runs are non-interactive. Broad runs, `get`, sensitive administrative operations, lock/unlock/inherit, and any selected set containing an interactive record require Touch ID before either class is unwrapped or any record is decrypted.
- The machine key and all machine-key metadata cannot decrypt an interactive record. Custody transitions atomically preserve the authenticated key class for existing and future matching records.
- The native core exclusively owns the live vault data key, plaintext resolution, and child launch; the TypeScript package exposes no generic key or decrypt operation.
- Copied vault material fails on a second physical Mac.
- Recovery of both custody classes is verified before key replacement and safely enrolls a replacement Mac or release identity without downgrading interactive records.
- The beta installs through the physically qualified pre-GA signing path without disabling Gatekeeper, clearing quarantine globally, or claiming an Apple identity the artifact does not have. The account-free goal remains blocked until such a path passes.
- Every beta artifact has a tagged source commit, checksum, public build provenance, and an explicit statement of its publisher and notarization status.
- The general-availability artifact is Developer ID signed, hardened-runtime enabled, notarized, stapled, and accepted by Gatekeeper on a clean Mac.
- General availability uses direct distribution rather than the Mac App Store, and Apple notarization gates only the macOS artifact.
- The beta-to-GA transition preserves existing vaults and fails recoverably at every interruption point.
- Tests, documentation, and product claims distinguish hardware mode, portable passphrase mode, beta distribution trust, and notarized general availability.
