---
title: "Hardware-only key custody"
type: security
status: settled
date: 2026-08-26
---

# Hardware-only key custody

## Desired outcome

On supported Macs and Linux systems, Keyclasp keeps no persistent software-wrapped vault data key. Non-exportable Secure Enclave or TPM objects protect short-lived symmetric data keys, and secret plaintext exists only inside a short-lived native core that launches the selected child process. The TypeScript process receives names, scope, command metadata, and a final status, but no data key or secret value.

"No software keys" does not mean that AES disappears. The Secure Enclave supports non-exportable 256-bit elliptic-curve private keys, not bulk SQLite encryption. Hardware mode therefore uses envelope encryption: a Secure Enclave key unwraps a random AES-256 data key in native memory; that data key encrypts vault records and is zeroized after the operation.

## Current facts

- Software mode currently stores two persistent AES-256 data keys in the v5 bundle: a machine-identity-wrapped machine key and a passphrase-wrapped interactive key. Record ciphertext is bound to its custody class and logical identity.
- The public TypeScript package no longer exports generic key, decrypt, plaintext-resolution, or child-launch functions, but software mode still performs those operations in Node.
- `src/hardware/status.ts` and `native/keyclasp-core/` expose only status. Hardware enrollment, unwrap, vault access, and child launch are deliberately disabled.
- The private native spike already establishes useful containment, rollback, recovery-envelope, ECIES, exact-key lookup, and code-identity machinery. It implements one biometric-bound key, not the required two hardware custody classes.
- The physical ad-hoc test reached permanent Secure Enclave creation and failed with `errSecMissingEntitlement`. Source and compiled tests do not establish a usable signing/persistence path.
- Apple currently documents Secure Enclave storage for generated P-256 private keys only; they cannot be imported and their private representation is non-exportable. `biometryCurrentSet` invalidates access when enrolled fingerprints change.

## Threat boundary

The target prevents a copied vault, backup, or disk from yielding secrets without the enrolled Secure Enclave or TPM. It also prevents Node/package callers from directly obtaining keys or plaintext.

It does not make a selected child incapable of copying a secret it legitimately receives, defeat an administrator controlling the enrolled host, or guarantee that transient plaintext never reaches framework-managed memory. Output redaction remains defense in depth, not an exfiltration boundary.

## Decisions

- Hardware custody is the default on supported macOS and Linux systems.
- Software mode may be selected only when creating a new vault. Hardware failure must never trigger automatic fallback, and a hardware vault cannot convert to software custody.
- Linux hardware custody uses TPM 2.0 rather than a machine-identity-derived wrapping key.
- Linux uses two TPM objects. Interactive custody requires a PIN/passphrase through `PolicyAuthValue`; machine custody remains unattended.
- Linux TPM objects bind to the TPM without binding to PCR measurements in the first release.
- Hardware vaults have no recovery material. Losing the Secure Enclave key, clearing or replacing the TPM, invalidating an interactive biometric key, or losing access after an incompatible identity change permanently destroys access to the affected records.

## Design tree

### 1. Product boundary

#### A. Hardware custody is the default on supported systems

Use Secure Enclave custody on supported Macs and TPM 2.0 custody on supported Linux systems. Keep portable passphrase mode as an explicit fallback for unsupported systems and deliberate portability. Hardware vaults contain no software-wrapped operational data key.

#### B. Keyclasp becomes macOS-only and hardware-only

Delete machine and portable operational modes. Unsupported hardware cannot use Keyclasp; recovery can restore only by enrolling replacement hardware. This produces the smallest claim but removes Linux and makes device loss/update failures much more consequential.

#### C. One vault silently falls back between hardware and software

Rejected. A fallback makes the protection level ambiguous and turns hardware failure into a downgrade path.

**Decision:** A, extended to Linux TPM custody. Software mode remains a separately selected fallback, never an automatic downgrade of a hardware vault.

### 2. Hardware envelope

#### A. One Secure Enclave key per vault

Simple, but Touch ID becomes either mandatory for every operation or merely a separate policy prompt. It cannot provide both unattended named runs and cryptographically biometric-bound records.

#### B. Two Secure Enclave keys per vault

Use one device-bound private key for machine-class data and a distinct `biometryCurrentSet` private key for interactive-class data. Each wraps an independent random AES-256 data key. The classes cannot decrypt one another. Custody transitions authenticate first, decrypt and re-encrypt affected rows, and atomically update policy and record class.

#### C. One Secure Enclave key per secret

Rejected for the first release. It multiplies Keychain state, lifecycle rollback, biometric prompts, migration work, and corruption cases without materially improving the stated trust boundary.

**Leading hypothesis:** B. It preserves Keyclasp's current machine/interactive semantics while replacing both persistent software wraps.

### 3. Secret-processing boundary

#### A. Node asks native code to unwrap a data key

Rejected. Node would still receive the key or plaintext, so the package and dependency surface remains inside the secret boundary.

#### B. A short-lived native core owns the transaction

Node sends a typed request containing scope, selected names, target environment names, command arguments, and output-protection preference. The core validates the request, locks the lifecycle, opens SQLite, evaluates policy, authenticates if required, unwraps only the required class keys, decrypts selected rows, launches the child without a shell, supervises it, zeroizes owned buffers, and returns only a classified status.

#### C. A persistent privileged broker owns secrets

Potentially stronger against same-user callers, but adds daemon installation, IPC authentication, upgrades, crash recovery, and a larger permanent attack surface. Defer unless the product promises caller identity stronger than explicit selection.

**Leading hypothesis:** B. It is the deepest boundary with the least new machinery.

### 4. Recovery

#### A. No recovery

Selected. Hardware loss, biometric enrollment changes, Keychain deletion, TPM clearing, or incompatible code-identity changes can permanently destroy secrets. Enrollment and destructive lifecycle commands must state this consequence and require explicit confirmation.

#### B. Passphrase recovery wraps the same operational data keys

A memory-hard passphrase-derived key wraps both AES data keys in an authenticated recovery envelope. This is a software recovery copy, so it conflicts with a literal claim that no software-wrapped key exists anywhere.

#### C. Recovery is a separate exported encrypted package

The live vault contains only hardware wraps. An explicit offline recovery artifact contains passphrase-wrapped recovery material and can be moved away from the machine. This makes the operational vault hardware-only while retaining recoverability, at the cost of backup UX and a second artifact users must protect.

**Decision:** A. Hardware vaults contain no recovery wrap or exported recovery package.

### 5. Linux TPM custody

#### A. TPM-bound machine class only

Seal the machine-class AES data key to a non-duplicable TPM object. This prevents a copied vault from opening on another machine, but it provides no interactive custody class comparable to Touch ID.

#### B. Two TPM objects, with an authorization value for the interactive class

Use one non-duplicable TPM object for unattended machine-class unseal and another whose policy requires `PolicyAuthValue` for interactive-class unseal. The user enters a Keyclasp PIN or passphrase for each interactive operation; the native core supplies it only within the TPM authorization session. TPM dictionary-attack protection limits repeated guesses when supported and correctly configured.

This retains the two-class model across macOS and Linux: the authentication mechanism differs, but the command-level contract, record classes, and transition semantics remain the same.

#### C. TPM machine custody plus a desktop biometric service

Use fingerprint authentication through PAM or a desktop service before unsealing a TPM object. Rejected as the cryptographic boundary unless the biometric result itself participates in TPM policy. A separate success signal can be spoofed by another same-user process or privileged software and recreates the current prompt-versus-key split.

#### D. TPM object gated by firmware biometrics

No portable PC-client TPM or UEFI contract exposes a firmware fingerprint match as a TPM enhanced-authorization assertion. `PolicyPhysicalPresence` is an optional firmware assertion used for TPM administration; it is not biometric verification and commonly requires a BIOS/UEFI ceremony. A vendor could build a private biometric authority that signs a `PolicyAuthorize` branch or changes a measured state, but Keyclasp could not depend on it across Linux systems, and the result would no longer be a TPM-only standard design.

Linux `fprintd` exposes fingerprint verification through D-Bus and PolicyKit. Its match result is software-visible and does not participate in `TPM2_Unseal`, so it can provide a convenience prompt but not the cryptographic interactive-custody boundary.

**Decision:** B. It keeps interactive authorization inside the TPM operation without introducing a distribution-specific biometric dependency.

### 6. TPM boot-state policy

#### A. Bind unseal to current PCR values

This can prevent unseal after changes to firmware, Secure Boot state, bootloader, kernel, or configuration, depending on the selected PCRs. With no recovery, an ordinary update or firmware reset can irreversibly strand the vault unless Keyclasp authorizes a new policy before reboot and every transition completes correctly.

#### B. Bind to the TPM but not PCR state

Create non-duplicable TPM objects under a stable primary hierarchy and restrict their use to `Unseal`; use an authorization value for the interactive class. A copied vault remains unusable on another TPM, while OS and firmware updates do not change the policy. This does not protect against an administrator already controlling the enrolled machine, which is outside the current threat boundary.

**Decision:** B for the first release. PCR binding adds update fragility that becomes data loss when recovery is intentionally absent.

### 7. Migration

Hardware mode cannot transform an existing Secure Enclave key from software key material because Apple does not allow key import. Migration must:

1. acquire exclusive lifecycle ownership and authenticate the operator;
2. verify the existing source credential and display the irreversible no-recovery consequence;
3. create two new permanent Secure Enclave key pairs or two new TPM objects in a qualification-safe namespace;
4. generate two new AES-256 data keys directly into native-owned zeroizable allocations;
5. create and authenticate both hardware wraps before touching live rows;
6. stream-decrypt each old record and re-encrypt it under the matching new class without passing plaintext through Node;
7. atomically activate new metadata and database generation with an interruption journal;
8. verify reopening through both hardware classes before deleting old software key material;
9. securely replace the old bundle where the filesystem permits, while stating that copy-on-write storage prevents a reliable promise that historical bytes were physically erased.

This is a one-way mode transition. A hardware vault cannot move to another machine and cannot be reopened through software mode. The only portable operation is an explicit plaintext export while the source hardware remains usable, followed by initialization of a different vault.

## Walking skeleton

1. Obtain a signing identity and entitlements that can physically create and reopen two permanent Secure Enclave keys on the target Mac. Separately prove creation and reopening of two non-duplicable TPM objects on each supported Linux family. Keep shipping executables status-only until these tests pass.
2. Build disposable, separately namespaced qualification commands with durable pre-creation state and authenticated receipts. On macOS, prove create, reopen, unwrap, exact deletion, interruption cleanup, biometric invalidation, same-identity rebuild, changed-identity update, and second-Mac copy failure. On Linux, prove the same lifecycle plus TPM clearing, wrong authorization value, dictionary-attack behavior, reboot, OS update, firmware update, and second-TPM copy failure.
3. Add a narrow versioned native request protocol. Its schemas must be structurally incapable of returning data keys or plaintext.
4. Implement only `init` and one exact-name `run` end to end inside the core. First prove a machine-class run without a prompt and an interactive-class run with Touch ID on macOS or `PolicyAuthValue` on Linux.
5. Add native-owned `set`, `get`, delete, rename, policy transitions, same-hardware backup, and migration after the walking skeleton passes.
6. Remove the software runtime from hardware-mode packaging and use import/package tests to keep `src/software/` unreachable from the hardware implementation.
7. Enable lifecycle operations only after physical Apple Silicon, T2, and TPM evidence; copied-vault evidence; destructive-loss and update/rollback drills; dependency review; and clean-artifact qualification pass.

## Security invariants

- No fallback from requested hardware mode to a software or Keychain-only key.
- No generic decrypt, unwrap, or plaintext-returning protocol operation.
- No data key or secret plaintext crosses into Node or protocol output.
- The core resolves authenticated record custody itself; Node cannot assert that authorization already happened.
- Mixed-class requests authenticate before unwrapping either class or decrypting any record.
- Empty or invalid explicit selections fail; they never widen to all secrets.
- Hardware metadata binds vault ID, key class, generation, application tag, label, public key, and code-identity expectations.
- Record AEAD binds vault ID, stable record ID, scope, name, kind, custody class, and format version.
- Enrollment, migration, policy transitions, and upgrades are journaled exclusive lifecycle operations.
- A child process is trusted with only explicitly selected secrets. No design claims containment after legitimate injection.

## Leading concept

Keyclasp uses hardware custody by default on supported macOS and Linux systems:

- macOS uses two non-exportable Secure Enclave P-256 private keys. The interactive key requires `biometryCurrentSet`; the machine key does not prompt.
- Linux uses two non-duplicable TPM 2.0 objects without PCR binding. The interactive object requires `PolicyAuthValue`; the machine object does not prompt.
- Each hardware object protects an independent AES-256 data key for its custody class. Data keys exist only in zeroizable native memory during an operation.
- One short-lived native core owns policy evaluation, hardware-key use, SQLite access, record encryption and decryption, and child launch. Node receives no key or plaintext.
- Software mode may be selected only for a newly created fallback vault. A hardware vault never downgrades or converts to software custody.
- Hardware vaults have no recovery path. Hardware loss or invalidation permanently destroys access.

No product decision remains on the current frontier. Implementation remains gated by the physical experiments below.

## Emerging principles

- Hardware custody is a vault property, not a best-effort runtime preference.
- No recovery means lifecycle failures are potential data-loss events, not repairable enrollment states.
- The smallest safe implementation is two hardware keys plus one short-lived native authority, not a daemon and not one key per record.
- Physical key persistence, identity continuity, and destructive-loss drills gate enablement; compilation cannot substitute for them.

## Remaining uncertainty

- Accepted pre-GA signing identity and exact entitlement profile for permanent macOS Secure Enclave keys.
- Hardware-key accessibility semantics needed for unattended macOS machine-class runs across login, lock, and reboot states.
- Exact supported TPM 2.0 stacks, distributions, device nodes, and provisioning ownership models.
- Exact identity behavior across same-version rebuilds, upgrades, Developer ID migration, and restored backups.
- Availability of a T2 Mac and second Mac for the required physical matrix.

## Next experiments

- Physically qualify Apple Development signing with the minimum Keychain/Secure Enclave entitlement set using a disposable namespace.
- Test two access-control profiles separately: device-bound non-biometric machine use and `biometryCurrentSet` plus private-key usage.
- Prototype two TPM sealed objects: unattended machine-class unseal and `PolicyAuthValue` interactive-class unseal, without PCR binding.
- Test TPM persistence across reboot, OS update, firmware update, owner changes, dictionary-attack lockout, clear, and second-machine copying.
- Capture authenticated receipts for create/reopen/unwrap/invalidation/update/copy tests without exposing key material.
- Prototype the typed `run` request and native child-launch transaction against an in-memory fake hardware backend before enabling real lifecycle commands.
