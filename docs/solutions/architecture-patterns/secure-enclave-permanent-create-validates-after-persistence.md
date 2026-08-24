---
title: Secure Enclave permanent creation requires exact post-create rollback
date: 2026-08-22
category: architecture-patterns
module: native keyclasp core
problem_type: platform_constraint
component: security
severity: high
tags: [secure-enclave, keychain, rollback, macos, security-framework]
---

# Secure Enclave permanent creation requires exact post-create rollback

## Assumption

The first owned lifecycle contract required a backend to validate the complete hardware-key record before committing persistent state. That ordering would make invalid output fail without leaving a Keychain item.

## What the platform API showed

Apple's supported flow creates a permanent Secure Enclave key by passing `kSecAttrIsPermanent` in `kSecPrivateKeyAttrs` to `SecKeyCreateRandomKey`. Creation and Keychain persistence happen in that call. The caller can copy the public key and inspect the returned key only after the permanent key exists.

A non-permanent Secure Enclave key followed by a separate `SecItemAdd` would invent an unproven two-step persistence flow. The logical application tag also cannot be assumed to be the Keychain row's uniqueness field: Apple's Security sources describe the application label as the public-key hash and expose the application tag as a separate attribute.

## Lesson

Model permanent Secure Enclave creation as one atomic platform commit followed immediately by validation inside the same locked backend operation:

1. under the logical-identity lock, query the exact application tag and reject any existing match;
2. create one permanent key with the canonical application tag, Secure Enclave token, P-256 type, and current-set biometric access control;
3. inspect the returned key and its Keychain attributes, then prove the tag has exactly one match;
4. pass the validated public record through the Rust lifecycle validator before returning success;
5. if any post-create validation fails, delete the exact returned key through `kSecMatchItemList`; and
6. return a distinct cleanup failure when exact deletion fails.

The backend must never delete by a broad label or prefix. The interprocess lock remains held from preflight through validation and rollback. The post-create singleton check detects an external race rather than trusting application-tag uniqueness. A process crash after `SecKeyCreateRandomKey` can leave a complete key, so retry must report duplicate and open-existing must validate that key without repair. Recovery remains required before the CLI exposes enrollment or deletion.

The same rollback boundary continues until activation is known not to have committed. In the owned adapter, `HardwareKeyBackend::create_new` can return a created, validated, and wrapped key before Rust writes active vault-key metadata. The platform backend must retain a trusted creation token containing the canonical tag, label, and public key. If later Rust validation fails, or activation fails before the atomic rename, the transaction must delete that exact created key through the trusted token while it still holds the lock, or return `CleanupFailed`. C-level rollback alone does not cover failures after the FFI call returns.

An atomic rename changes that rule. A failed directory `fsync` after rename leaves the active metadata visible and potentially durable. Treat that state as `ActivationIndeterminate`: retain the exact hardware key and return a distinct recovery-required error. Deleting it could strand authenticated active metadata that still names the deleted key. Failure injection must cover both the pre-rename rollback path and the post-rename indeterminate path.

## Physical signing lesson

The beta plan assumed that an ad-hoc signature plus interactive Gatekeeper approval could defer publisher identity while still creating a permanent Secure Enclave Keychain item. A feature-gated disposable prototype tested that assumption from the user's Terminal session on macOS 27. It reached `SecKeyCreateRandomKey`, then failed closed with `errSecMissingEntitlement`. Embedding a self-issued application identifier and Keychain access group did not create a valid identity; macOS killed that prototype before `main`. The host had no valid code-signing identity installed.

Ad-hoc signing remains sufficient for the non-mutating status probe, but this platform configuration does not accept it for permanent Secure Enclave enrollment. The next qualification attempt should use Apple Development signing with an accepted Keychain entitlement; that path is not yet verified. Developer ID remains the separate GA distribution identity. Self-asserted entitlements on an ad-hoc signature are not a substitute.

This result applies to permanent Keychain-backed Secure Enclave creation on the tested macOS 27 build. It does not prove identical behavior on every older macOS release, and it does not affect in-memory cryptographic operations or the read-only capability probe.

## Scope

This applies to permanent Secure Enclave key creation through Security.framework. It does not select Keyclasp's run-authorization policy: effectively unlocked named `--env` runs use normal vault-mode behavior, while broad and effectively locked named runs require Touch ID. It does not authorize a public create command, prove behavior on physical hardware, or replace the recovery and two-Mac acceptance matrix.

Useful pointers:

- `native/keyclasp-core/c/security_backend.c`
- `native/keyclasp-core/src/transaction.rs`
- `docs/plans/2026-08-22-001-macos-hardware-beta-to-ga-plan.md`
- `docs/security/2026-08-22-hardware-enclave-spike-evidence.md`
- Apple's `OSX/shared_regressions/si-44-seckey-aks.m`
- Apple's `OSX/libsecurity_keychain/lib/SecItem.cpp`
