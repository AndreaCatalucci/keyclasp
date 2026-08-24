---
title: Touch-ID-gated hardware operations require current-set biometric invalidation
date: 2026-08-22
category: architecture-patterns
module: native keyclasp core
problem_type: dependency_constraint
component: security
severity: high
tags: [secure-enclave, touch-id, hardware-enclave, macos, beta]
---

# Touch-ID-gated hardware operations require current-set biometric invalidation

## Assumption

The macOS beta plan selected GoDaddy's `hardware-enclave` crate as the leading integration candidate. The original Slice 1 required the pinned revision to keep a Secure Enclave private key non-exportable, require Touch ID for every key release, reject weaker backends, and fail closed after biometric enrollment changes. The product policy later changed: effectively unlocked named `--env` runs use normal vault-mode behavior, while broad and effectively locked named runs require Touch ID.

## What the source audit showed

Revision `3b4ac1bcb637fb60ac18d4cd9877dba989c46dba` (`v0.2.10`) maps `AccessPolicy::BiometricOnly` to CryptoKit access control flag `.biometryAny` in `crates/hardware-enclave/swift/bridge.swift`. Apple's `.biometryAny` accepts any currently enrolled fingerprint. It does not invalidate the key when the enrolled fingerprint set changes. The beta checklist requires enrollment changes to fail closed.

The same revision has two code-identity concerns that the update spike must measure:

- `is_binary_signed()` treats any artifact accepted by `codesign --verify --no-strict` as signed, including an ad-hoc-signed beta artifact after it leaves Cargo's `target` directory.
- That function invokes `codesign` through `PATH`; a sibling entitlement check already uses `/usr/bin/codesign` and records the relative invocation as follow-up work.

Its public `create_encryptor()` factory also initializes storage: it creates a missing key and deletes and regenerates a key whose stored access policy differs. A copied-device, deleted-key, corrupted-handle, or policy-mismatch test cannot call that factory without risking mutation of the evidence under test.

These findings come from source inspection. They do not prove runtime behavior on a physical Mac.

## What the correction experiment showed

A bounded patch tested whether separate `create_new_encryptor()` and `open_existing_encryptor()` entry points could make the existing storage implementation strict. The focused fake-backend tests passed, but review showed that the new entry points still inherited hidden behavior from legacy helpers:

- `public_key()` can repair its disk cache and migrate the wrapping-key item, so calling it from open is not read-only;
- strict create can persist a key and return success when metadata-HMAC setup fails;
- strict open authenticates one metadata read and parses another, while the returned handle resumes legacy fail-open integrity checks;
- a directory lock cannot serialize a Keychain item shared by callers that use different `keys_dir` values; and
- inspecting an executable pathname with two `codesign` subprocesses does not establish the identity of the running code object.

The experiment did prove that a distinct `.biometryCurrentSet` bridge value and an ad-hoc-versus-Developer-ID result are mechanically possible. Those isolated changes do not make the dependency eligible for physical qualification because the lifecycle boundary remains mutable and race-prone.

## Lesson

Treat biometric policy and code identity as dependency acceptance criteria, not configuration details. Apply current-set biometry only to operations whose policy requires Touch ID; do not attach it to the device-binding path used by default named runs. Keyclasp can adopt a revision only after it:

- uses current-enrollment biometric invalidation for broad and effectively locked authorization or documents and approves a different recovery threat model;
- distinguishes ad-hoc beta identity from stable Developer ID identity without path-based heuristics;
- invokes identity tools through fixed system paths;
- provides an open-existing operation that never creates, repairs, deletes, or rekeys state; and
- passes the physical enrollment-change, rebuild, update, and two-Mac matrix.

A strict lifecycle must own the complete macOS transaction. It needs one canonical identity for Keychain operations, caches, authorization context, and interprocess locking; it must verify and parse the same metadata bytes; and it must retain strict verification for every operation on the returned handle. New public method names do not create a strict boundary when they delegate to helpers that repair, migrate, cache, or fail open.

Code identity must come from the running code object through Security.framework. Fixed-path `codesign` is safer than `PATH` lookup, but pathname inspection remains insufficient for an authorization decision.

The replacement feasibility slice selected a narrow Keyclasp-owned adapter. Its status probe has no upstream hardware-enclave dependency, constructs `.biometryCurrentSet`, applies the Developer ID Application requirement to `SecCodeCopySelf`, and uses kernel runtime signing flags for development and ad-hoc classification. A later private recovery slice added pinned RustCrypto Argon2id. The ad-hoc build verifies and runs a temporary candidate before atomically staging it. This removes the rejected dependency from the status boundary without claiming that key lifecycle work is complete.

The next lifecycle slice belongs at the owned macOS transaction boundary. It must establish the canonical Keychain identity and interprocess lock before adding create-new or open-existing. The non-mutating status probe remains executable evidence, while revision `3b4ac1b` and its bounded correction remain rejected.

## Scope

This lesson applies to Touch-ID-required operations in macOS hardware mode and to release identity. It does not require Touch ID for default exact named `--env` runs. Portable passphrase mode and the existing TypeScript vault remain unchanged.
