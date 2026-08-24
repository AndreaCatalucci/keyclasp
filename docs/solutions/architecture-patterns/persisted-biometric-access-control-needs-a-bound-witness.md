---
title: Persisted biometric access control needs a bound policy witness
date: 2026-08-22
category: architecture-patterns
module: native keyclasp core
problem_type: platform_constraint
component: security
severity: high
tags: [secure-enclave, keychain, biometry, access-control, macos]
---

# Persisted biometric access control needs a bound policy witness

## Assumption

The first Security.framework backend compared a stored `SecAccessControlRef` with a fresh object created from the required `.biometryCurrentSet` flags. The comparison looked like a direct way to reject weaker persisted policy.

## What the platform implementation showed

Security.framework binds biometric constraints when it persists an item. Apple's `SecItem` implementation marks the evaluated access control as bound, and `SecAccessControl` equality compares the complete internal dictionaries. A fresh template contains placeholder biometric values and no bound marker, so it is not an equality witness for the persisted object it created.

The public macOS header exposes access-control creation and type identity, but not the private constraint inspection and binding functions shown in Apple's open-source implementation. Parsing a description or importing private Security functions would make the boundary brittle.

## Lesson

Do not compare a freshly created biometric access-control template with a persisted access-control object.

Creation may prove which flags it supplied, inspect that the stored item has an access-control object and the required accessibility class, and keep the backend unreachable while physical qualification is pending. Open-existing must not claim exact current-set validation until it has a supported persisted policy witness or a reviewed behavioral proof. The witness must survive process restart and be authenticated with the key identity; an in-memory object or a second unauthenticated marker is insufficient.

## Scope

This blocks runtime exposure of the hidden create/open backend that was designed for biometric key release. It does not weaken `.biometryCurrentSet | .privateKeyUsage` for broad or effectively locked authorization, require that policy for effectively unlocked named `--env` runs, or authorize private Security.framework APIs.

Useful pointers:

- `native/keyclasp-core/c/security_backend.c`
- `docs/security/2026-08-22-hardware-enclave-spike-evidence.md`
- Apple's `OSX/sec/Security/SecAccessControl.m`
- Apple's `OSX/sec/Security/SecItem.m`
