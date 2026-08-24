# Keyclasp-owned macOS adapter spike

This crate is disposable Slice 1 evidence. It is not part of the published Keyclasp package and cannot open a vault or handle secrets.

The spike replaces the rejected `hardware-enclave` dependency with a Keyclasp-owned Rust, Swift, and C adapter. Its non-mutating `status` operation reports `SecureEnclave.isAvailable`, proves that `.biometryCurrentSet` access control can be constructed, and classifies the running artifact through Security.framework plus kernel runtime signing flags. The executable does not create or open a key.

The reported biometric policy is qualification evidence for whole-scope and strict-mode authorization, not a requirement for every `run`. The product contract keeps exact named `--env` runs non-interactive by default and requires Touch ID for whole-scope requests or when strict authorization is configured.

The internal Rust lifecycle contract derives one application tag and a stable per-user lock name from the canonical vault home. It rejects non-owner permissions and extended ACLs, serializes separate processes, and defines atomic backend requirements for `create_new` and read-only `open_existing`. A private macOS backend now compiles those paths against Security.framework. It performs an exact logical-identity preflight, permanent Secure Enclave creation, post-create inspection, singleton validation, and exact-item rollback. Neither lifecycle module is public, and neither operation is available from the executable command line.

Build the reviewed ad-hoc artifact:

```bash
./scripts/build-adhoc.sh
```

The active Swift compiler must match the selected macOS SDK. On this repository's current development machine, use the installed Xcode beta and writable isolated module caches:

```bash
DEVELOPER_DIR=/Applications/Xcode-beta.app/Contents/Developer \
XDG_CACHE_HOME=/tmp/keyclasp-xdg-cache \
CLANG_MODULE_CACHE_PATH=/tmp/keyclasp-clang-cache \
./scripts/build-adhoc.sh
```

Inspect the adapter's non-mutating platform report:

```bash
./dist/keyclasp-core-spike status
```

The executable has no create, open, wrap, unwrap, delete, export, vault, or child-launch operation. The private core durably recovery-wraps a disposable vault data key before permanent hardware-key creation, adds an ECIES hardware wrap bound to the enrolled public key, and compares both recovered copies after an authenticated hardware unwrap. Recovery now uses the bounded, versioned Argon2id envelope recorded in the [strict lifecycle evidence](../../docs/security/2026-08-22-hardware-enclave-spike-evidence.md#strict-lifecycle-contract). The hidden lifecycle remains unreachable until the remaining memory-lifetime and physical-qualification blockers in that record are resolved. Recovery must enroll a replacement Secure Enclave key before an enrolled key is invalidated.
