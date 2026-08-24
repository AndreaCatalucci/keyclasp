# Keyclasp Security Design

> Self-audit of the cryptographic architecture. Covers v1.0.0, the minimal hardened core (local vault + guarded `run`).
> To report a vulnerability privately, open a [GitHub security advisory](https://github.com/AndreaCatalucci/keyclasp/security/advisories/new).

## Threat Model

**What we protect against:**
- Secrets being left in project files that coding agents can inspect
- Keyclasp returning a plaintext secret through the agent's prompt, transcript, command arguments, or its own stdout
- Unauthorized vault access from other operating-system users
- Machine theft (encrypted-at-rest)
- Tampering with vault data
- Accidental leakage of an injected secret into a guarded command's own stdout/stderr

**What we don't protect against (out of scope):**
- Kernel-level attacks (rootkits)
- Physical hardware keyloggers
- Memory dumping from a running process that has unlocked the vault
- Supply chain compromise of the installed Keyclasp package itself
- A trusted child process deliberately exfiltrating a secret it was intentionally given (e.g. via `--allow-unsafe`, or a network call it makes on purpose)
- Another process running as the same user requesting a known secret name through the default explicit `--env` path

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│                   KEYCLASP VAULT                      │
├──────────────────────────────────────────────────────┤
│                                                       │
│  Random DEK ──► AES-256-GCM ──► SQLite (secret blobs) │
│                                                       │
│  Passphrase ──► PBKDF2 (600K) ──► GCM-wrap DEK        │
│  or machine identity ──► GCM-wrap DEK (weaker mode)   │
│                                                       │
│  Secrets stored as:                                   │
│    { iv, authTag, ciphertext }                        │
│                                                       │
└──────────────────────────────────────────────────────┘
```

## Cryptographic Primitives

### 1. Key Derivation

The vault data key is 32 random bytes. A passphrase, when set, is used only to wrap that key:

- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 600,000
- **Salt**: 32 random bytes, stored in the key file
- **Key length**: 32 bytes (256 bits)

```ts
const dek = crypto.randomBytes(32);
const kek = crypto.pbkdf2Sync(passphrase, salt, 600_000, 32, "sha256");
```

**Rationale**: 600K iterations balances security with startup time (~200ms on modern hardware). Per OWASP guidance, this is at or above the minimum for PBKDF2-SHA256. The data key is independent of the passphrase so a wrap change does not rewrite `vault.db`.

An empty passphrase at `init` selects **machine-only** mode: the data key is GCM-wrapped under a KEK derived from a local machine fingerprint. That mode is weaker (the fingerprint is not a secret) and is the path for agents and CI.

### 2. Authenticated key-file wrap

The on-disk key file stores `encrypt(DEK, KEK)` with AES-256-GCM. `KEK` is either `PBKDF2(passphrase)` or `SHA256(magic || salt || machineIdentity)`. Mode is stored in the header and bound as AAD. Unlock of a passphrase vault requires that passphrase; there is no XOR fallback.

`machineIdentity` prefers a stable hardware/OS identifier (e.g. `IOPlatformUUID` on macOS, `/etc/machine-id` on Linux, `MachineGuid` on Windows) and falls back to a hash of hostname/user/platform/arch. It is used only in machine-only mode.

**Caveat**: Machine-only wrap is not hardware attestation. An attacker with the key file and this machine's identity can unwrap a machine-only vault. A passphrase vault cannot be unwrapped without the passphrase.

### 3. Symmetric Encryption (AES-256-GCM)

Every secret value stored in the SQLite database is individually encrypted:

- **Algorithm**: AES-256-GCM
- **Key**: 256-bit vault key
- **IV**: 96-bit random (`crypto.randomBytes(12)`) per value
- **Auth tag**: 128-bit (GCM default)

```ts
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", key, iv, { authTagLength: 16 });
const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
const authTag = cipher.getAuthTag();
```

**GCM over CBC**: GCM provides built-in authentication (AEAD). Tampering with ciphertext or the auth tag is detected on decryption and throws, rather than silently returning corrupted plaintext.

## Storage Security

- **Location**: `~/.keyclasp/vault.db` and `~/.keyclasp/.keyclasp.key`
- **Directory permissions**: `0700` (owner-only)
- **File permissions**: `0600` (owner read/write only) on both the database and the key file
- **What's stored in plaintext**: project, environment, and secret names (needed to scope, list, and query)
- **What's encrypted**: every secret value, individually, with its own IV

## `keyclasp run`: the Process Boundary

`keyclasp run` is the only supported way for a coding agent to cause a secret to reach a process. Keyclasp does not return the plaintext directly to the agent; the selected child receives it and must be trusted:

1. Secret names (not values) are the only thing an agent can discover, via `keyclasp list --project <project> --environment <environment>`.
2. `keyclasp run --project <project> --environment <environment> --env SOURCE[:TARGET] -- <command>` resolves and decrypts only the explicitly named secrets and injects them directly into the spawned child's environment. An effectively unlocked named request uses normal vault-mode behavior; an effectively locked request requires platform operator authorization first. The value never passes through the CLI's own stdout, shell command line, or process arguments.
3. Before spawning, the command is checked against a small denylist of programs and shell one-liners known to dump the full environment (`env`, `printenv`, `export`, `bash -c 'env'`, etc.) and refused unless `--allow-unsafe` is passed explicitly.
4. While the child runs, its stdout and stderr are scanned for any injected value at least 8 characters long. A match is redacted in the stream and the child is terminated (`SIGTERM`, then `SIGKILL` after a grace period) so a partial leak cannot continue.

Explicit `--env` selection limits which secrets reach the child; it does not authenticate the caller. Another process running as the same user can request a known secret name under the default policy. The approved child receives a usable credential and remains trusted.

Software validates the complete explicit selection before decrypting any value. A missing value, malformed mapping, duplicate target variable, or unresolved secret fails before child launch and never falls back to a broad run. The planned hardware core must preserve this invariant inside the native authority.

## Operator Authorization Gates

Two broad plaintext-access paths require operator authentication before Keyclasp resolves any secret value:

- `keyclasp get <name>`, which prints plaintext for a human operator.
- `keyclasp run` without `--env`, which injects every secret in the selected scope.

Broad runs, `get`, policy mutations, backup, and restore always require platform operator authorization. Named runs require it when any selected secret is effectively locked. On macOS, Keyclasp evaluates the biometric-only device-owner policy; unavailable, unenrolled, cancelled, denied, or failed Touch ID has no fallback, and a passphrase vault then requires its normal passphrase. On Linux, one non-empty live-vault or backup passphrase entry both authorizes and unlocks; machine-only and non-interactive gated operations fail closed. Windows operator authorization is deferred to the Slice 3 support-matrix decision.

The authenticated policy stores lock or unlock rules for exact secrets, exact project/environment pairs, one project, or one environment. Matching prefers exact secret, then exact scope, then project-only or environment-only, then unlocked. Locked wins equal-specificity conflicts, while a more-specific unlock overrides a broader lock. Rules cover future secrets. The document is domain-separated and bound to the vault ID and generation; its owner-only key anchor plus the database commitment detect tampering, scope transplant, deletion, and replay. An interruption journal restores the last committed generation. Rename, backup, and restore must preserve or fail closed on effective policy.

`keyclasp status` reads only names and authenticated metadata. It reports the software mode and effective authorization state but never unlocks the data key or decrypts secret values. Supported package exports are limited to parsing, context, biometric-result classification, path reporting, and name validation; vault database access, policy decisions, mutation, plaintext resolution, and child launch remain behind the lifecycle-serialized CLI boundary.

Policy mutations and managed backup/restore require Touch ID and take an exclusive lifecycle lock. Normal commands take shared locks, preserving concurrent request behavior while preventing restore from replacing an open vault. Managed backup manifests are authenticated with the vault data key, and passphrase or machine binding must unlock the backup before replacement. Backup creation syncs every staged file and directory before reporting success; a failure after destination publication is reported as indeterminate and leaves the destination for inspection. Restore uses an authenticated durable journal, retains the old set until the new set is complete, and keeps cleanup retryable after commit. The authenticated policy, vault database, and key must be backed up and restored as one set.

## Attack Surface Analysis

| Attack Vector | Risk | Mitigation |
|---------------|------|------------|
| Agent asks for a secret value directly | **HIGH** | `keyclasp get` requires Touch ID or an interactive vault passphrase before resolving the value, and the agent skill prohibits invoking it |
| Agent requests every secret in a scope | **HIGH** | A broad run always requires platform operator authorization; agent workflows must use explicit scope and `--env` mappings |
| Child process reads injected secrets | **HIGH** | Run only trusted commands; guarded execution reduces accidental disclosure but does not make malicious software safe |
| Injected command prints secrets to its own output | **HIGH** | `keyclasp run` blocks obvious environment dumps, redacts detected injected values from stdout/stderr, and terminates the child process by default; `--allow-unsafe` disables this and must be explicit |
| Vault.db + key file stolen, passphrase vault, no passphrase | **LOW** | GCM wrap under PBKDF2-SHA256 600k; brute force is the remaining path |
| Vault.db + key file stolen, machine-only, same machine identity | **HIGH** | Machine fingerprint is not a secret; this mode is for agents/CI, not theft resistance |
| Same-user process after unlock, or machine-only vault | **HIGH** | OS user isolation is the boundary; the wrap does not hide values from that user |
| Memory dump of a running process that has unlocked the vault | **MEDIUM** | Out of scope; limit the lifetime of trusted processes |
| Dependency compromise | **MEDIUM** | Dependency set is intentionally minimal (`better-sqlite3` is the only runtime dependency); review lockfile changes before installing |

`keyclasp run` tracks injected values of at least 8 characters for output leak detection. Shorter values are still injected, but they are too ambiguous to scan safely without false positives in ordinary command output.

## Operational Recommendations

1. **Never commit `.keyclasp/`** to version control.
2. **Set a real passphrase at `keyclasp init`** unless you specifically want a machine-bound vault with no passphrase to remember.
3. **Use `keyclasp run`** instead of printing secrets into the shell or pasting them into an agent prompt.
4. **Always use explicit `--project`, `--environment`, and `--env SOURCE[:TARGET]` for agent commands** so both the namespace and requested secrets are unambiguous. Broad and locked named runs require platform operator authorization. A macOS passphrase vault still requires its passphrase after Touch ID.
5. **Run only trusted child processes** with injected credentials.
6. **Rotate affected secrets** (`keyclasp set <name>` again) if you suspect compromise.

## Cryptographic Inventory

| Algorithm | Key Size | Used For | Node API |
|-----------|----------|----------|----------|
| AES-256-GCM | 256 bit | Secret value encryption | `crypto.createCipheriv` |
| PBKDF2-SHA256 | 256 bit | Key derivation from passphrase | `crypto.pbkdf2Sync` |
| SHA256 | 256 bit | Machine fingerprint for machine-only wrap | `crypto.createHash` |

All algorithms use Node.js's built-in `crypto` module. No third-party crypto libraries.
