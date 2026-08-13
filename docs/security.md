# Keyclasp Security Design

> Self-audit of the cryptographic architecture. Covers v1.0.0, the minimal hardened core (local vault + guarded `run`).
> To report a vulnerability privately, open a [GitHub security advisory](https://github.com/AndreaCatalucci/keyclasp/security/advisories/new).

## Threat Model

**What we protect against:**
- Secrets being left in project files that coding agents can inspect
- A coding agent (or its prompt/transcript/context) ever observing a plaintext secret value
- Unauthorized vault access from other local processes or users
- Machine theft (encrypted-at-rest)
- Tampering with vault data
- Accidental leakage of an injected secret into a guarded command's own stdout/stderr

**What we don't protect against (out of scope):**
- Kernel-level attacks (rootkits)
- Physical hardware keyloggers
- Memory dumping from a running process that has unlocked the vault
- Supply chain compromise of the installed Keyclasp package itself
- A trusted child process deliberately exfiltrating a secret it was intentionally given (e.g. via `--allow-unsafe`, or a network call it makes on purpose)

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│                   KEYCLASP VAULT                      │
├──────────────────────────────────────────────────────┤
│                                                       │
│  User Passphrase ──► PBKDF2 (600K iter) ──► Key      │
│                                                       │
│  Machine Fingerprint ──► XOR-wrap ──► Key file        │
│       (stable hardware/OS identifier)                 │
│                                                       │
│  Key ──► AES-256-GCM ──► SQLite (encrypted blobs)    │
│                                                       │
│  Secrets stored as:                                   │
│    { iv, authTag, ciphertext }                        │
│                                                       │
└──────────────────────────────────────────────────────┘
```

## Cryptographic Primitives

### 1. Key Derivation

The vault encryption key is derived from the user's passphrase using:

- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 600,000
- **Salt**: 32 random bytes, stored alongside the wrapped key in the key file
- **Key length**: 32 bytes (256 bits)

```ts
const key = crypto.pbkdf2Sync(passphrase, salt, 600_000, 32, "sha256");
```

**Rationale**: 600K iterations balances security with startup time (~200ms on modern hardware). Per OWASP guidance, this is at or above the minimum for PBKDF2-SHA256.

An empty passphrase is accepted ("machine-only key"). In that mode the derived key depends only on the random salt, so the meaningful protection comes entirely from the machine-identity wrap described next — the vault is then portable only in the sense that it requires the original machine, not a secret the user must remember.

### 2. Machine-Identity-Bound Key File

The on-disk key file wraps the derived key with a machine fingerprint before writing it out:

```ts
const wrappingKey = sha256(magic || salt || machineIdentity);
const wrappedKey = xor(key, wrappingKey);
```

`machineIdentity` prefers a stable hardware/OS identifier (e.g. `IOPlatformUUID` on macOS, `/etc/machine-id` on Linux, `MachineGuid` on Windows) and falls back to a hash of hostname/user/platform/arch.

**Purpose**: A key file copied to another machine cannot be unwrapped there, even with the correct passphrase, unless the destination machine's identity also matches. This limits blast radius if the key file alone is exfiltrated.

**Caveat**: This is not hardware attestation (no TPM/Secure Enclave). It is a locally-readable machine fingerprint, not a secret. An attacker with local access to the same machine (or its fingerprint) plus the passphrase can reconstruct the key. The real security boundary against a stolen key file is the passphrase, when one is set.

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

## `keyclasp run` — the Process Boundary

`keyclasp run` is the only supported way for a coding agent to cause a secret to reach a process. The agent itself never sees the plaintext value:

1. Secret names (not values) are the only thing an agent can discover, via `keyclasp list --project <project> --environment <environment>`.
2. `keyclasp run --project <project> --environment <environment> [--env SOURCE[:TARGET]] -- <command>` resolves and decrypts the requested secrets in that explicit scope and injects them directly into the spawned child's environment — the value never passes through the CLI's own stdout, and never appears in the shell command line or process arguments.
3. Before spawning, the command is checked against a small denylist of programs and shell one-liners known to dump the full environment (`env`, `printenv`, `export`, `bash -c 'env'`, etc.) and refused unless `--allow-unsafe` is passed explicitly.
4. While the child runs, its stdout and stderr are scanned for any injected value at least 8 characters long. A match is redacted in the stream and the child is terminated (`SIGTERM`, then `SIGKILL` after a grace period) so a partial leak cannot continue.

## Operator Biometric Gates

Two broad plaintext-access paths require operator authentication before Keyclasp resolves any secret value:

- `keyclasp get <name>`, which prints plaintext for a human operator.
- `keyclasp run` without `--env`, which injects every secret in the selected scope.

Keyclasp asks macOS LocalAuthentication to evaluate the biometric-only device-owner policy when Touch ID is available. If Touch ID is unavailable, not enrolled, or the helper cannot start, it asks for the vault passphrase in an interactive terminal and checks it against the key derived at `init`. A cancelled or failed Touch ID prompt does not fall back to the passphrase. A machine-only (empty) passphrase cannot authorize these paths. The passphrase prompt requires a TTY so a non-interactive agent cannot satisfy it by piping stdin. Agents must never invoke either operator-only path.

## Attack Surface Analysis

| Attack Vector | Risk | Mitigation |
|---------------|------|------------|
| Agent asks for a secret value directly | **HIGH** | `keyclasp get` requires Touch ID or an interactive vault passphrase before resolving the value, and the agent skill prohibits invoking it |
| Agent requests every secret in a scope | **HIGH** | Whole-scope `keyclasp run` requires Touch ID or an interactive vault passphrase; agent workflows must use explicit scope and `--env` mappings |
| Child process reads injected secrets | **HIGH** | Run only trusted commands; guarded execution reduces accidental disclosure but does not make malicious software safe |
| Injected command prints secrets to its own output | **HIGH** | `keyclasp run` blocks obvious environment dumps, redacts detected injected values from stdout/stderr, and terminates the child process by default; `--allow-unsafe` disables this and must be explicit |
| Vault.db stolen + passphrase known | **MEDIUM** | Machine-identity-bound key file prevents unwrapping on different hardware |
| Vault.db stolen, no passphrase, key file also stolen | **LOW-MEDIUM** | AES-256-GCM with 600K-iteration PBKDF2; if a real passphrase was set, brute force is infeasible. An empty ("machine-only") passphrase is weaker if both files leave the original machine's identity along with them |
| Memory dump of a running process that has unlocked the vault | **MEDIUM** | Out of scope; limit the lifetime of trusted processes |
| Dependency compromise | **MEDIUM** | Dependency set is intentionally minimal (`better-sqlite3` is the only runtime dependency); review lockfile changes before installing |

`keyclasp run` tracks injected values of at least 8 characters for output leak detection. Shorter values are still injected, but they are too ambiguous to scan safely without false positives in ordinary command output.

## Operational Recommendations

1. **Never commit `.keyclasp/`** to version control.
2. **Set a real passphrase at `keyclasp init`** unless you specifically want a machine-bound vault with no passphrase to remember.
3. **Use `keyclasp run`** instead of printing secrets into the shell or pasting them into an agent prompt.
4. **Always use explicit `--project`, `--environment`, and `--env SOURCE[:TARGET]` for agent commands** so both the namespace and requested secrets are unambiguous. Whole-scope injection is operator-only (Touch ID or interactive vault passphrase).
5. **Run only trusted child processes** with injected credentials.
6. **Rotate affected secrets** (`keyclasp set <name>` again) if you suspect compromise.

## Cryptographic Inventory

| Algorithm | Key Size | Used For | Node API |
|-----------|----------|----------|----------|
| AES-256-GCM | 256 bit | Secret value encryption | `crypto.createCipheriv` |
| PBKDF2-SHA256 | 256 bit | Key derivation from passphrase | `crypto.pbkdf2Sync` |
| SHA256 | 256 bit | Machine fingerprint, key wrapping | `crypto.createHash` |

All algorithms use Node.js's built-in `crypto` module. No third-party crypto libraries.
