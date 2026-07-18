# Keyblind Security Design

> Self-audit of the cryptographic architecture. Covers v0.5.0.
> For a professional third-party audit, contact security@keyblind.dev.

## Threat Model

**What we protect against:**
- Secrets being left in project files that coding agents can inspect
- Unauthorized vault access from other local processes
- Machine theft (encrypted-at-rest)
- Tampering with vault data

**What we don't protect against (out of scope):**
- Kernel-level attacks (rootkits)
- Physical hardware keyloggers
- Memory dumping from a running process that has unlocked the vault
- Supply chain compromise of the `keyblind` npm package itself

## Architecture Overview

```
┌──────────────────────────────────────────────────────┐
│                   KEYBLIND VAULT                      │
├──────────────────────────────────────────────────────┤
│                                                       │
│  User Passphrase ──► PBKDF2 (600K iter) ──► KEK      │
│                                                       │
│  Machine Fingerprint ──► XOR ──► DEK                 │
│       (hostname + arch + platform + cpus)             │
│                                                       │
│  DEK ──► AES-256-GCM ──► SQLite (encrypted blobs)    │
│                                                       │
│  Secrets stored as:                                   │
│    { iv, authTag, ciphertext }                        │
│                                                       │
│  HMAC-SHA256 ──► Deterministic sandbox fakes          │
│                                                       │
│  HKDF ──► Share link key derivation                    │
│                                                       │
└──────────────────────────────────────────────────────┘
```

## Cryptographic Primitives

### 1. Key Derivation (KEK)

The Key Encryption Key (KEK) is derived from the user's passphrase using:

- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 600,000
- **Salt**: Stored in vault metadata (`_keyblind_meta`)
- **Key length**: 32 bytes (256 bits)

```ts
const kek = crypto.pbkdf2Sync(passphrase, salt, 600_000, 32, "sha256");
```

**Rationale**: 600K iterations balances security with startup time (~200ms on modern hardware). Per OWASP 2025 guidelines, the minimum is 600K for PBKDF2-SHA256.

### 2. Machine-Identity-Bound Key (DEK)

The Data Encryption Key (DEK) is derived by XOR-wrapping the KEK with a machine fingerprint:

```ts
const fingerprint = crypto.createHash("sha256")
  .update(`${os.hostname()}-${os.arch()}-${os.platform()}-${os.cpus().length}`)
  .digest();
const dek = xor(kek, fingerprint);
```

**Purpose**: A vault file copied to another machine cannot be decrypted even with the correct passphrase. The attacker needs both the passphrase AND the original machine's fingerprint.

**Caveat**: This is NOT a hardware-bound key (no TPM/SE usage). It provides machine identity binding but not hardware attestation. An attacker with the original machine's hostname/arch/cpu info AND the passphrase can reconstruct the DEK.

### 3. Symmetric Encryption (AES-256-GCM)

Every secret stored in the SQLite database is individually encrypted:

- **Algorithm**: AES-256-GCM
- **Key**: 256-bit DEK
- **IV**: 96-bit random (crypto.randomBytes(12))
- **Auth tag**: 128-bit (GCM default)
- **AAD**: None

```ts
const iv = crypto.randomBytes(12);
const cipher = crypto.createCipheriv("aes-256-gcm", dek, iv, { authTagLength: 16 });
const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
const authTag = cipher.getAuthTag();
```

**GCM over CBC**: We chose GCM for built-in authentication (AEAD). Tampering with ciphertext or auth tag is detected on decryption and throws. This prevents chosen-ciphertext attacks.

**Why no AAD**: We don't associate additional data with the ciphertext. The secret name is stored outside the encrypted blob, making it queryable. An attacker can't swap two secrets' encrypted values because the decryption would produce garbage (not a valid secret), and the auth tag check would fail if the ciphertext is modified.

### 4. Sandbox Fakes (HMAC-SHA256)

Deterministic fake values for `.env` sandboxing:

```ts
const fake = crypto.createHmac("sha256", projectHash)
  .update(secretName)
  .digest("hex")
  .slice(0, 32);
```

**Property**: Same project + same secret name = same fake value every time. Safe to commit to git. Collision resistance from SHA256.

### 5. Secret Sharing (AES-256-GCM + URL Fragment)

Share links encrypt the secret into the URL fragment:

```ts
const key = crypto.randomBytes(32);
const iv = crypto.randomBytes(12);
// AES-256-GCM encrypt payload → encode as base64url
// Key goes in fragment, payload follows
```

**The fragment (everything after #) never leaves the browser.** When the recipient opens the link, the browser strips the fragment before sending the HTTP request. The receiving CLI decrypts locally.

**One-time view**: The `maxViews` field is advisory — stored in the encrypted payload itself. A malicious recipient could re-share. For truly one-time sharing, use a separate channel for the key.

## Storage Security

### SQLite Database

- **Location**: `~/.keyblind/vault.db`
- **Permissions**: `0600` (owner read/write only)
- **Keychain directory**: `~/.keyblind/` permissions `0700`

### What's Stored in Plaintext

- Secret names (for querying)
- Alias metadata (alias name and canonical target name)
- Internal metadata (`_keyblind_meta`, `_expiry:*`)
- TOTP URIs

### What's Encrypted

- Secret values (each with unique IV)

Aliases are local-vault metadata pointers only. They do not duplicate encrypted secret values, and listing aliases never returns plaintext.

## Attack Surface Analysis

| Attack Vector | Risk | Mitigation |
|---------------|------|------------|
| Agent reads a real `.env` | **HIGH** | Import the file, then use deterministic sandbox values before agent access |
| Child process reads injected secrets | **HIGH** | Run only trusted commands; guarded execution reduces accidental disclosure but does not make malicious software safe |
| Alias metadata reveals naming conventions | **LOW** | Alias tools return names and targets only, never plaintext secret values |
| Vault.db stolen + passphrase known | **MEDIUM** | Machine-identity-bound DEK prevents decryption on different hardware |
| Vault.db stolen, no passphrase | **LOW** | AES-256-GCM with 600K PBKDF2 iterations. Brute force infeasible |
| Share link intercepted | **LOW-MED** | Fragment never sent to server. But link can be intercepted via browser history or phishing |
| Replay of old share links | **LOW** | TTL + expiry enforcement |
| Injected command prints secrets | **HIGH** | `keyblind run` blocks obvious environment dumps, redacts detected injected secret values from stdout/stderr, terminates the child process, and requires `--allow-unsafe` to disable this guard |
| Memory dump of running process | **MEDIUM** | DEK is in memory while vault is open. Limit the lifetime of trusted processes |
| Dependency compromise | **MEDIUM** | Keep the dependency set small, review lockfile changes, and install only trusted releases |

`keyblind run` tracks injected values of at least 8 characters for output leak detection. Shorter values are still injected, but they are too ambiguous to scan safely without false positives in ordinary command output.

## Operational Recommendations

1. **Never commit `.keyblind/`** to version control
2. **Use `keyblind sandbox`** before coding agents inspect project configuration
3. **Use `keyblind run`** instead of printing secrets into the shell
4. **Run only trusted child processes** with injected credentials
5. **Rotate passphrases and affected secrets** if you suspect compromise
6. **Treat remote backends as external trust boundaries** with their own accounts and networks

## Cryptographic Inventory

| Algorithm | Key Size | Used For | Node API |
|-----------|----------|----------|----------|
| AES-256-GCM | 256 bit | Secret encryption | `crypto.createCipheriv` |
| PBKDF2-SHA256 | 256 bit | Key derivation | `crypto.pbkdf2Sync` |
| SHA256 | 256 bit | Machine fingerprint, HMAC | `crypto.createHash` |
| HMAC-SHA256 | 256 bit | Sandbox fakes | `crypto.createHmac` |
| HMAC-SHA1/256/512 | 160-512 bit | TOTP/HOTP codes | `crypto.createHmac` |

All algorithms use Node.js built-in `crypto` module. No third-party crypto libraries.
