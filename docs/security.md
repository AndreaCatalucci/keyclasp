# Keyblind Security Design

> Self-audit of the cryptographic architecture. Covers v0.5.0.
> For a professional third-party audit, contact security@keyblind.dev.

## Threat Model

**What we protect against:**
- Secrets leaking into LLM conversation transcripts
- Unauthorized vault access from other local processes
- Machine theft (encrypted-at-rest)
- Tampering with license files or vault data

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
│  Ed25519 ──► License validation (offline)             │
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

### 4. Ed25519 License Validation

License keys are signed with Ed25519:

- **Key pair**: Ed25519 (Curve25519)
- **Public key**: Baked into `src/license.ts` at build time
- **Private key**: Never shipped. Stored in Vercel environment (KEYBLIND_SIGNING_KEY)
- **Format**: `keyblind.<base64url(JSON payload)>.<base64url(signature)>`

```ts
const pubKey = crypto.createPublicKey({
  key: Buffer.from(PUBLIC_KEY_BASE64, "base64"),
  format: "der",
  type: "spki",
});
const valid = crypto.verify(null, data, pubKey, signature);
```

**Why Ed25519**: Fast, compact (64-byte signatures), and no side-channel concerns. Standard for software licensing.

**Revocation**: Not implemented. Compromised keys are handled by shipping a new version with an updated public key. The KEYBLIND_PUBLIC_KEY env var allows emergency key rotation without a new release.

### 5. Sandbox Fakes (HMAC-SHA256)

Deterministic fake values for `.env` sandboxing:

```ts
const fake = crypto.createHmac("sha256", projectHash)
  .update(secretName)
  .digest("hex")
  .slice(0, 32);
```

**Property**: Same project + same secret name = same fake value every time. Safe to commit to git. Collision resistance from SHA256.

### 6. Secret Sharing (AES-256-GCM + URL Fragment)

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
- Internal metadata (`_keyblind_meta`, `_expiry:*`)
- TOTP URIs and deadman configs

### What's Encrypted

- Secret values (each with unique IV)
- Team vault check data

## Protocol Security

### MCP Transport

- **Stdio transport**: Local process communication. No network exposure.
- **HTTP transport** (`keyblind start --http`): Plain HTTP on localhost by default. No TLS for local development. Use `--https --domain example.com` for remote access with Let's Encrypt auto-provisioning.

### HTTPS (Let's Encrypt)

- ACME HTTP-01 challenge for domain validation
- Auto-renewal 30 days before expiry (checked every 24h)
- Self-signed fallback if provisioning fails
- HTTP→HTTPS redirect on port 80

## Attack Surface Analysis

| Attack Vector | Risk | Mitigation |
|---------------|------|------------|
| LLM reads secrets from transcript | **HIGH** | MCP resolves at runtime, plaintext never in prompt |
| Malicious MCP client reads all secrets | **MEDIUM** | MCP tools only return user-facing names, not `_keyblind*` internal entries |
| Vault.db stolen + passphrase known | **MEDIUM** | Machine-identity-bound DEK prevents decryption on different hardware |
| Vault.db stolen, no passphrase | **LOW** | AES-256-GCM with 600K PBKDF2 iterations. Brute force infeasible |
| License tampering | **LOW** | Ed25519 signatures verified offline. Cannot forge without private key |
| Share link intercepted | **LOW-MED** | Fragment never sent to server. But link can be intercepted via browser history or phishing |
| Replay of old share links | **LOW** | TTL + expiry enforcement |
| Memory dump of running process | **MEDIUM** | DEK is in memory while vault is open. Mitigate with shorter session lifetimes |
| Dependency compromise | **MEDIUM** | Only 3 runtime deps (better-sqlite3, stripe, resend) + stdlib crypto |

## Recommendations for Production Deployments

1. **Use the biometric gate** (`keyblind unlock --biometric`) for session management
2. **Set KEYBLIND_SESSION_TIMEOUT** to auto-lock after inactivity
3. **Never commit `.keyblind/`** to version control
4. **Use `keyblind sandbox`** for all projects that interact with AI tools
5. **Rotate passphrases** if you suspect vault compromise
6. **Enable HTTPS** for remote MCP access (`keyblind start --https --domain X`)
7. **Set up dead man's switch** for team vault passphrase recovery

## Cryptographic Inventory

| Algorithm | Key Size | Used For | Node API |
|-----------|----------|----------|----------|
| AES-256-GCM | 256 bit | Secret encryption | `crypto.createCipheriv` |
| PBKDF2-SHA256 | 256 bit | Key derivation | `crypto.pbkdf2Sync` |
| SHA256 | 256 bit | Machine fingerprint, HMAC | `crypto.createHash` |
| HMAC-SHA256 | 256 bit | Sandbox fakes | `crypto.createHmac` |
| HMAC-SHA1/256/512 | 160-512 bit | TOTP/HOTP codes | `crypto.createHmac` |
| Ed25519 | 256 bit | License signing | `crypto.verify` |
| RSA-OAEP | 2048+ bit | Deadman key shard | `crypto.publicEncrypt` |

All algorithms use Node.js built-in `crypto` module. No third-party crypto libraries.
