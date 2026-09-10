# FAQ

## Which systems are supported?

The software beta supports macOS `arm64` and glibc Linux `arm64` or `x64` on Node.js 24 and 26. macOS `x64`, Node 25, and musl Linux are outside the beta matrix. Windows is unsupported because the beta does not verify owner-only Windows ACLs or provide a qualified operator-authorization mechanism. Unsupported installs and forced diagnostic stateful use fail closed before vault creation.

## Why does `keyclasp init` report an unsafe macOS biometric helper ancestor path?

Before creating a vault, Keyclasp validates the packaged Touch ID helper and every directory from its package root to `/`. It rejects symbolic links, directories owned by anyone other than root or the current user, and directories writable by a group or by everyone. This error concerns the installation path; it can occur on a new machine before vault creation or a Touch ID prompt.

For a global npm installation under `/opt/homebrew`, one possible cause is `/opt/homebrew/lib` having permissions `775` (`drwxrwxr-x`). Check it with:

```sh
ls -ld /opt/homebrew/lib
```

If it shows `drwxrwxr-x`, remove group write permission and retry:

```sh
chmod g-w /opt/homebrew/lib
keyclasp init
```

This changes permissions on a shared Homebrew directory: other members of its group will no longer be able to write there through group permissions. The directory owner retains write access. If the permissions differ or the error persists, another directory in the installation path may be responsible; the current error does not identify which one.

## Is the machine key hardware-backed?

No. It is wrapped with a value derived from local machine identity. That value is not secret, attested, or protected by Secure Enclave or TPM. The mode supports unattended local agents; it does not provide theft resistance against someone who can reproduce the source machine identity.

## What does the interactive key add?

It is a separate random data key wrapped only by a non-empty passphrase. Possession of the machine key and its metadata cannot decrypt an interactive record. macOS requires Touch ID plus the passphrase for interactive use. Linux uses the passphrase as authorization and key unlock.

Fresh passphrase vaults use interactive custody for unmatched new records. `init --machine-only` is the explicit unattended alternative. Upgraded vaults keep a labelled legacy machine default until the operator runs `lock --default` or `unlock --default`.

## Can an agent use a dual-key vault?

Yes, for an explicitly selected record whose effective rule is unlocked and whose custody is machine. The agent must stop for locked selections, `get`, broad runs, passphrase prompts, custody changes, and backup or restore. Explicit selection limits disclosure but does not authenticate another process running as the same user.

## Can a backup move to another machine?

Only when every record is interactive. A mixed or machine-only backup requires its source machine identity and fails before replacing live state elsewhere. An all-interactive backup can restore with its passphrase and receives a fresh target-machine key without changing record custody.

## What happens if I lose the passphrase?

There is no recovery email, bypass, or passphrase removal. Recover the underlying credentials from their issuers. A backup of interactive records still requires its passphrase. Keep the database, key bundle, policy, and manifest together through `keyclasp backup`.

## Does locking revoke old backups or copied credentials?

No. Completed locking sanitizes the current database free space and SQLite sidecars; when no machine records remain it also retires the live machine key. It cannot revoke external snapshots, copied backups, values retained by a child, logs, swap, or crash captures. Backup authentication does not prove that a copy is the newest. Apply a retention policy to saved copies and rotate the credential with its provider when revocation matters.

## Does Keyclasp erase secrets from memory?

Keyclasp overwrites the key buffers it owns before replacing or clearing them and minimizes temporary decrypted buffers during custody changes. JavaScript strings, process environments, OS caches, swap, and crash collectors can retain copies outside that control; Keyclasp does not claim protected memory.

## Does `keyclasp run` make a child safe?

No. The child receives usable credentials. Keyclasp blocks common environment dumps and terminates on detected output leaks, but a child can transmit, store, transform, or leak a value shorter than eight characters without detection. Run only trusted code.

## Why was `[KEYCLASP_REDACTED]` printed?

The child wrote an injected value to stdout or stderr. Keyclasp redacted it, stopped forwarding output, and tried to terminate the supervised process group. It reports if OS permissions prevent confirmed termination. Fix the child's logging. `--allow-unsafe` disables the guard and should be used only for a specifically authorized invocation.

## Is hardware mode available?

No. The optional hardware adapter is status-only: it cannot enroll, open a vault, decrypt, recover, or launch a child. The software beta has a separate Touch ID authorization helper, which does not provide hardware key custody.

## How do I report a security issue?

Open a [private GitHub security advisory](https://github.com/AndreaCatalucci/keyclasp/security/advisories/new). Use a public issue only for non-sensitive defects.
