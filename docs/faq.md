# FAQ

## What is Keyclasp?

Keyclasp is a local encrypted secrets vault and CLI. It keeps real credentials outside project files and injects secrets into child processes only when a command needs them.

## How is this different from a `.env` file?

A `.env` file stores plaintext inside the project directory, where coding agents, logs, shell tools, and accidental commits can expose it. Keyclasp stores values in an AES-256-GCM encrypted vault and only decrypts a value into a trusted child process's environment via `keyclasp run`.

## Is Keyclasp open source?

Yes. Keyclasp uses the MIT license. The source is available at [github.com/AndreaCatalucci/keyclasp](https://github.com/AndreaCatalucci/keyclasp).

## Where is my data stored?

An AES-256-GCM encrypted SQLite vault at `~/.keyclasp/vault.db`, with an owner-only-readable key file beside it. No account, network connection, or telemetry is required or used.

## What happens if I lose my passphrase or change machines?

There is no recovery email, backdoor, or "forgot password" flow. A passphrase vault cannot be opened without that passphrase. A machine-only vault (empty passphrase at `init`) is bound to this machine's identity and will not unlock on different hardware. Keep a tested backup or recovery plan before treating the local vault as the only copy of an important credential.

If a new CLI refuses an old XOR key file, clone this repository and run `scripts/migrate-vault-key-wrap.mjs` on the original machine.

## Can a coding agent safely use Keyclasp?

Yes, when the vault is machine-only and every explicitly selected secret is effectively unlocked. Selection limits disclosure but does not authenticate another same-user process. Passphrase vaults and locked rules require human input, so agents must stop. Agents must never call `get`, change lock rules, manage backups, or omit `--env`.

## What happens if recovery is needed?

- A forgotten passphrase has no bypass. Restore does not remove it; recover the credential from its issuer or another trusted source, then create a new vault.
- A passphrase-mode managed backup is portable with its passphrase. A machine-mode backup remains bound to the original machine identity; restore preflight rejects it on another machine without replacing usable live state.
- Restored lock rules remain authenticated and effective. On Linux they require a passphrase vault; on macOS they require usable Touch ID; unsupported gated operations fail closed.
- A missing, corrupt, or mismatched current key can be replaced by `keyclasp backup restore` because restore validates the backup rather than consulting the damaged live key. Database, key, and policy files must always come from the same managed backup.

## Does `keyclasp run` make any program safe?

No. A child process that receives a secret can still misuse it. Keyclasp blocks common environment-dump commands and scans output for injected values, terminating the process on a detected leak. These are safeguards, not a security boundary against malicious code.

## What Node.js version do I need?

Node.js 24 or newer. The package declares `"engines": { "node": ">=24" }`.

## Does it work on Linux and Windows?

Unlocked named runs work on macOS, Linux, and Windows using normal vault-mode behavior. Locked named runs and broad runs use Touch ID on macOS or one non-empty vault passphrase on Linux. Linux machine-only and Windows gated operations fail closed. Use explicit mappings on every platform.

## Why did `env` or `printenv` get blocked?

Those commands dump the process environment, which would print injected secrets. That is intentional. Prove injection with the target command, or with a check that reports only whether the variable is set, not its value.

## Why did my command print `[KEYCLASP_REDACTED]` and exit?

The child process wrote an injected secret to stdout or stderr. Keyclasp redacts the value and terminates the child. Fix the command so it does not print the credential; do not pass `--allow-unsafe` to hide the leak.

## How do I install Keyclasp?

```bash
npm install -g keyclasp
```

Or clone, build, and link:

```bash
git clone https://github.com/AndreaCatalucci/keyclasp.git
cd keyclasp
npm install
npm run build
npm link
```

## How do I report a security issue?

Open a [private GitHub security advisory](https://github.com/AndreaCatalucci/keyclasp/security/advisories/new). Do not open a public issue for security vulnerabilities.
