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

Yes, when the agent works with secret names only and uses explicit `keyclasp run --project ... --environment ... --env ...` mappings instead of requesting plaintext. Agents must never call `keyclasp get` or omit `--env`; those paths are operator-only and require Touch ID or an interactive vault passphrase. See the bundled [agent skill](../skills/keyclasp-agent/SKILL.md) for the exact workflow and safety rules.

## Does `keyclasp run` make any program safe?

No. A child process that receives a secret can still misuse it. Keyclasp blocks common environment-dump commands and scans output for injected values, terminating the process on a detected leak — these are safeguards, not a security boundary against malicious code.

## What Node.js version do I need?

Node.js 24 or newer. The package declares `"engines": { "node": ">=24" }`.

## Does it work on Linux and Windows?

Yes. The vault, `set`, `list`, `status`, and `keyclasp run --env ...` work on macOS, Linux, and Windows. `keyclasp get` and whole-scope `keyclasp run` (no `--env`) ask for Touch ID when it is available. If Touch ID is missing, they ask for the vault passphrase in an interactive terminal. Use explicit `--env` mappings on every platform.

## Why did `env` or `printenv` get blocked?

Those commands dump the process environment, which would print injected secrets. That is intentional. Prove injection with the target command, or with a check that reports only whether the variable is set — not its value.

## Why did my command print `[KEYCLASP_REDACTED]` and exit?

The child process wrote an injected secret to stdout or stderr. Keyclasp redacts the value and terminates the child. Fix the command so it does not print the credential; do not pass `--allow-unsafe` to hide the leak.

## How do I install Keyclasp?

```bash
npm install -g github:AndreaCatalucci/keyclasp
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
