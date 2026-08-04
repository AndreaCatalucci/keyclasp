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

There is no recovery email, backdoor, or "forgot password" flow. If you initialized with an empty passphrase ("machine-only key"), the vault key is also bound to a machine fingerprint and will not unlock on different hardware. Keep a tested backup or recovery plan before treating the local vault as the only copy of an important credential.

## Can a coding agent safely use Keyclasp?

Yes, when the agent works with secret names only and runs commands through `keyclasp run` instead of requesting plaintext. See the bundled [agent skill](../skills/keyclasp-agent/SKILL.md) for the exact workflow and safety rules.

## Does `keyclasp run` make any program safe?

No. A child process that receives a secret can still misuse it. Keyclasp blocks common environment-dump commands and scans output for injected values, terminating the process on a detected leak — these are safeguards, not a security boundary against malicious code.

## How do I report a security issue?

Open a [private GitHub security advisory](https://github.com/AndreaCatalucci/keyclasp/security/advisories/new). Do not open a public issue for security vulnerabilities.
