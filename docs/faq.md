# FAQ

## What is Keyblind?

Keyblind is a local encrypted secrets vault and CLI. It keeps real credentials outside project files, replaces `.env` values with safe deterministic fakes, and injects secrets into child processes only when a command needs them.

## How is this different from a `.env` file?

A `.env` file stores plaintext inside the project directory, where coding agents, logs, shell tools, and accidental commits can expose it. Keyblind stores real values in an encrypted vault. `keyblind sandbox` leaves fake values in the project, while `keyblind run` supplies the real values to a trusted process at runtime.

## How is this different from 1Password or Bitwarden?

Keyblind focuses on safe developer and coding-agent workflows around project environment variables. It can also use 1Password or Bitwarden as an optional backend, so those tools can remain the source of truth while Keyblind provides sandboxing and guarded command execution.

## Is Keyblind open source?

Yes. Keyblind uses the MIT license. The source is available at [github.com/AndreaCatalucci/keyblind](https://github.com/AndreaCatalucci/keyblind).

## Where is my data stored?

The default backend stores an AES-256-GCM encrypted SQLite vault at `~/.keyblind/vault.db`. Local mode requires no account, network connection, or telemetry. Optional remote backends use their provider CLIs, accounts, and networks.

## What happens if I lose my passphrase or change machines?

There is no recovery email, backdoor, or “forgot password” flow. The vault key is also bound to a machine fingerprint. Keep a tested recovery or migration path before treating the local vault as the only copy of an important credential.

## Can I use Keyblind in CI/CD?

Yes. Use a vault or backend available in the CI environment and run the required command through `keyblind run`. Avoid commands that print the full environment, and treat build logs as potentially sensitive.

## Can a coding agent safely use Keyblind?

Yes, when the agent works with secret names and uses guarded commands instead of requesting plaintext. Sandbox project `.env` files before the agent reads them, and prefer `keyblind run -- <command>` whenever a tool needs credentials.

## Does `keyblind run` make any program safe?

No. A child process that receives a secret can misuse it. Keyblind blocks common environment-dump commands and scans output for injected values, but these are safeguards rather than a security boundary against malicious software.

## How do I switch backends?

```bash
keyblind config backend aws
keyblind config backend local
keyblind backends
```

## How do I report a security issue?

Email security@keyblind.dev. Do not open a public issue for security vulnerabilities.
