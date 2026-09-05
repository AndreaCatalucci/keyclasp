# Keyclasp: Runtime Secrets for Coding Agents

You want to run your cli tool, and there's no MCP wrapping it. So you might be tempted to copypaste your api key into the agent's prompt to let it call this CLI.
Don't do that! Keyclasp lets you safely invoke any cli and pass secrets without the agent ever seeing them!

Keyclasp stores credentials in a local encrypted vault and injects selected values into a trusted child process. Keyclasp keeps values out of project files, prompts, its own command arguments, and its own output. A trusted child can deliberately copy an injected value into a downstream process argument; that degraded fallback can expose the value through process inspection, accounting, telemetry, or crash reports.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Keyclasp supports macOS `arm64` and glibc Linux `arm64` or `x64` on Node.js 24 or 26. macOS `x64` and Windows are unsupported at the moment

## Install

```bash
# After protected beta publication and registry-integrity verification:
npm install -g keyclasp@beta
keyclasp init
```

`keyclasp init` requires a non-empty passphrase and makes unmatched new records interactive. Use `keyclasp init --machine-only` only when unattended machine custody is an explicit requirement.

## Store and use a secret

```bash
keyclasp set SECRET_API_KEY - --project myapp --environment prod
keyclasp list --project myapp --environment prod
keyclasp run --project myapp --environment prod --env SECRET_API_KEY -- npm test
```

Map a stored name to the variable expected by the child:

```bash
keyclasp run --project myapp --environment prod \
  --env STORED_API_KEY:OPENAI_API_KEY -- npm test
```

Keyclasp launches the command without a shell. It blocks common environment-dump commands and scans stdout and stderr for injected values of at least eight characters. On a match it prints `[KEYCLASP_REDACTED]` and terminates the child. This catches accidental output; it cannot stop a trusted child from sending, storing, or transforming a credential.


## How custody works

Each software vault holds two independent AES-256-GCM data keys:

- The machine key supports unattended agent work.
- The interactive key is wrapped by a non-empty passphrase. Any access to such keys requires interactive authorization, preventing the agent from accessing secrets in this portion without explicit human authorization.

On macOS, interactive operations require Touch ID in a dialog. On Linux, one passphrase entry authorizes the operation and unlocks the interactive key.

A machine-only vault is an explicit unattended-storage choice. It can run an explicitly selected, unlocked secret without a prompt, but cannot perform `get`, broad runs, policy changes, backup, or restore until interactive custody is enrolled.

Fresh passphrase vaults default unmatched records to interactive custody. Existing upgraded vaults retain their prior unattended behavior as a visible `legacy machine default` until the operator makes an authorized `lock --default` or `unlock --default` choice. More-specific rules continue to take precedence.

`lock`, `unlock`, and `inherit` change rules and record custody under exclusive lifecycle control. A machine-to-interactive change does not complete until SQLite free pages and sidecars have been sanitized and the closed vault has been verified. If no machine records remain, Keyclasp also rotates and retires the old machine data key.

## Move records between custody classes

```bash
keyclasp passphrase set
keyclasp lock --project myapp --environment prod SECRET_API_KEY
keyclasp unlock --project myapp --environment prod SECRET_API_KEY
keyclasp inherit --project myapp --environment prod SECRET_API_KEY
keyclasp lock --default
keyclasp unlock --default
keyclasp passphrase rotate
```

Rules can target one project, one environment, an exact project/environment, or one exact secret. Resolution prefers exact secret, exact project/environment, project-only or environment-only, then the vault-wide default. Locked wins when project-only and environment-only rules have equal specificity. `inherit` removes the exact override and applies the next matching rule.

## Backup and restore

```bash
keyclasp backup create /secure/path/keyclasp-backup
keyclasp backup restore /secure/path/keyclasp-backup
```

Managed backups bind the database, dual-key bundle, policy, custody inventory, and manifest. A mixed backup containing machine records restores only on the source machine. A backup containing only interactive records can move to another supported machine with its passphrase; restore creates a fresh target-machine key without reclassifying records. Restore never drops or downgrades a record whose key is unavailable.

Backup authentication proves that a saved set is genuine and internally consistent; it does not prove that it is the newest state. Locking, changing a passphrase, sanitizing the live vault, or retiring a machine key cannot erase external snapshots, copied backups, child-process copies, logs, swap, or crash captures. Keep an explicit retention policy for every copy and rotate the provider credential when revocation matters.

## Coding-agent contract

Agents should inspect names with explicit scope, then run only effectively unlocked named selections:

```bash
keyclasp status --project myapp --environment prod
keyclasp list --project myapp --environment prod
keyclasp run --project myapp --environment prod --env SECRET_API_KEY -- npm test
```

There is a packaged agent skill in [`skills/keyclasp-agent`](skills/keyclasp-agent).

## Commands

| Command | Purpose |
|---|---|
| `init [--machine-only]` | Create an interactive-default vault, or explicitly choose machine-only custody |
| `set`, `list`, `delete` | Manage scoped secret records |
| `run --env SOURCE[:TARGET] -- <command>` | Inject selected secrets into one child |
| `get` | Print one value after operator authorization |
| `lock`, `unlock`, `inherit`; `lock\|unlock --default` | Change authenticated rules, fallback, and record custody |
| `passphrase set\|rotate` | Enroll or rotate interactive custody; removal is unavailable |
| `backup create\|restore` | Create or restore one authenticated vault set |
| `status` | Report custody and policy metadata after any required startup recovery |
| `doctor` | Report the disabled, status-only hardware boundary |

See the [command reference](docs/commands.md), [getting started guide](docs/getting-started.md), [security model](docs/security.md), and [FAQ](docs/faq.md).

## Security limits

- Keyclasp relies on the OS user boundary. It does not isolate secrets from root, a compromised OS, or another process running as the same user.
- The machine key is software-bound and weaker than a passphrase. It is not Secure Enclave, TPM, hardware attestation, or theft resistance.
- The interactive key is portable with its passphrase when no machine-key record is present in the backup.
- `get` prints plaintext into terminal output. Agents must never invoke it.
- `--allow-unsafe` disables command preflight and output scanning for that invocation; it never bypasses authorization.
- Project, environment, secret names, and policy metadata are not encrypted.
- Keyclasp overwrites its owned key buffers on a best-effort basis, but JavaScript strings, child environments, OS caches, swap, crash collectors, filesystem snapshots, and prior copies cannot be reliably erased in place.
- Keyclasp has not received a professional third-party security audit.

## Development

```bash
git clone https://github.com/AndreaCatalucci/keyclasp.git
cd keyclasp
npm ci
npm test
```

Keyclasp began as a fork of [Keyblind](https://github.com/aarifmms/keyblind), created by Mohammed Aarif Shaikh. Attribution is retained in [LICENSE](LICENSE) and [NOTICE](NOTICE).

Keyclasp is available under the [MIT License](LICENSE).
