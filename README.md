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

Press Enter at `init` for a machine-only vault, or enter a passphrase to create the custody keys.

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

Keyclasp launches the command without a shell. It rejects secret strings that cannot be represented unchanged as UTF-8, blocks common environment-dump commands, and scans stdout and stderr for injected values of at least eight characters. On a match it prints `[KEYCLASP_REDACTED]`, stops forwarding child output, terminates every supervised process-group member that the invoking user can signal, and returns a nonzero result. If the operating system refuses a descendant signal, Keyclasp reports that containment could not be confirmed. This catches accidental exact-value output; it cannot stop a trusted child from sending, storing, transforming, or privilege-elevating with a credential.


## How custody works

Each software vault holds two independent AES-256-GCM data keys:

- The machine key supports unattended agent work.
- The interactive key is wrapped by a non-empty passphrase. Any access to such keys requires interactive authorization, preventing the agent from accessing secrets in this portion without explicit human authorization.

On macOS, interactive operations require Touch ID in a dialog. On Linux, one passphrase entry authorizes the operation and unlocks the interactive key.

A machine-only vault can run an explicitly selected, unlocked secret without a prompt, but cannot perform `get`, broad runs, policy changes, backup, or restore until interactive custody is enrolled.

The  `lock`, `unlock`, and `inherit` move secrets from machine to the interactive key encryption, and always require interactive authorization.

## Move records between custody classes

```bash
keyclasp passphrase set
keyclasp lock --project myapp --environment prod SECRET_API_KEY
keyclasp unlock --project myapp --environment prod SECRET_API_KEY
keyclasp inherit --project myapp --environment prod SECRET_API_KEY
keyclasp passphrase rotate
```

Rules can target one project, one environment, an exact project/environment, or one exact secret. Resolution prefers exact secret, exact project/environment, project-only or environment-only, then unlocked. Locked wins when project-only and environment-only rules have equal specificity. `inherit` removes the exact override and applies the next matching rule.

## Backup and restore

```bash
keyclasp backup create /secure/path/keyclasp-backup
keyclasp backup restore /secure/path/keyclasp-backup
```

Managed backups bind the database, dual-key bundle, policy, custody inventory, and manifest. A mixed backup containing machine records restores only on the source machine. A backup containing only interactive records can move to another supported machine with its passphrase; restore creates a fresh target-machine key without reclassifying records. Restore never drops or downgrades a record whose key is unavailable.

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
| `init` | Create a machine-only or dual-key software vault |
| `set`, `list`, `delete` | Manage scoped secret records |
| `run --env SOURCE[:TARGET] -- <command>` | Inject selected secrets into one child |
| `get` | Print one value after operator authorization |
| `lock`, `unlock`, `inherit` | Change authenticated rules and record custody |
| `passphrase set\|rotate` | Enroll or rotate interactive custody; removal is unavailable |
| `backup create\|restore` | Create or restore one authenticated vault set |
| `status` | Read custody and policy metadata without loading a data key |
| `doctor` | Report the disabled, status-only hardware boundary |

See the [command reference](docs/commands.md), [getting started guide](docs/getting-started.md), [security model](docs/security.md), and [FAQ](docs/faq.md).

## Security limits

- Keyclasp relies on the OS user boundary. It does not isolate secrets from root, a compromised OS, or another process running as the same user.
- The machine key is software-bound and weaker than a passphrase. It is not Secure Enclave, TPM, hardware attestation, or theft resistance.
- The interactive key is portable with its passphrase when no machine-key record is present in the backup.
- `get` prints plaintext into terminal output. Agents must never invoke it.
- `--allow-unsafe` disables command preflight and output scanning for that invocation; it never bypasses authorization.
- On macOS, Keyclasp validates the packaged Touch ID helper's path, ownership, mode bits, write-granting ACLs, manifest hash, signature, hardened-runtime flag, identifier, and designated requirement before launch. It starts the helper with a fixed minimal environment. These checks detect a damaged or replaced package but do not isolate Keyclasp from arbitrary code already running as the same user.
- Project, environment, secret names, and policy metadata are not encrypted.
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
