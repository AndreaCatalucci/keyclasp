# Keyclasp: Runtime Secrets for Coding Agents

Keyclasp stores credentials in a local encrypted vault and injects selected values into a trusted child process. Normal storage and guarded-run flows keep values out of project files, prompts, command arguments, and Keyclasp's own output. The operator-only `get` command is the explicit plaintext-output exception.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

The `0.2.0-beta.1` software beta supports macOS `arm64` and glibc Linux `arm64` or `x64` on Node.js 24 or 26. macOS `x64` and Windows are unsupported: installation and stateful use fail closed before creating vault state. Hardware mode is unavailable; `keyclasp doctor` reports status only.

## How custody works

Each software vault can hold two independent AES-256-GCM data keys:

- The machine key supports unattended agent work. Its wrapping mechanism uses local machine identity, which is not a secret or hardware attestation.
- The interactive key is wrapped by a non-empty passphrase. Interactive records remain unreadable with the machine key and its metadata.

New records use machine custody unless an effective lock rule assigns them to interactive custody. `lock`, `unlock`, and `inherit` atomically update the rule and re-encrypt matching existing records under the resulting key.

On macOS, interactive operations require Touch ID in a dialog identified as **Keyclasp**, then the vault passphrase. Run dialogs show the command, scope, selected secret names, and output-protection state without showing secret values. On Linux, one passphrase entry authorizes the operation and unlocks the interactive key. A machine-only vault can run an explicitly selected, unlocked secret without a prompt, but cannot perform `get`, broad runs, policy changes, backup, or restore until interactive custody is enrolled.

Explicit selection limits which values reach a child; it does not authenticate another process running as the same OS user. The child receives usable credentials and must be trusted.

## Install

```bash
# After protected beta publication and registry-integrity verification:
npm install -g keyclasp@beta
keyclasp init
```

Before publication, reviewers install only the exact local tarball and SHA-256 named in the release-candidate receipt. The registry command above is not evidence that the candidate has been published or qualified from npm.

Press Enter at `init` for a machine-only vault, or enter a passphrase to create both custody keys. The exact Keyclasp tarball carries reviewed `better-sqlite3` prebuilds for macOS `arm64` and glibc Linux `arm64` or `x64`; installation verifies the selected native binding's SHA-256 before Keyclasp can load it. No native binary is downloaded during installation. To compile the bundled reviewed sources instead, set `npm_config_build_from_source=true`; that path needs Xcode Command Line Tools on macOS or Python plus a C++ toolchain on Linux.

This prerelease has been prepared but is not yet published. Until publication is explicitly authorized, install the exact reviewed tarball by path instead of using `@beta`.

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

Agents must stop for locked selections and operator-only commands. They must not call `get`, omit `--env`, change custody rules, manage recovery, prompt for a passphrase, or use `--allow-unsafe` without authorization.

The packaged agent skill is in [`skills/keyclasp-agent`](skills/keyclasp-agent).

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
