# Keyblind — Blind AI to Your Keys

**A local encrypted vault that keeps real credentials out of files coding agents can read.**

[![npm version](https://img.shields.io/npm/v/keyblind)](https://www.npmjs.com/package/keyblind)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## What Keyblind Does

Keyblind stores API keys, passwords, tokens, and other credentials in an encrypted local vault. It helps you work with coding agents without leaving real secrets in `.env` files, terminal commands, generated code, or git diffs.

Use Keyblind to:

- replace real `.env` values with stable, realistic fakes before an agent reads the project;
- run commands with secrets injected only into the child process;
- block obvious environment-dump commands and stop output that contains injected secrets;
- store, rotate, share, and audit secrets from one local CLI;
- optionally read from 1Password, Bitwarden, environment variables, AWS, GCP, or Azure.

Keyblind is local-first. The default vault requires no account, network connection, or telemetry.

## Why It Helps

Coding agents inspect configuration, run commands, edit files, and collect logs. A normal `.env` file puts plaintext credentials directly inside that working set.

Keyblind separates project configuration from real credentials:

```text
project files       Keyblind vault           child process
safe fake values -> encrypted secrets -> runtime environment
```

The agent can understand which variables a project expects without reading their real values. When a command needs credentials, `keyblind run` injects them at execution time and watches output for accidental disclosure.

## Quick Start

### 1. Install and initialize

```bash
npm install -g keyblind
keyblind init
```

Keep the vault passphrase safe. Keyblind cannot recover it for you.

### 2. Store a secret securely

```bash
keyblind set OPENAI_API_KEY -
```

Paste the value at the secure prompt and press Ctrl+D. Avoid typing secrets directly into shell commands, where they may remain in shell history.

### 3. Prepare a project for an agent

If the project already has a real `.env`, import it before replacing its values:

```bash
keyblind import .env
keyblind sandbox .env
```

The sandbox uses deterministic fake values, so repeated runs do not create noisy git diffs.

### 4. Run a command with secrets

```bash
keyblind run -- npm test
keyblind run -- npm start
```

Keyblind injects stored secrets as environment variables for the child process. If detected output contains an injected secret, Keyblind redacts the value and terminates the command.

### 5. Verify the setup

```bash
keyblind status
keyblind list
```

`status` checks the vault and active backend. `list` prints secret names only, never their values.

## Common Workflows

### Map a secret to another variable name

For one command:

```bash
keyblind run --env OPENAI_API_KEY:AI_TOKEN -- npm test
```

For a reusable local alias:

```bash
keyblind alias OPENAI_API_KEY AI_TOKEN
keyblind aliases
```

Aliases point to the original encrypted value; they do not duplicate it.

### Generate or rotate without revealing the value

```bash
keyblind generate SESSION_SECRET
keyblind rotate OPENAI_API_KEY
```

### Restore a sandboxed `.env`

```bash
keyblind unsandbox .env
```

Restore real values only when a local workflow genuinely requires them. Sandbox the file again before giving a coding agent access to the project.

### Check health and activity

```bash
keyblind doctor
keyblind audit
keyblind check --expired
```

## Using Keyblind With Coding Agents

Keyblind works best when the agent follows three rules:

1. Inspect secret names and redacted status, not plaintext values.
2. Sandbox `.env` files before reading or editing them.
3. Use `keyblind run -- <command>` when a tool needs credentials.

Reusable coding-agent skills and task recipes are planned, but are not currently shipped. They will build on sandboxing and guarded CLI execution rather than giving the model direct access to secret values.

## Backends

The default local backend stores AES-256-GCM encrypted values in SQLite. Optional adapters use their provider CLIs and may require accounts and network access.

| Backend | Read | Write | Requirement |
|---|---:|---:|---|
| **local** | ✓ | ✓ | Nothing |
| **1password** | ✓ | ✓ | `op` CLI |
| **bitwarden** | ✓ | — | `bw` CLI |
| **env** | ✓ | — | Environment variables |
| **aws** | ✓ | ✓ | `aws` CLI |
| **gcp** | ✓ | ✓ | `gcloud` CLI |
| **azure** | ✓ | ✓ | `az` CLI |

```bash
keyblind backends
keyblind config backend 1password
```

## Security Boundaries

- Secret values are encrypted individually with AES-256-GCM.
- The default vault lives under `~/.keyblind/` with owner-only permissions.
- Secret names and some metadata remain plaintext so Keyblind can query them.
- A process receiving an injected secret can still misuse or print it; `keyblind run` reduces this risk but cannot make an untrusted program safe.
- Commands such as `keyblind get` and `keyblind export --env` deliberately print plaintext. Their output may remain in terminal scrollback or logs.
- Machine identity binding makes copied vaults harder to decrypt, but also affects machine migration and recovery. Review the security guide before relying on it as your only copy.
- Keyblind has not received a professional third-party security audit.

See the [security design](docs/security.md) for the full threat model.

## Documentation

- [Getting started](docs/getting-started.md)
- [CLI command reference](docs/commands.md)
- [Recipes](docs/recipes.md)
- [Security design](docs/security.md)
- [FAQ](docs/faq.md)

## Development

```bash
git clone https://github.com/AndreaCatalucci/keyblind.git
cd keyblind
npm install
npm run build
npm test
```

## License

MIT
