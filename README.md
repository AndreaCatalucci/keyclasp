# Keyclasp — Runtime Secrets for Coding Agents

**Keep API keys out of coding-agent context and inject them only into trusted commands.**

[![npm version](https://img.shields.io/npm/v/keyclasp)](https://www.npmjs.com/package/keyclasp)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Keyclasp is a local secrets manager and encrypted vault for AI coding agents such as Codex, Claude Code, Cursor, Cline, and GitHub Copilot. It lets an agent run tests, builds, API calls, cloud CLIs, and deployment tools without reading the real API keys, tokens, passwords, or credentials those commands need.

If you are looking for a way to use secrets with an AI coding agent without putting them in `.env`, prompts, shell arguments, logs, or source files, Keyclasp is built for that problem.

## The Problem Keyclasp Solves

Coding agents inspect project files, execute commands, collect logs, and keep context about what they read. A normal `.env` file places plaintext credentials directly inside that working set.

Keyclasp separates what the agent can inspect from what a trusted process can receive:

```text
coding agent          Keyclasp vault           trusted child process
secret names only  -> encrypted values      -> runtime environment
safe .env fakes    -> local storage         -> credentials when needed
```

The agent can understand that a project expects `OPENAI_API_KEY` without seeing its value. When a command needs that key, `keyclasp run` injects it at the process boundary. Keyclasp watches the command's output, redacts a detected secret, and terminates the process if it leaks one.

## Why Use Keyclasp Instead of a Plain `.env` File?

| Workflow | Where the real secret appears | Visible to a coding agent? |
|---|---|---:|
| Plain `.env` | Project file | Usually |
| Shell argument | Shell history and process arguments | Often |
| Pasted into a prompt | Conversation history | Yes |
| `keyclasp run` | Encrypted vault and trusted child environment | No, unless the child process exposes it |

Keyclasp is local-first. The default vault needs no account, cloud service, network connection, dashboard, telemetry, or MCP server.

## Quick Start

### 1. Install and initialize

```bash
npm install -g keyclasp
keyclasp init
```

Keep the vault passphrase safe. Keyclasp cannot recover it for you.

### 2. Store an API key without putting it in shell history

```bash
keyclasp set OPENAI_API_KEY -
```

Paste the value at the secure prompt and press Ctrl+D.

### 3. Replace real `.env` values before an agent reads the project

```bash
keyclasp import .env
keyclasp sandbox .env
```

The sandbox replaces real values with deterministic fakes. The same variable receives the same fake, so repeated runs do not create noisy git diffs.

### 4. Run a command with secrets injected at runtime

```bash
keyclasp run --env OPENAI_API_KEY -- npm test
keyclasp run --env STRIPE_SECRET_KEY -- npm start
```

Use explicit `--env` options so each command receives only the secrets it needs. To inject every configured secret, use the shorter form:

```bash
keyclasp run -- npm test
```

### 5. Check the setup without revealing values

```bash
keyclasp status
keyclasp list
keyclasp doctor
```

`list` prints secret names only. It never prints their values.

## Use Keyclasp With Codex and Other Coding Agents

Tell the agent:

> Use Keyclasp for commands that need credentials. Inspect secret names with `keyclasp list`, choose the minimum required `--env` mappings, and run the trusted command through `keyclasp run`. Never call `keyclasp get` or `keyclasp export --env`, and never print injected environment variables.

Keyclasp ships an agent skill at [`skills/keyclasp-agent`](skills/keyclasp-agent). Install that directory as a Codex skill, then invoke `$keyclasp-agent` or let Codex select it when a command needs credentials. The skill teaches the agent to discover secret names, apply least privilege, and avoid plaintext-revealing commands.

The npm package includes the skill so agent tooling can discover the same instructions from the installed package.

## Common Workflows

### Map a stored secret to the variable a command expects

```bash
keyclasp run --env OPENAI_KEY:OPENAI_API_KEY -- npm test
```

For a reusable local alias:

```bash
keyclasp alias OPENAI_KEY OPENAI_API_KEY
keyclasp aliases
```

### Generate, rotate, and audit secrets

```bash
keyclasp generate SESSION_SECRET
keyclasp rotate OPENAI_API_KEY
keyclasp audit
keyclasp check --expired
```

### Restore a sandboxed `.env`

```bash
keyclasp unsandbox .env
```

Restore plaintext only when a local workflow genuinely requires it. Sandbox the file again before a coding agent inspects the project.

## Secret Backends

The default backend stores AES-256-GCM encrypted values in a local SQLite vault. Optional adapters use provider CLIs and may require an account and network access.

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
keyclasp backends
keyclasp config backend 1password
```

## Security Boundaries

- Secret values are encrypted individually with AES-256-GCM.
- New local vaults live under `~/.keyclasp/` with owner-only permissions.
- Secret names and some metadata remain plaintext so Keyclasp can query them.
- A child process receiving a secret can still misuse or print it. `keyclasp run` reduces this risk but cannot make untrusted code safe.
- `keyclasp get` and `keyclasp export --env` deliberately print plaintext. Their output may remain in terminal scrollback or logs.
- Machine-identity binding makes copied vaults harder to decrypt, but affects machine migration and recovery.
- Keyclasp has not received a professional third-party security audit.

Read the [security design](docs/security.md) for the full threat model.

## Migrating From Keyblind

Keyclasp recognizes existing Keyblind vaults and project configuration:

- `~/.keyblind/` is used when `~/.keyclasp/` does not exist;
- `KEYBLIND_HOME` remains accepted as a fallback for `KEYCLASP_HOME`;
- `.keyblind.key`, Keyblind v2 key headers, sandbox backups, and sync bundles remain readable;
- `.keyblind` project configuration remains readable, while future writes use `.keyclasp`.

Install the new package and use the new command:

```bash
npm uninstall -g keyblind
npm install -g keyclasp
keyclasp status
keyclasp install-hook
```

`keyclasp install-hook` replaces a pre-commit hook generated by Keyblind. Also replace any Keyblind completion setup in your shell configuration with the matching Keyclasp command:

```bash
# ~/.zshrc: replace source <(keyblind completions zsh) with:
source <(keyclasp completions zsh)

# ~/.bashrc: replace source <(keyblind completions bash) with:
source <(keyclasp completions bash)

# Fish: remove ~/.config/fish/completions/keyblind.fish, then run:
keyclasp completions fish > ~/.config/fish/completions/keyclasp.fish
```

Use only the command for your shell, then restart the shell or reload its configuration.

Back up your vault before moving or renaming its files manually.

## Documentation

- [Getting started](docs/getting-started.md)
- [CLI command reference](docs/commands.md)
- [Recipes](docs/recipes.md)
- [Security design](docs/security.md)
- [FAQ](docs/faq.md)

## Development

```bash
git clone https://github.com/AndreaCatalucci/keyclasp.git
cd keyclasp
npm install
npm run build
npm test
```

## Upstream Attribution

Keyclasp began as a fork of [Keyblind](https://github.com/aarifmms/keyblind), created by Mohammed Aarif Shaikh. The original project established the encrypted local vault, deterministic sandbox values, CLI workflows, and many of the capabilities that Keyclasp continues to build on.

Keyclasp has since diverged into a local, CLI-first process-boundary tool for coding agents. The upstream git history is preserved, the original MIT copyright notice remains in [LICENSE](LICENSE), and additional attribution is recorded in [NOTICE](NOTICE).

## License

Keyclasp is available under the [MIT License](LICENSE).
