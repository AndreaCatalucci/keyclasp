# Keyclasp — Local Encrypted Credential Vault for Coding Agents

**Store credentials locally, encrypted. Let a coding agent run commands that need them — without the agent, its prompt, or its output ever seeing the plaintext.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Keyclasp is a minimal local secrets vault and CLI for AI coding agents. It lets an agent run tests, builds, API calls, cloud CLIs, and deployment tools without reading the real API keys, tokens, passwords, or credentials those commands need.

Requires **Node.js 24+**. The vault, `set`/`list`/`status`, and `keyclasp run --env ...` work on macOS, Linux, and Windows. `keyclasp get` and whole-scope `keyclasp run` (no `--env`) ask for macOS Touch ID when it is available, and otherwise ask for the vault passphrase in an interactive terminal.

## The Problem Keyclasp Solves

Coding agents inspect project files, execute commands, collect logs, and keep context about what they read. Putting a credential in a `.env` file, a shell argument, or a prompt puts it directly inside that working set.

Keyclasp separates what the agent can inspect from what a trusted process can receive:

```text
coding agent          Keyclasp vault           trusted child process
secret names only  -> encrypted values      -> runtime environment
```

The agent can discover that a project expects `SECRET_API_KEY` without ever seeing its value. When a command needs that key, `keyclasp run` injects it directly into the child process's environment — the value never passes through the agent's context, the CLI's own stdout, or the shell command line. Keyclasp also watches the command's own output, redacts a detected secret, and terminates the process if it leaks one.

## Why Use Keyclasp Instead of a Plain `.env` File?

| Workflow | Where the real secret appears | Visible to a coding agent? |
|---|---|---:|
| Plain `.env` | Project file | Usually |
| Shell argument | Shell history and process arguments | Often |
| Pasted into a prompt | Conversation history | Yes |
| `keyclasp run` | Encrypted vault and trusted child environment only | No, unless the child process itself prints it |

Keyclasp is local-only by design: no account, cloud service, network connection, dashboard, or telemetry. The vault lives at `~/.keyclasp/`, encrypted with AES-256-GCM, in a directory and key file only your OS user can read.

## Quick Start

### 1. Install

```bash
npm install -g github:AndreaCatalucci/keyclasp
```

The install compiles a native SQLite binding (`better-sqlite3`). If that step fails, install a C++ toolchain (Xcode Command Line Tools on macOS, `build-essential` plus Python on Linux) and retry.

Or clone, build, and link:

```bash
git clone https://github.com/AndreaCatalucci/keyclasp.git
cd keyclasp
npm install
npm run build
npm link
```

### 2. Initialize a local vault

```bash
keyclasp init
```

Enter a passphrase, or press Enter for a machine-only key. A passphrase vault asks for that passphrase again in each new process. Machine-only stays on this machine and is what agents and CI should use. Keyclasp cannot recover a lost passphrase.

### 3. Try it with a dummy secret

No real API key is required. `keyclasp set NAME -` prompts securely so the value does not enter shell history. Paste the value and press Enter (not Ctrl+D).

```bash
keyclasp set DEMO_SECRET - --project demo --environment local
# Paste any 8+ character string, then press Enter

keyclasp list --project demo --environment local
```

`list` prints names only. Prove injection without printing the value:

```bash
keyclasp run --project demo --environment local --env DEMO_SECRET -- \
  node -e 'const v = process.env.DEMO_SECRET; console.log(v ? "injected, " + v.length + " chars" : "missing")'
```

`env`, `printenv`, and `export` are blocked on purpose. If the child process prints the secret itself, Keyclasp redacts it as `[KEYCLASP_REDACTED]` and terminates the process — that is the leak guard working, not a failed inject:

```bash
keyclasp run --project demo --environment local --env DEMO_SECRET -- \
  node -e 'console.log(process.env.DEMO_SECRET)'
```

### 4. Use it with a real command

```bash
keyclasp set SECRET_API_KEY - --project myapp --environment prod
keyclasp run --project myapp --environment prod --env SECRET_API_KEY -- npm test
keyclasp status --project myapp --environment prod
```

Use explicit `--env` options so each command receives only the secrets it needs. This is the form that works on every platform, and the form coding agents should use.

An operator can inject every secret in the selected scope by omitting `--env`. That path asks for Touch ID when available, or the vault passphrase when Touch ID is not available:

```bash
keyclasp run --project myapp --environment prod -- npm test
```

## Use Keyclasp With Coding Agents

Tell the agent:

> Use Keyclasp for commands that need credentials. Agents and CI need a machine-only vault (empty passphrase at `init`); a passphrase vault stays locked in each new process and `run --env` will fail. Always pass the intended `--project` and `--environment` explicitly to `keyclasp list`, `keyclasp status`, and `keyclasp run`; do not rely on `keyclasp use` or ambient context. Choose the minimum required `--env` mappings and never omit `--env`. Never call `keyclasp get`, request whole-scope injection, or print or paste injected environment variables.

Keyclasp ships an agent skill at [`skills/keyclasp-agent`](skills/keyclasp-agent) that encodes exactly this workflow, plus explicit safety rules. From a clone of this repository:

```bash
npm run install:codex-skill
```

That copies the skill into the local agent skills directory (`$CODEX_HOME/skills/keyclasp-agent`, or `~/.codex/skills/keyclasp-agent` when `CODEX_HOME` is unset). For other tools, install the skill directory using that tool's skill mechanism or point the agent at it directly.

## Command Reference

| Command | Description |
|---------|-------------|
| `keyclasp init` | Initialize the encrypted vault |
| `keyclasp set <name>` | Store a secret (also updates an existing one) |
| `keyclasp get <name>` | Resolve and print a secret after Touch ID or vault passphrase (human use only) |
| `keyclasp list` | List stored secret names |
| `keyclasp delete <name>` | Delete a secret |
| `keyclasp use <project> <environment>` | Persist an interactive human context |
| `keyclasp projects` / `keyclasp environments` | List scope names in use |
| `keyclasp rename ...` | Rename a project, environment, or exact scope |
| `keyclasp delete --bulk ...` | Delete a scope after typed interactive confirmation |
| `keyclasp run [--env SOURCE[:TARGET]] [--allow-unsafe] -- <command>` | Run a command with secrets injected and output leak-guarded |
| `keyclasp status` | Show vault location, secret count, and a decryptability check |

Secret operations accept `--project`/`-p` and `--environment`/`-E`. Each field resolves independently through explicit flag, `KEYCLASP_PROJECT`/`KEYCLASP_ENVIRONMENT`, persisted context, then `default`. Scripts and coding agents should always pass both flags explicitly.

See the [full CLI reference](docs/commands.md).

## Security Boundaries

- Secret values are encrypted individually with AES-256-GCM; project, environment, and secret names are stored in plaintext.
- The vault lives under `~/.keyclasp/` with owner-only directory and file permissions (`0700`/`0600`).
- `keyclasp run` is the only path from the vault to a process; it blocks obvious environment-dump commands and redacts/terminates on a detected output leak.
- `keyclasp get` and whole-scope `keyclasp run` require a fresh macOS Touch ID approval when Touch ID is available. If it is not available, they ask for the vault passphrase in an interactive terminal. A cancelled Touch ID prompt does not fall back. A machine-only (empty) passphrase cannot authorize these paths.
- A child process that receives a secret can still misuse or print it. `keyclasp run` reduces this risk but cannot make untrusted code safe — only run trusted commands through it.
- `keyclasp get` deliberately prints plaintext after biometric approval. Its output may remain in terminal scrollback; agents must never invoke it.
- A non-empty passphrase wraps the vault data key. Unlock after each new process requires that passphrase (TTY). An empty ("machine-only") passphrase binds the key to the local machine's identity — that is the agent/CI mode.
- Old XOR key files are refused. Migrate this machine with `scripts/migrate-vault-key-wrap.mjs` from a clone of this repo.
- Keyclasp has not received a professional third-party security audit.

Read the [security design](docs/security.md) for the full threat model.

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

Keyclasp began as a fork of [Keyblind](https://github.com/aarifmms/keyblind), created by Mohammed Aarif Shaikh. The original project established the encrypted local vault and CLI workflow that Keyclasp continues to build on. Keyclasp has since narrowed to a minimal, hardened local vault and guarded-run process boundary for coding agents. The upstream git history is preserved, the original MIT copyright notice remains in [LICENSE](LICENSE), and additional attribution is recorded in [NOTICE](NOTICE).

## License

Keyclasp is available under the [MIT License](LICENSE).
