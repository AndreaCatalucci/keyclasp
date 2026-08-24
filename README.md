# Keyclasp: Local Encrypted Credential Vault for Coding Agents

**Store credentials locally, encrypted. Let a coding agent run commands that need them, without the agent, its prompt, or its output ever seeing the plaintext.**

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

Keyclasp is a minimal local secrets vault and CLI for AI coding agents. It keeps credentials out of project files, prompts, and command arguments while injecting selected values into the child process that needs them. That child receives usable credentials and must be trusted.

Requires **Node.js 24+**. Unlocked named runs use normal vault-mode behavior. Locked named runs and broad runs require Touch ID on macOS or one non-empty passphrase on Linux; Linux machine-only fails closed. Windows operator authorization remains deferred.

## The Problem Keyclasp Solves

Coding agents inspect project files, execute commands, collect logs, and keep context about what they read. Putting a credential in a `.env` file, a shell argument, or a prompt puts it directly inside that working set.

Keyclasp separates what the agent can inspect from what a trusted process can receive:

```text
coding agent          Keyclasp vault           trusted child process
secret names only  -> encrypted values      -> runtime environment
```

The agent can discover that a project expects `SECRET_API_KEY` without ever seeing its value. When a command needs that key, `keyclasp run` injects it directly into the child process's environment. The value never passes through the agent's context, the CLI's own stdout, or the shell command line. Keyclasp also watches the command's own output, redacts a detected secret, and terminates the process if it leaks one.

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
npm install -g keyclasp
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

`env`, `printenv`, and `export` are blocked on purpose. If the child process prints the secret itself, Keyclasp redacts it as `[KEYCLASP_REDACTED]` and terminates the process. That's not a failed inject: the injection worked, but the child leaked the value into its own output, so the leak guard caught it and shut the process down:

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

Use explicit `--env` options so each command receives only the secrets it needs. Named runs use each selected secret's effective lock state. Coding agents should use only effectively unlocked mappings.

Explicit selection limits disclosure; it does not authenticate the caller. Another process running as the same operating-system user can request a known secret name for a child command. The child that receives a secret must be trusted.

An operator can lock one project, environment, scope, or exact secret. A more-specific unlock overrides a broader lock:

```bash
keyclasp lock --project myapp
keyclasp lock --project myapp --environment prod
keyclasp unlock --project myapp --environment prod READ_ONLY_TOKEN
```

An operator can request every secret in the selected scope by omitting `--env`. That path always requires platform operator authorization:

```bash
keyclasp run --project myapp --environment prod -- npm test
```

## Use Keyclasp With Coding Agents

Tell the agent:

> Use Keyclasp for commands that need credentials. Agents and CI need a machine-only vault and effectively unlocked named selections. Always pass `--project`, `--environment`, and the minimum required `--env` mappings explicitly. Never call `get`, request a broad run, change authorization policy, or print injected values.

Keyclasp ships an agent skill at [`skills/keyclasp-agent`](skills/keyclasp-agent) that encodes this workflow and the safety rules. Install it for the coding agents on this machine:

```bash
npx skills add AndreaCatalucci/keyclasp@keyclasp-agent -g
```

From a clone of this repository:

```bash
npx skills add . --skill keyclasp-agent -g
```

## Command Reference

| Command | Description |
|---------|-------------|
| `keyclasp init` | Initialize the encrypted vault |
| `keyclasp set <name>` | Store a secret (also updates an existing one) |
| `keyclasp get <name>` | Resolve and print a secret after platform operator authorization |
| `keyclasp list` | List stored secret names |
| `keyclasp delete <name>` | Delete a secret |
| `keyclasp use <project> <environment>` | Persist an interactive human context |
| `keyclasp projects` / `keyclasp environments` | List scope names in use |
| `keyclasp rename ...` | Rename a project, environment, or exact scope |
| `keyclasp delete --bulk ...` | Delete a scope after typed interactive confirmation |
| `keyclasp run [--env SOURCE[:TARGET]] [--allow-unsafe] -- <command>` | Run a command with secrets injected and output leak-guarded |
| `keyclasp lock\|unlock [--project P] [--environment E] [SECRET]` | Set an authenticated authorization rule |
| `keyclasp backup create\|restore <directory>` | Create or restore one verified, consistent vault backup |
| `keyclasp status` | Show vault mode, effective authorization state, location, and secret count without decrypting values |
| `keyclasp doctor` | Inspect the status-only macOS hardware core; does not enable hardware mode |

Secret operations accept `--project`/`-p` and `--environment`/`-E`. Each field resolves independently through explicit flag, `KEYCLASP_PROJECT`/`KEYCLASP_ENVIRONMENT`, persisted context, then `default`. Scripts and coding agents should always pass both flags explicitly.

See the [full CLI reference](docs/commands.md).

## Security Boundaries

- Hardware-backed mode is not released. The current native core is status-only and cannot open a vault, handle secrets, enroll a key, or launch a child.
- Lock state is authorization policy only. `unlock` does not change passphrase/machine key custody or vault mode.
- Secret values are encrypted individually with AES-256-GCM; project, environment, and secret names are stored in plaintext.
- The vault lives under `~/.keyclasp/` with owner-only directory and file permissions (`0700`/`0600`).
- `keyclasp run` is the only path from the vault to a process; it blocks obvious environment-dump commands and redacts/terminates on a detected output leak.
- `get`, policy mutations, recovery, and broad runs always require platform operator authorization. macOS Touch ID never falls back to passphrase-only authorization. Linux reuses one successful passphrase entry for authorization and unlock.
- A child process that receives a secret can still misuse or print it. `keyclasp run` reduces this risk but cannot make untrusted code safe. Only run trusted commands through it.
- `keyclasp get` deliberately prints plaintext after biometric approval. Its output may remain in terminal scrollback; agents must never invoke it.
- A non-empty passphrase wraps the vault data key. Unlock after each new process requires that passphrase (TTY). An empty ("machine-only") passphrase binds the key to the local machine's identity. That is the agent/CI mode.
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
