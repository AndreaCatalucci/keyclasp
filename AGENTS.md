# Keyblind — Blind AI to Your Keys

> **Local encrypted secrets vault for coding-agent workflows. Secrets stay out of project files and are injected into trusted commands at runtime.**

> **Local-only project.** PRs MUST target `origin` (AndreaCatalucci/keyblind). Use `gh pr create --repo AndreaCatalucci/keyblind --base main`.

## Tech Stack

- **Runtime**: Node.js (TypeScript, ESM)
- **Encryption**: AES-256-GCM (Node crypto)
- **Storage**: SQLite (better-sqlite3)
- **Interface**: Local TypeScript CLI
- **Backends**: Local vault, 1Password CLI, Bitwarden CLI, env vars, AWS, GCP, Azure

## Project Structure

```
src/
├── vault.ts        → AES-256-GCM encryption + SQLite store
├── sandbox.ts      → .env sandbox with deterministic fakes (HMAC-SHA256)
├── backends.ts     → Multi-backend abstraction (local, 1Password, Bitwarden, env)
├── cli.ts          → CLI entry point (40+ commands)
├── index.ts        → Public API exports
├── totp.ts         → TOTP/HOTP 2FA code generation (zero deps)
├── share.ts        → Encrypted secret sharing via URL fragments
├── run.ts          → Guarded child-process execution with secret injection
├── sync.ts         → Version history, rollback, sync bundles
├── doctor.ts       → Vault health check
├── config.ts       → Project configuration (.keyblind)
├── completions.ts  → Shell completions (bash, zsh, fish)
├── hook.ts         → Pre-commit hook for secret detection
└── watch.ts        → Watch .env and auto-sandbox

docs/solutions/     # documented solutions (bugs, best practices, workflow patterns), organized by category with YAML frontmatter (module, tags, problem_type)
```

## Commands

```bash
npm run build    # Compile TypeScript
npx tsc --watch  # Dev mode
```

## New User Flow

```bash
npm i -g keyblind     # Install
keyblind init         # Create vault
keyblind set API_KEY - # Store a secret securely
keyblind run -- npm test # Inject secrets into a trusted command
```

## Key Decisions

- **Process-boundary integration.** Coding agents work with safe project files; trusted commands receive real secrets only at runtime.
- **CLI-first.** Vault, sandbox, guarded execution, aliases, TOTP, sharing, sync, audit, and backend operations share one local interface.
- **Local-first core.** No dashboard or network service is required.
- **Deterministic sandbox fakes** using HMAC-SHA256(project hash + key name) so git diffs stay clean.
- **Machine-identity-bound key** — encryption key XOR-wrapped with machine fingerprint.
- **Zero network, zero telemetry** — fully local, no cloud, no accounts.
