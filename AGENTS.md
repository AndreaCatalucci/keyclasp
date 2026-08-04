# Keyclasp — Runtime Secrets for Coding Agents

> **Local encrypted secrets vault for coding-agent workflows. Secrets stay out of project files and are injected into trusted commands at runtime.**

> **Local-only project.** PRs MUST target `origin` (AndreaCatalucci/keyclasp). Use `gh pr create --repo AndreaCatalucci/keyclasp --base main`.

## Tech Stack

- **Runtime**: Node.js (TypeScript, ESM)
- **Encryption**: AES-256-GCM (Node crypto)
- **Storage**: SQLite (better-sqlite3)
- **Interface**: Local TypeScript CLI

## Project Structure

```
src/
├── vault.ts        → AES-256-GCM encryption + SQLite store, key management
├── run.ts          → Guarded child-process execution with secret injection
├── cli.ts          → CLI entry point (init/set/get/list/delete/run/status/version)
├── index.ts        → Public API exports
└── version.ts      → Package/git-derived version string

docs/solutions/     # documented solutions (bugs, best practices, workflow patterns), organized by category with YAML frontmatter (module, tags, problem_type)
```

## Commands

```bash
npm run build    # Compile TypeScript
npx tsc --watch  # Dev mode
```

## New User Flow

```bash
npm i -g keyclasp     # Install
keyclasp init         # Create vault
keyclasp set API_KEY - # Store a secret securely
keyclasp run -- npm test # Inject secrets into a trusted command
```

## Key Decisions

- **Process-boundary integration.** Coding agents work with secret names only; trusted commands receive real secrets only at runtime via `keyclasp run`.
- **Minimal surface, deliberately.** The CLI is intentionally small (init/set/get/list/delete/run/status) — every additional command is additional attack surface.
- **Local-only.** No dashboard, backend, or network service. The vault lives at `~/.keyclasp/`, owner-only permissions.
- **Machine-identity-bound key** — encryption key XOR-wrapped with a machine fingerprint before it's written to disk.
- **Zero network, zero telemetry** — fully local, no cloud, no accounts.
