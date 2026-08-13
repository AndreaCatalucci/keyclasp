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
├── vault.ts        → AES-256-GCM encryption + SQLite store, key management, project/environment scoping
├── run.ts          → Guarded child-process execution with secret injection
├── context.ts      → --project/--environment flag parsing and precedence resolution (flag > env var > context.json > default)
├── cli.ts          → CLI entry point (init/set/get/list/delete/use/projects/environments/rename/run/status/version)
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
npm i -g github:AndreaCatalucci/keyclasp  # Install
keyclasp init         # Empty passphrase for machine-only (agents/CI)
keyclasp set API_KEY - # Store a secret securely
keyclasp run --env API_KEY -- npm test # Inject only the named secret
```

## Key Decisions

- **Process-boundary integration.** Coding agents work with secret names only; trusted commands receive real secrets only at runtime via `keyclasp run`.
- **Small surface, justified.** Every command in the CLI is deliberate — additional commands (`use`/`projects`/`environments`/`rename`, `--bulk` delete) exist because retroactively scoping secrets by project/environment required them, not by default. Each is weighed against the attack surface it adds.
- **Projects and environments are namespacing, not isolation.** Secrets live in one vault.db, keyed by `(project, environment, name)` — not per-project databases. Same secret name in two scopes is independent. Agents should always pass `--project`/`--environment` explicitly on every operation rather than relying on the persisted `keyclasp use` context, so parallel agent runs never race on shared mutable state.
- **Local-only.** No dashboard, backend, or network service. The vault lives at `~/.keyclasp/`, owner-only permissions.
- **Passphrase wraps the data key** — a random AES key is GCM-wrapped with PBKDF2(passphrase). Empty init selects a weaker machine-only wrap. The app does not read legacy XOR or Keyblind key files.
- **Zero network, zero telemetry** — fully local, no cloud, no accounts.
