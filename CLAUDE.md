# Keyblind — Blind AI to Your Keys

> **Encrypted secrets vault with MCP for AI agents. Secrets resolved at runtime, never leaked to LLM conversations.**

## Tech Stack

- **Runtime**: Node.js (TypeScript, ESM)
- **Encryption**: AES-256-GCM (Node crypto)
- **Storage**: SQLite (better-sqlite3)
- **Protocol**: MCP (Model Context Protocol) via stdio transport
- **Backends**: Local vault, 1Password CLI, Bitwarden CLI, env vars

## Project Structure

```
src/
├── vault.ts      → AES-256-GCM encryption + SQLite store
├── server.ts     → MCP server (6 tools)
├── sandbox.ts    → .env sandbox with deterministic fakes (HMAC-SHA256)
├── backends.ts   → Multi-backend abstraction (local, 1Password, Bitwarden, env)
├── cli.ts        → CLI entry point (init, set, get, list, delete, sandbox, unsandbox, run, start, backends)
└── index.ts      → Public API exports
```

## Commands

```bash
npm run build    # Compile TypeScript
npx tsc --watch  # Dev mode
```

## Key Decisions

- **MCP-first, not editor-first.** Works with every AI tool that speaks MCP (Claude Code, Cursor, Copilot, Windsurf, Cline, Zed), not just VS Code.
- **Deterministic sandbox fakes** using HMAC-SHA256(project hash + key name) so git diffs stay clean.
- **Machine-identity-bound key** — encryption key XOR-wrapped with machine fingerprint.
- **Zero network, zero telemetry** — fully local, no cloud, no accounts.

## Direct Competitor

**Cloak** (getcloak.dev, launched May 25 2026) — Rust CLI + VS Code extension. Sandboxes .env files with AES-256-GCM, Touch ID gate. No MCP support. VS Code/Cursor only.
