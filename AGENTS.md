# Keyblind — Blind AI to Your Keys

> **Encrypted secrets vault with MCP for AI agents. Secrets resolved at runtime, never leaked to LLM conversations.**

> **Local-only project.** PRs MUST target `origin` (AndreaCatalucci/keyblind). Use `gh pr create --repo AndreaCatalucci/keyblind --base main`.

## Tech Stack

- **Runtime**: Node.js (TypeScript, ESM)
- **Encryption**: AES-256-GCM (Node crypto)
- **Storage**: SQLite (better-sqlite3)
- **Protocol**: MCP (Model Context Protocol) via stdio
- **Backends**: Local vault, 1Password CLI, Bitwarden CLI, env vars, AWS, GCP, Azure

## Project Structure

```
src/
├── vault.ts        → AES-256-GCM encryption + SQLite store
├── server.ts       → MCP stdio server
├── sandbox.ts      → .env sandbox with deterministic fakes (HMAC-SHA256)
├── backends.ts     → Multi-backend abstraction (local, 1Password, Bitwarden, env)
├── cli.ts          → CLI entry point (40+ commands)
├── index.ts        → Public API exports
├── totp.ts         → TOTP/HOTP 2FA code generation (zero deps)
├── share.ts        → Encrypted secret sharing via URL fragments
├── setup-mcp.ts    → Auto-configure MCP for Claude Code (`keyblind setup-mcp`)
├── auth.ts         → Biometric authentication gate
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
keyblind setup-mcp    # Auto-configure Claude Code MCP
# Restart Claude Code — done
```

`keyblind setup-mcp` runs `claude mcp add --scope user keyblind -- keyblind start` under the hood. Works from any directory.

## Key Decisions

- **MCP-first, not editor-first.** Works with every AI tool that speaks MCP (Claude Code, Cursor, Copilot, Windsurf, Cline, Zed), not just VS Code.
- **13 MCP tools** — secrets, TOTP, sharing, sandbox.
- **Local-first MCP server** — stdio transport for AI agents; no dashboard REST backend in core.
- **Deterministic sandbox fakes** using HMAC-SHA256(project hash + key name) so git diffs stay clean.
- **Machine-identity-bound key** — encryption key XOR-wrapped with machine fingerprint.
- **Zero network, zero telemetry** — fully local, no cloud, no accounts.
