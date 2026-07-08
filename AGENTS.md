# Keyblind — Blind AI to Your Keys

> **Encrypted secrets vault with MCP for AI agents. Secrets resolved at runtime, never leaked to LLM conversations.**

> **Fork** of [aarifmms/keyblind](https://github.com/aarifmms/keyblind) (MIT). Upstream remote configured.

## Tech Stack

- **Runtime**: Node.js (TypeScript, ESM)
- **Encryption**: AES-256-GCM (Node crypto)
- **Storage**: SQLite (better-sqlite3)
- **Protocol**: MCP (Model Context Protocol) via stdio + Streamable HTTP transport
- **Backends**: Local vault, 1Password CLI, Bitwarden CLI, env vars, AWS, GCP, Azure

## Project Structure

```
src/
├── vault.ts        → AES-256-GCM encryption + SQLite store
├── server.ts       → MCP server (16 tools) + REST API for dashboard
├── sandbox.ts      → .env sandbox with deterministic fakes (HMAC-SHA256)
├── backends.ts     → Multi-backend abstraction (local, 1Password, Bitwarden, env)
├── cli.ts          → CLI entry point (40+ commands)
├── index.ts        → Public API exports
├── totp.ts         → TOTP/HOTP 2FA code generation (zero deps)
├── share.ts        → Encrypted secret sharing via URL fragments
├── deadman.ts      → Dead man's switch with email notification
├── https.ts        → Let's Encrypt HTTPS for MCP server
├── sso.ts          → SSO/OIDC authentication for team vaults
├── setup-mcp.ts    → Auto-configure MCP for Claude Code (`keyblind setup-mcp`)
├── auth.ts         → Biometric authentication gate
├── license.ts      → Ed25519 license key verification
├── team.ts         → Shared team vaults (git-safe)
├── sync.ts         → Version history, rollback, sync bundles
├── doctor.ts       → Vault health check
├── config.ts       → Project configuration (.keyblind)
├── completions.ts  → Shell completions (bash, zsh, fish)
├── hook.ts         → Pre-commit hook for secret detection
├── watch.ts        → Watch .env and auto-sandbox
└── alerts.ts       → Slack/Discord webhook alerts

dashboard/          → Next.js web dashboard (app.keyblind.dev)
browser-extension/  → Chrome extension (MV3, paste interception)
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
- **16 MCP tools** — secrets, TOTP, sharing, dead man's switch, SSO, sandbox.
- **REST API alongside MCP** — same server supports browser dashboard at `app.keyblind.dev`.
- **Deterministic sandbox fakes** using HMAC-SHA256(project hash + key name) so git diffs stay clean.
- **Machine-identity-bound key** — encryption key XOR-wrapped with machine fingerprint.
- **Zero network, zero telemetry** — fully local, no cloud, no accounts.
- **Ed25519 license keys** — `keyblind.<base64url-payload>.<base64url-sig>` format, verified client-side.

## External Services

| Service | Purpose | Config |
|---------|---------|--------|
| **Vercel** | Dashboard hosting | `app.keyblind.dev` |
| **Stripe** | License payments | Webhook → `api/webhooks/stripe` |
| **Resend** | License key emails | `license@keyblind.dev` |

## Direct Competitor

**Cloak** (getcloak.dev, launched May 25 2026) — Rust CLI + VS Code extension. Sandboxes .env files with AES-256-GCM, Touch ID gate. No MCP support. VS Code/Cursor only.
