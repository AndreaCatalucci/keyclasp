# Keyblind — Blind AI to Your Keys

**Encrypted secrets vault with MCP for AI agents. Secrets resolved at runtime, never leaked to LLM conversations.**

[![npm version](https://img.shields.io/npm/v/keyblind)](https://www.npmjs.com/package/keyblind)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Why

Developers regularly leak API keys, passwords, and tokens to AI coding tools. 100,000+ LLM conversations with exposed secrets were found indexed by search engines in 2025.

AI agents read your `.env` files. They copy-paste secrets into conversations. They commit them accidentally. Keyblind stops this by keeping secrets encrypted at rest and resolving them _at runtime_ — the plaintext value never touches the LLM transcript.

## How It Works

```
┌──────────┐     ┌────────────────┐     ┌─────────────────┐
│ AI Agent │ ──→ │  Keyblind MCP  │ ──→ │  Encrypted      │
│ (Claude) │     │  Server        │     │  SQLite Vault   │
│          │ ←── │  (6 tools)     │ ←── │  (AES-256-GCM)  │
└──────────┘     └────────────────┘     └─────────────────┘
      ↑                                        │
      │ secret value never appears             │ secrets never
      │ in conversation transcript             │ stored in plaintext
```

## Quick Start

```bash
# Install
npm i -g keyblind

# Initialize your vault
keyblind init

# Store secrets
echo "sk-proj-abc123" | keyblind set OPENAI_API_KEY
keyblind set DATABASE_URL -    # prompts securely

# Sandbox your .env (AI agents see fakes)
keyblind sandbox

# Resolve a secret
keyblind get OPENAI_API_KEY

# Run commands with secrets injected as env vars
keyblind run -- npm start

# List all secrets (names only)
keyblind list
```

## MCP Server

Keyblind is **MCP-first** — it works with every AI tool that speaks the Model Context Protocol:

**Claude Code, Cursor, Copilot, Windsurf, Cline, Zed** — add a `.mcp.json` to your project root:

```json
{
  "mcpServers": {
    "keyblind": {
      "command": "npx",
      "args": ["keyblind", "start"]
    }
  }
}
```

With biometric gate (Touch ID required before secrets are resolved):

```json
{
  "mcpServers": {
    "keyblind": {
      "command": "npx",
      "args": ["keyblind", "start", "--biometric"]
    }
  }
}
```

> **Note**: `--biometric` requires running `keyblind unlock` first to authenticate. Session expires after 15 minutes.

[Full editor-specific configs →](docs/editors.md)

### MCP Tools

| Tool | Description |
|------|-------------|
| `resolve_secret` | Resolve a secret at runtime (value hidden from transcript) |
| `store_secret` | Encrypt and store a secret |
| `list_secrets` | List secret names (values never revealed) |
| `sandbox_env` | Replace `.env` values with deterministic fakes |
| `unsandbox_env` | Restore real `.env` values from vault |
| `delete_secret` | Delete a secret |

## Pricing

| | Free | Pro | Team |
|------|------|-----|------|
| **Price** | $0 | $79/year | $29/user/month |
| **Secrets** | 5 | Unlimited | Unlimited |
| **Local vault** | ✓ | ✓ | ✓ |
| **Sandbox / Unsandbox** | ✓ | ✓ | ✓ |
| **MCP server** | ✓ | ✓ | ✓ |
| **7 backends** | ✓ | ✓ | ✓ |
| **Team vaults** | — | ✓ | ✓ |
| **Audit log** | — | ✓ | ✓ |
| **Secret rotation** | — | ✓ | ✓ |
| **CI/CD integration** | — | ✓ | ✓ |
| **Biometric gate** | — | ✓ | ✓ |
| **Cloud backends** | — | ✓ | ✓ |

```bash
# Activate a Pro or Team license
keyblind activate <your-license-key>

# Check your current status
keyblind status
```

> **Coming soon:** Purchase licenses at [keyblind.dev](https://keyblind.dev). For early access, open a GitHub issue or contact the maintainer.

## Backends

Keyblind supports multiple secret backends:

```bash
keyblind backends                          # List available backends
keyblind backend 1password                 # Switch to 1Password
keyblind backend bitwarden                 # Switch to Bitwarden
```

| Backend | Read | Write | Requires |
|---------|------|-------|----------|
| **local** (default) | ✓ | ✓ | Nothing |
| **1password** | ✓ | ✓ | `op` CLI |
| **bitwarden** | ✓ | — | `bw` CLI |
| **env** | ✓ | — | Nothing |
| **aws** | ✓ | ✓ | `aws` CLI |
| **gcp** | ✓ | ✓ | `gcloud` CLI |
| **azure** | ✓ | ✓ | `az` CLI |

## Keyblind vs Cloak

| | Keyblind | Cloak |
|------|----------|-------|
| **Protocol** | MCP (all editors) | VS Code extension only |
| **Storage** | AES-256-GCM SQLite | AES-256-GCM file |
| **Backends** | Local, 1Password, Bitwarden, Env | Local only |
| **Sandbox** | Deterministic HMAC fakes | AES-256-GCM encrypted |
| **Touch ID** | ✓ (macOS biometric gate) | ✓ |
| **CI/CD** | `keyblind run` for env injection | — |
| **Network** | Zero (fully local) | Zero |
| **License** | MIT | Proprietary |
| **Free tier** | ✓ (5 secrets) | ✓ |
| **Pro** | $79/year (unlimited) | — |

## Security

- **AES-256-GCM** encryption with PBKDF2 key derivation (600K iterations)
- **Machine-identity-bound key** — encryption key XOR-wrapped with machine fingerprint
- **Zero network, zero telemetry** — no cloud, no accounts, no analytics
- **Vault stored at `~/.keyblind/`** with `0700` permissions
- **Deterministic sandbox fakes** using HMAC-SHA256 per project + key name

## CLI Reference

```
keyblind init                 Initialize the encrypted vault
keyblind set <name>           Store a secret (value from stdin)
keyblind set <name> -         Store a secret (prompts securely)
keyblind get <name>           Resolve and print a secret
keyblind list                 List all stored secrets
keyblind delete <name>        Delete a secret
keyblind sandbox [.env]       Replace .env with deterministic fakes
keyblind unsandbox [.env]     Restore real .env values
keyblind run <command...>     Run command with secrets as env vars
keyblind start                Start MCP server (for AI agents)
keyblind backends             List available backends
keyblind backend <name>       Switch backend
keyblind activate <key>       Activate a Pro/Team license
keyblind deactivate           Remove current license
keyblind status               Show license and vault status
keyblind audit                Show secret resolution audit log
keyblind check --expired      List secrets past expiry
keyblind rotate <name>        Update a secret value
keyblind team init [path]     Create a shared team vault
keyblind team push <name>     Push a secret to team vault
keyblind team pull            Pull secrets from team vault
keyblind team list            List secrets in team vault
```

## Development

```bash
git clone https://github.com/aarifmms/keyblind.git
cd keyblind
npm install
npm run build       # Compile TypeScript
npm test            # Run tests
npm run dev         # Watch mode
```

## License

MIT
