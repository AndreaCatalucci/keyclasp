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
│          │ ←── │  (16 tools)    │ ←── │  (AES-256-GCM)  │
└──────────┘     └────────────────┘     └─────────────────┘
      ↑                                        │
      │ secret value never appears             │ secrets never
      │ in conversation transcript             │ stored in plaintext
```

## Quick Start

```bash
# 1. Install
npm i -g keyblind

# 2. Initialize your vault
keyblind init

# 3. Auto-configure MCP for Claude Code (one command)
keyblind setup-mcp

# 4. Store secrets
echo "sk-proj-abc123" | keyblind set OPENAI_API_KEY
keyblind set DATABASE_URL -    # prompts securely

# 5. Sandbox your .env (AI agents see fakes)
keyblind sandbox

# 6. Resolve a secret
keyblind get OPENAI_API_KEY

# 7. Run commands with secrets injected as env vars
keyblind run -- npm start

# 8. List all secrets (names only, values hidden)
keyblind list
```

> **That's it.** After `keyblind setup-mcp`, restart Claude Code. Then just say _"list my keyblind secrets"_ or _"use my OPENAI_API_KEY"_ — the AI agent resolves secrets at runtime without ever seeing them in the transcript.

## MCP Server

Keyblind is **MCP-first** — it works with every AI tool that speaks the Model Context Protocol (Claude Code, Cursor, Copilot, Windsurf, Cline, Zed).

### Setup (automatic)

```bash
keyblind setup-mcp
```

This auto-configures Claude Code to use Keyblind. Works from any directory. For other editors, see [editor-specific configs](docs/editors.md).

### Setup (manual)

Add a `.mcp.json` to your project root, or use `claude mcp add`:

```bash
claude mcp add --scope user keyblind -- keyblind start
```

With biometric gate (Touch ID required before secrets are resolved):

```bash
keyblind unlock                      # Authenticate first
claude mcp add keyblind -- keyblind start --biometric
```

### MCP Tools

| Tool | Description |
|------|-------------|
| `resolve_secret` | Resolve a secret at runtime (value hidden from transcript) |
| `store_secret` | Encrypt and store a secret |
| `list_secrets` | List secret names (values never revealed) |
| `delete_secret` | Delete a secret |
| `sandbox_env` | Replace `.env` values with deterministic fakes |
| `unsandbox_env` | Restore real `.env` values from vault |
| `audit_log` | View secret resolution audit trail |
| `totp_code` | Generate a TOTP 2FA code for a stored config |
| `totp_store` | Store a TOTP configuration from otpauth:// URI |
| `totp_list` | List all stored TOTP configurations |
| `totp_delete` | Delete a TOTP configuration |
| `create_share_link` | Create encrypted, expiring share link for a secret |
| `receive_share` | Receive and decrypt a shared secret |

## Browser Extension

The **Keyblind Chrome Extension** detects and blocks secrets from being pasted into AI chat interfaces (Claude.ai, ChatGPT, Copilot).

[![Chrome Web Store](https://img.shields.io/badge/Chrome_Web_Store-Coming_Soon-blue)]()

Features:
- Detects 12+ API key formats (OpenAI, GitHub, Stripe, AWS, etc.)
- Intercepts paste events on AI chat sites
- Warning banner when secrets are detected
- Popup with vault connection status

Located in `browser-extension/`. Load as unpacked extension from `chrome://extensions`.

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
keyblind setup-mcp            Auto-configure MCP for Claude Code
keyblind sandbox [.env]       Replace .env with deterministic fakes
keyblind unsandbox [.env]     Restore real .env values
keyblind run <command...>     Run command with secrets as env vars
keyblind start                Start MCP server (stdio — for AI agents)
keyblind start --biometric    Start MCP server with biometric requirement
keyblind backends             List available backends
keyblind backend <name>       Switch backend
keyblind status               Show vault status
keyblind audit                Show secret resolution audit log
keyblind check --expired      List secrets past expiry
keyblind rotate <name>        Update a secret value
keyblind totp set <name>      Store TOTP 2FA config
keyblind totp code <name>     Generate current TOTP code
keyblind totp list            List all TOTP configs
keyblind totp delete <name>   Delete a TOTP config
keyblind share <name>         Create encrypted share link
keyblind receive <url>        Receive a shared secret
keyblind doctor               Run vault health check
keyblind generate <name>      Generate a strong random secret
keyblind import [.env]        Bulk import from .env file
keyblind export               Export all secrets
keyblind completions [shell]  Generate shell completion script
```

## Development

```bash
git clone https://github.com/AndreaCatalucci/keyblind.git
cd keyblind
npm install
npm run build       # Compile TypeScript
npm test            # Run tests
npm run dev         # Watch mode
```

## License

MIT
