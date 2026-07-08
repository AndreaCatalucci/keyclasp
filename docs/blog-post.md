**Title:** How I Built a Tool That Blinds AI to Your API Keys (And Why Every Developer Needs It)

**Description:** 100,000+ LLM conversations with exposed secrets were found indexed by search engines in 2025. Here's how to make sure yours aren't next.

**Tags:** `security` `privacy` `ai` `mcp` `api-keys` `devtools` `open-source` `typescript` `show-hn`

---

100,000+ LLM conversations with exposed secrets were found indexed by search engines in 2025. Here's how to make sure yours aren't next.
You know that sinking feeling when you realize your `.env` file just got read by an AI agent and your `OPENAI_API_KEY` is now sitting in a conversation transcript somewhere?

AI coding tools are incredible. Claude Code, Cursor, Copilot, Windsurf  they've transformed how we write software. But they have a blind spot: **they can't tell the difference between code and secrets.**

Your `.env` file looks like configuration to them. They'll read it, copy from it, suggest changes to it, and sometimes even commit it. Every time an AI agent touches a file with a secret, that secret is one copy-paste away from leaking into a conversation transcript — potentially indexed by search engines forever.

## The Problem Is Bigger Than You Think

In 2025, security researchers found over 100,000 LLM conversation transcripts containing exposed API keys, tokens, and passwords publicly indexed and searchable. These weren't sophisticated hacks. They were developers who:

- Pasted their `.env` into a chat window to debug something
- Let an AI agent "help" with environment configuration
- Committed secrets exposed by an AI suggestion
- Had their sandboxed environment read by an agent with file access

The existing solutions all had the same limitation: they were editor-specific. VS Code extensions that don't work in Cursor. CLI tools that don't integrate with AI workflows. Nothing that worked across the entire AI-assisted development ecosystem.

## Enter Keyblind: MCP-First Secret Management

Keyblind takes a different approach. Instead of being an editor extension, it's an **MCP server** a tool that any AI agent can talk to using the Model Context Protocol, the standard protocol for AI-tool communication.

Here's the architecture:

```
┌──────────┐     ┌────────────────┐     ┌─────────────────┐
│ AI Agent │ ──→ │  Keyblind MCP  │ ──→ │  Encrypted      │
│ (Claude) │     │  Server (7 tools)│   │  SQLite Vault   │
│          │ ←── │                 │ ←── │  (AES-256-GCM)  │
└──────────┘     └────────────────┘     └─────────────────┘
      ↑                                        │
      │ secret value never appears             │ secrets never
      │ in conversation transcript             │ stored in plaintext
```

When an AI agent needs an API key, it calls `resolve_secret("OPENAI_API_KEY")`. Keyblind decrypts the value and passes it back but the value goes directly to the runtime environment, **never appearing in the LLM conversation transcript.**

The AI agent never sees the actual secret. It just knows the operation succeeded.

## The Sandbox Trick

Keyblind's killer feature is `.env` sandboxing:

```bash
# Real .env
OPENAI_API_KEY=sk-proj-abc123xyz
DATABASE_URL=postgresql://user:pass@localhost/db

# After: keyblind sandbox
OPENAI_API_KEY=sandbox_f4e2a9b1c3d5_OPENAI_API_KEY
DATABASE_URL=sandbox_a1b2c3d4e5f6_DATABASE_URL
```

Your real values are encrypted and stored in the vault. The `.env` file now contains deterministic fake values **the same fake every time**, so your git diffs stay clean. AI agents reading your `.env` see only the fakes.

When you're ready to work: `keyblind unsandbox`. Real values restored instantly.

## Seven Secret Backends

Keyblind doesn't force you into a single way of managing secrets:

| Backend | What It Does |
|---------|-------------|
| **Local Vault** | AES-256-GCM encrypted SQLite on your machine |
| **1Password** | Reads/writes via `op` CLI |
| **Bitwarden** | Reads via `bw` CLI |
| **Environment** | Reads from `process.env` (read-only) |
| **AWS Secrets Manager** | Full CRUD via `aws` CLI |
| **GCP Secret Manager** | Full CRUD via `gcloud` CLI |
| **Azure Key Vault** | Full CRUD via `az` CLI |

Use your password manager. Use your cloud provider. Use the local vault. Mix and match. Keyblind abstracts the "where" so your AI tools don't care.

## Zero Network, Zero Telemetry

Keyblind is **fully local**. No cloud. No accounts. No analytics. No network calls. Your secrets never leave your machine. The encryption is AES-256-GCM with PBKDF2 key derivation at 600,000 iterations. The encryption key is XOR-wrapped with your machine identity even if someone copies your vault file to another machine, they can't decrypt it.

## Works Everywhere

Keyblind speaks MCP. Any editor or tool that supports the Model Context Protocol can use it:

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

That's it. Claude Code, Cursor, Copilot, Windsurf, Cline, Zed  one config file, zero editor-specific setup.

## The Competition

[Cloak](https://getcloak.dev) launched two days before Keyblind (May 25, 2026). It's a Rust CLI + VS Code extension that sandboxes `.env` files. Solid tool. But it's VS Code/Cursor only no MCP support, no other editors, no other backends.

Keyblind's bet is that the future of AI-secret management is **protocol-native**, not editor-native. MCP is the standard. Every editor will support it. Building on MCP means Keyblind works today and tomorrow, regardless of which AI tool wins.

## What's Next

Keyblind v0.2.0 shipped with:
- 7 MCP tools (including audit logging)
- 7 secret backends (local, cloud, and password managers)
- Secret rotation and expiry tracking
- Team vaults for shared secrets
- Biometric gate (Touch ID)

The roadmap includes secret scanning across repos, automatic secret rotation, and deeper CI/CD integration.

## Try It

```bash
npm install -g keyblind
keyblind init
echo "sk-your-key" | keyblind set OPENAI_API_KEY
keyblind sandbox
```

Your `.env` is now safe from AI agents. Your secrets are encrypted. Your peace of mind is restored.

---

**[Keyblind on GitHub](https://github.com/AndreaCatalucci/keyblind)** | **[npm](https://www.npmjs.com/package/keyblind)**

*MIT Licensed. Built with TypeScript, SQLite, and paranoia.*
Disclosure: It's MIT-licensed open source free to use. No accounts, no telemetry, no network calls. Your secrets stay on your machine.