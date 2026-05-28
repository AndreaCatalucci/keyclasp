**Title:** Show HN — Keyblind: An MCP Server That Blinds AI to Your API Keys

**URL:** https://github.com/aarifmms/keyblind

---

Your `.env` file has API keys, passwords, and tokens. Every AI coding tool (Claude Code, Cursor, Copilot) reads it. When they do, those secrets land in conversation transcripts — sometimes indexed by search engines forever. Researchers found 100,000+ exposed secrets in LLM transcripts last year.

Keyblind solves this. It's an MCP server that encrypts your secrets and resolves them at runtime. The AI agent never sees the real value.

**The sandbox trick:**

```
# Real .env
OPENAI_API_KEY=sk-proj-abc123xyz
DATABASE_URL=postgresql://user:pass@localhost/db

# After `keyblind sandbox`
OPENAI_API_KEY=sandbox_f4e2a9b1c3d5_OPENAI_API_KEY
DATABASE_URL=sandbox_a1b2c3d4e5f6_DATABASE_URL
```

Same fakes every time (deterministic HMAC), so git diffs stay clean. AI agents see fakes. `keyblind run -- npm start` injects real values as env vars. `keyblind unsandbox` restores everything.

**Works everywhere.** One `.mcp.json` file. Claude Code, Cursor, Copilot, Windsurf, Cline, Zed — any editor that speaks MCP.

**Seven backends:** Local vault (AES-256-GCM), 1Password, Bitwarden, AWS/GCP/Azure secret managers, env vars. Mix and match.

**Zero network, zero telemetry, zero accounts.** Fully local. Encryption key bound to your machine — copy the vault to another machine, it won't decrypt.

**Comparison:** Cloak (launched 2 days before us) is VS Code/Cursor only. Keyblind is protocol-native — MCP support means every editor works today and tomorrow.

```bash
npm install -g keyblind
keyblind init
echo "sk-your-key" | keyblind set OPENAI_API_KEY
keyblind sandbox
```

MIT licensed. Built with TypeScript, SQLite, and paranoia.

I'd love feedback from the HN community — especially on the MCP-first approach vs editor-native alternatives, and what features you'd want next.
