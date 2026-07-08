**Title:** I Built a Tool That Blinds AI to Your API Keys 100K+ Leaked Conversations Last Year Alone

**Flair:** `Showcase`

**Body:**

Your `.env` file. Full of API keys, passwords, and tokens. Every AI coding tool reads it. And when they do, those secrets end up in conversation transcripts sometimes indexed by search engines forever. Security researchers found 100,000+ LLM conversations with exposed secrets in 2025.

Keyblind is an MCP server that encrypts your secrets and resolves them at runtime. AI agents never see the real values.

**How it works:**

- `keyblind sandbox` — replaces every real value in `.env` with a deterministic fake. Same fake every time, clean git diffs.
- AI agent reads `.env` → sees only fakes.
- `keyblind run -- npm test` — injects real secrets as env vars for that command only.
- `keyblind unsandbox` — restores real values when you're done.

**Works everywhere:** Claude Code, Cursor, Copilot, Windsurf, Cline, Zed one `.mcp.json` file.

**Zero network, zero telemetry, zero accounts.** AES-256-GCM encrypted. Keys bound to your machine.

```bash
npm install -g keyblind
keyblind init
echo "sk-your-key" | keyblind set OPENAI_API_KEY
keyblind sandbox
```

GitHub: https://github.com/AndreaCatalucci/keyblind

*Disclosure: I built this. MIT-licensed open source, completely free. No cloud, no analytics, no network calls. Your secrets never leave your machine.*
