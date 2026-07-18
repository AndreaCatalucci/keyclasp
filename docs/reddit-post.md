**Title:** I Built a Tool That Blinds AI to Your API Keys 100K+ Leaked Conversations Last Year Alone

**Flair:** `Showcase`

**Body:**

Your `.env` file. Full of API keys, passwords, and tokens. Every AI coding tool reads it. And when they do, those secrets end up in conversation transcripts sometimes indexed by search engines forever. Security researchers found 100,000+ LLM conversations with exposed secrets in 2025.

Keyclasp is a local encrypted vault that replaces project secrets with deterministic fakes and injects real values only into guarded commands.

**How it works:**

- `keyclasp sandbox` — replaces every real value in `.env` with a deterministic fake. Same fake every time, clean git diffs.
- AI agent reads `.env` → sees only fakes.
- `keyclasp run -- npm test` — injects real secrets as env vars for that command only.
- `keyclasp unsandbox` — restores real values when you're done.

**Works everywhere:** the workflow protects files and commands, so it does not depend on a particular editor.

**Zero network, zero telemetry, zero accounts.** AES-256-GCM encrypted. Keys bound to your machine.

```bash
npm install -g keyclasp
keyclasp init
echo "sk-your-key" | keyclasp set OPENAI_API_KEY
keyclasp sandbox
```

GitHub: https://github.com/AndreaCatalucci/keyclasp

*Disclosure: I built this. MIT-licensed open source, completely free. No cloud, no analytics, no network calls. Your secrets never leave your machine.*
