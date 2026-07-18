**Title:** I Built a Tool That Prevents AI Coding Tools From Leaking Your API Keys

---

Last year, researchers found 100,000+ LLM conversation transcripts with exposed API keys, passwords, and tokens — publicly indexed by search engines.

AI coding tools like Claude Code, Cursor, and Copilot can't tell the difference between code and secrets. They read your `.env` file, copy from it, and sometimes those secrets end up in transcripts forever.

I built **Keyblind** to solve this.

It's a local encrypted vault that replaces project secrets with deterministic fakes and injects real values only into guarded commands.

**How it works:**
- `keyblind sandbox` replaces every real `.env` value with a deterministic fake
- AI agents see only fakes
- `keyblind run -- npm start` injects real secrets as env vars for that command only
- `keyblind unsandbox` restores everything when you're done

**Key features:**
- Works with every AI editor (Claude Code, Cursor, Copilot, Windsurf, Cline, Zed)
- 7 secret backends (local AES-256-GCM, 1Password, Bitwarden, AWS/GCP/Azure)
- Zero network, zero telemetry, zero accounts
- Guarded command execution with output leak detection
- Encrypted, expiring secret sharing

Open source, MIT licensed. No cloud. No accounts. Secrets stay on your machine.

```bash
npm install -g keyblind
keyblind init
echo "sk-your-key" | keyblind set OPENAI_API_KEY
keyblind sandbox
```

GitHub: https://github.com/AndreaCatalucci/keyblind

Curious to hear from developers using AI tools — how are you currently protecting your secrets? What would you want in a tool like this?
