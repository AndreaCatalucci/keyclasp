**Title:** Keyblind Demo — Blind AI to Your API Keys (2-Minute Screencast)

**Description:** Terminal screencast + split-screen editor showing how Keyblind encrypts secrets and blinds AI agents to API keys, passwords, and tokens using MCP.

**Tags:** `demo` `screencast` `security` `privacy` `ai` `mcp` `api-keys` `devtools` `open-source`

---

**Target length:** 2 minutes | **Format:** Terminal screencast + split-screen editor

## Scene 1: The Problem (0:00–0:15)

**Visual:** Terminal showing `cat .env` with real API keys.

```
$ cat .env
OPENAI_API_KEY=sk-proj-abc123xyz890
DATABASE_URL=postgresql://admin:s3cret@db.example.com/prod
STRIPE_SECRET=sk_live_abc123def456
```

**Voiceover:** "Your `.env` file. Full of API keys, passwords, and tokens. Every AI coding tool you use can read this file. And when they do, those secrets end up in conversation transcripts — sometimes publicly indexed forever."

---

## Scene 2: Install & Init (0:15–0:30)

**Visual:** Terminal commands with clean output.

```
$ npm install -g keyblind
$ keyblind init
Enter vault passphrase (or empty for machine-only key):
🔑 Keyblind vault created at ~/.keyblind/
```

**Voiceover:** "Keyblind is an MCP server that encrypts your secrets and resolves them at runtime — so AI agents never see the real values. Install it, initialize a vault, and you're ready."

---

## Scene 3: Store Secrets (0:30–0:45)

**Visual:** Piping secrets into the vault.

```
$ echo "sk-proj-abc123xyz890" | keyblind set OPENAI_API_KEY
Stored "OPENAI_API_KEY"

$ keyblind set DATABASE_URL -
Enter value for DATABASE_URL: ******
Stored "DATABASE_URL"

$ keyblind set STRIPE_SECRET -
Enter value for STRIPE_SECRET: ******
Stored "STRIPE_SECRET"

$ keyblind list
  - DATABASE_URL
  - OPENAI_API_KEY
  - STRIPE_SECRET
```

**Voiceover:** "Store your secrets in the encrypted vault. Pipe them in, or use the secure prompt. The vault is AES-256-GCM encrypted with a key bound to your machine."

---

## Scene 4: Sandbox (0:45–1:05)

**Visual:** Side-by-side terminal showing before/after of .env.

```
$ keyblind sandbox
Sandboxed 3 value(s) in .env:
  - DATABASE_URL → fake (real value backed up to vault)
  - OPENAI_API_KEY → fake (real value backed up to vault)
  - STRIPE_SECRET → fake (real value backed up to vault)

$ cat .env
OPENAI_API_KEY=sandbox_a3f2e1b4c5d6_OPENAI_API_KEY
DATABASE_URL=sandbox_b7c8d9e0f1a2_DATABASE_URL
STRIPE_SECRET=sandbox_c3d4e5f6a7b8_STRIPE_SECRET
```

**Voiceover:** "Now run `keyblind sandbox`. Every real value is replaced with a deterministic fake — same fake every time, so your git diffs stay clean. The real values are encrypted and stored in the vault."

---

## Scene 5: AI Agent Reads .env (1:05–1:25)

**Visual:** Split screen — left side shows AI agent reading .env, right side shows vault stays encrypted.

**Left side (editor):** AI agent reads `.env` — sees only sandbox fakes.
**Right side (terminal):** `keyblind get OPENAI_API_KEY` returns real value (never shown to AI).

```
# AI agent reads .env — sees only fakes:
OPENAI_API_KEY=sandbox_a3f2e1b4c5d6_OPENAI_API_KEY

# But you can still use real values:
$ keyblind run -- npm test
# ↑ injects real secrets as env vars for this command only
```

**Voiceover:** "When an AI agent reads your `.env`, it only sees the fakes. But when your code runs, Keyblind injects the real values as environment variables. Your secrets work. Your AI doesn't see them."

---

## Scene 6: Unsandbox & Restore (1:25–1:40)

**Visual:** Restoring real values.

```
$ keyblind unsandbox
Restored 3 value(s) in .env:
  - DATABASE_URL → real
  - OPENAI_API_KEY → real
  - STRIPE_SECRET → real
```

**Voiceover:** "When you need the real values back, `keyblind unsandbox` restores them instantly. Sandbox before you code. Unsandbox when you're done working with AI."

---

## Scene 7: TOTP & Sharing (1:40–1:55)

**Visual:** Terminal showing 2FA code generation and secret sharing.

```
$ keyblind totp code github
003486  (rotates in 22s)

$ keyblind share DATABASE_URL --ttl 1h --max-views 1
Share link for "DATABASE_URL" (expires in 1h):
https://keyblind.dev/share#v1.abc.def...
```

**Voiceover:** "Keyblind also handles 2FA codes and secure secret sharing. Generate TOTP codes for any service. Or share a secret with a teammate — encrypted in the URL fragment so it never touches a server."

---

## Scene 8: MCP Server (1:55–2:10)

**Visual:** Show `.mcp.json` config file and editor recognizing the MCP server.

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

**Voiceover:** "Keyblind works with every AI editor — Claude Code, Cursor, Copilot, Windsurf, Cline, Zed. One config file. Every tool. Your secrets stay secret."

---

## Scene 9: Outro (2:10–2:15)

**Visual:** GitHub repo README, npm badge, MIT license.

```
npm install -g keyblind
```

**Voiceover:** "Keyblind is open source, MIT licensed, zero network, zero telemetry. Install it today at github.com/AndreaCatalucci/keyblind."

---

## Recording Tips

| Tip | Detail |
|-----|--------|
| **Terminal** | Use a clean theme (e.g., Dracula, Nord). Increase font size for readability. |
| **Typing** | Pre-type commands and execute them — don't type live. Use `;` chaining for pace. |
| **Editor** | Show VS Code or Cursor with `.env` open. Highlight the sandboxed values. |
| **Screen recorder** | Use OBS (free) or Screen Studio (Mac, paid). Record at 1080p 60fps. |
| **Audio** | Use a decent mic. Record voiceover separately, not during screencast. |
| **Length** | Keep under 2.5 minutes. Cut mercilessly. Speed up non-critical sections 1.5x. |

## Commands to Pre-Run Before Recording

```bash
# Clean state
rm -f .env
rm -rf ~/.keyblind/

# Setup
cat > .env << 'EOF'
OPENAI_API_KEY=sk-proj-abc123xyz890
DATABASE_URL=postgresql://admin:s3cret@db.example.com/prod
STRIPE_SECRET=sk_live_abc123def456
EOF

npm install -g keyblind
keyblind init  # press enter for machine-only key

echo "sk-proj-abc123xyz890" | keyblind set OPENAI_API_KEY
echo "postgresql://admin:s3cret@db.example.com/prod" | keyblind set DATABASE_URL
echo "sk_live_abc123def456" | keyblind set STRIPE_SECRET

# Pre-store TOTP for demo
keyblind totp set github "otpauth://totp/GitHub:demo-user?secret=JBSWY3DPEHPK3PXP&issuer=GitHub"
```
