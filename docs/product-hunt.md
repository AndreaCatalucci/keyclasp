# Product Hunt Launch — Keyblind

**Scheduled for:** Tuesday or Thursday, 12:01 AM PT (PH launches start at midnight)

---

## Listing

| Field | Value |
|-------|-------|
| **Product Name** | Keyblind |
| **URL** | https://keyblind.dev |
| **Tagline** | Encrypted secrets vault that blinds AI agents to your API keys |
| **Topics** | Developer Tools, Open Source, Security, CLI, Privacy |

## Description (260 chars max)

```
AI coding tools read your .env file — and secrets leak into transcripts.
Keyblind encrypts API keys into a local AES-256-GCM vault and replaces
them with deterministic fakes. Secrets resolve at runtime. Your AI
never sees them. MCP-native, works everywhere.
```

## Thumbnail

- 635×635px PNG
- Dark background (#0d1117)
- Keyblind logo or eye/slash icon
- Text: "Blind AI to Your Keys"

---

## Gallery Images (1270×760px — 5 images)

### Image 1: The Problem — Terminal showing real .env
```
$ cat .env
OPENAI_API_KEY=sk-proj-abc123xyz890
DATABASE_URL=postgresql://admin:s3cret@db.example.com/prod
STRIPE_SECRET=sk_live_abc123def456
```
Caption: "Your .env file. AI agents read it. Secrets leak into transcripts."

### Image 2: Sandbox — Terminal showing sandboxed .env
```
$ keyblind sandbox
Sandboxed 3 value(s) in .env

$ cat .env
OPENAI_API_KEY=sandbox_a3f2e1b4c5d6_OPENAI_API_KEY
DATABASE_URL=sandbox_b7c8d9e0f1a2_DATABASE_URL
STRIPE_SECRET=sandbox_c3d4e5f6a7b8_STRIPE_SECRET
```
Caption: "After sandboxing — deterministic fakes, clean git diffs"

### Image 3: AI Safety — Split screen showing AI sees fakes
Caption: "AI agent sees fakes. Your code runs with real secrets."

### Image 4: MCP Config — Show .mcp.json
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
Caption: "Works with every MCP-compatible editor. One config file."

### Image 5: Pricing Tiers
Caption: "Free: 5 secrets. Pro: $79/year, unlimited, team vaults, audit log, CI/CD."

---

## First Comment (posted immediately after launch)

```
Hey Product Hunt! I built Keyblind after getting paranoid about AI coding
tools reading my .env files.

The problem: Every AI editor (Claude Code, Cursor, Copilot) reads your
project files. When they read .env, your API keys end up in conversation
transcripts. Researchers found 100,000+ exposed secrets in LLM logs last
year. That's terrifying.

Keyblind is my answer:

1. Store secrets encrypted — AES-256-GCM, key bound to your machine
2. Sandbox your .env — deterministic fakes replace real values
3. Run with confidence — `keyblind run -- npm start` injects real secrets

The fakes are deterministic (HMAC-SHA256) so your git diffs stay clean.
Same fake every time for the same key.

Tech stack: TypeScript, SQLite (better-sqlite3), Node.js crypto. MCP
protocol over stdio. Zero network, zero telemetry, zero accounts. MIT.

It works with Claude Code, Cursor, Copilot, Windsurf, Cline, Zed —
any editor that speaks MCP. That's the key differentiator from
editor-specific alternatives.

Pricing: Free tier (5 secrets, all backends). Pro ($79/year — unlimited
secrets, team vaults, audit log, secret rotation, CI/CD integration,
biometric gate).

I launched 2 days ago and already have production users. Would love
feedback from the PH community — especially on what Pro features you'd
prioritize and whether you'd trust an MCP server with your secrets.

Ask me anything!
```

---

## Social Shares

### Twitter/X

```
I built Keyblind — an MCP server that encrypts your API keys and blinds
AI agents to them.

AI editors read your .env. Secrets leak into transcripts. Keyblind replaces
real values with deterministic fakes. Your code runs with real secrets.
Your AI never sees them.

Open source. MIT. Zero telemetry.

keyblind.dev
```

### LinkedIn

```
I launched Keyblind on Product Hunt today.

AI coding tools read your .env file. When they do, API keys, tokens,
and passwords end up in conversation transcripts — sometimes indexed
by search engines permanently.

Keyblind encrypts your secrets into an AES-256-GCM vault and replaces them
with deterministic fakes. Your code runs with real secrets. Your AI
never sees the real values.

3 commands:
• keyblind set KEY → encrypt a secret
• keyblind sandbox → replace .env with fakes
• keyblind run -- npm start → run with real secrets injected

Open source, MIT licensed, zero network, zero telemetry.

Check it out: keyblind.dev
```

---

## Launch Checklist

- [ ] Create Product Hunt account / claim maker profile
- [ ] Upload thumbnail (635×635px, dark theme)
- [ ] Create 5 gallery screenshots (use `demo/screenshot.html` as template)
- [ ] Fill in tagline, description, topics
- [ ] Schedule for Tuesday 12:01 AM PT (or Thursday)
- [ ] Prepare first comment (copy from above)
- [ ] Line up early upvotes (friends, colleagues, Twitter followers)
- [ ] Post on Twitter/LinkedIn when live
- [ ] Respond to every comment within the first 4 hours
- [ ] Add "Product Hunt" badge to landing page after launch
