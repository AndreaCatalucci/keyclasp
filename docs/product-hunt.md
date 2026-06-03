# Product Hunt Launch — Keyblind v0.6.0

**Scheduled for:** Tuesday, June 9, 2026 — 12:01 AM PT

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
MCP-native secrets vault. Encrypt API keys, sandbox .env files with
deterministic fakes, resolve at runtime. AI agents never see real values.
16 MCP tools, 7 backends, 40+ CLI commands. Works with Claude Code,
Cursor, Copilot, Windsurf, Cline, Zed. MIT. Zero telemetry.
```

## Thumbnail

- 635x635px PNG (already generated at `demo/thumbnail.png`)
- Dark background (#0d1117), Keyblind logo, text: "Blind AI to Your Keys"

---

## Gallery Images (1270x760px — 5 images)

### Image 1: The Problem
Terminal showing `cat .env` with real API keys exposed.
Caption: "AI agents read your .env. Secrets leak into transcripts. 100K+ already found indexed."

### Image 2: Sandboxed
Terminal showing `keyblind sandbox` output with deterministic fakes.
Caption: "After sandboxing: deterministic HMAC-SHA256 fakes. Clean git diffs. Same fake every time."

### Image 3: Feature Grid
Show the full feature set: vault, sandbox, TOTP, sharing, dead man's switch, team vaults, dashboard.
Caption: "16 MCP tools, 7 backends (local, 1Password, Bitwarden, AWS, GCP, Azure, env), 40+ CLI commands."

### Image 4: Keyblind vs Cloak
Comparison table from landing page.
Caption: "Why Keyblind: MCP-native (not editor-specific), 16 tools vs 3, 7 backends vs 1, deterministic sandbox."

### Image 5: Web Dashboard
Screenshot of app.keyblind.dev showing sidebar, secrets list, and health indicator.
Caption: "Web dashboard at app.keyblind.dev. CLI pairing login. Manage secrets, TOTP, sharing, team vaults."

---

## First Comment (post immediately after launch)

```
Hey Product Hunt! I built Keyblind because AI coding tools reading .env
files terrifies me.

100,000+ LLM conversations with exposed secrets were found indexed by
search engines. Every AI editor reads your project files — including .env.

Keyblind encrypts your secrets (AES-256-GCM, machine-identity-bound key),
replaces .env values with deterministic fakes, and resolves real secrets
at runtime. The AI never sees them.

What's shipped in v0.6.0 (just published today):

- 16 MCP tools — secrets, sandbox, TOTP, secret sharing, dead man's
  switch, team vaults, SSO, audit log, HTTPS, alerts
- 7 backends — local, 1Password, Bitwarden, env, AWS, GCP, Azure
- 40+ CLI commands
- Web dashboard (app.keyblind.dev) with CLI pairing login
- Chrome extension (paste interception on AI chat sites)
- Browser auto-open on `keyblind dashboard-login`
- Terraform provider (skeleton, Go)

Key differentiator from Cloak (launched last week): Keyblind is MCP-
native — works with every AI editor, not just VS Code. 7 backends vs 1.
Deterministic sandbox vs random placeholders.

Pricing:
- Free: 5 secrets, all 7 backends, all 16 MCP tools
- Pro ($79/year): Unlimited secrets, team vaults, audit log, CI/CD,
  secret rotation, biometric gate, cloud backends
- PH2025 code = 50% off Pro first year

Stack: TypeScript, SQLite (better-sqlite3), Node.js crypto. Zero network,
zero telemetry, zero accounts. MIT licensed.

Just dogfooded Keyblind to publish itself to npm — stored the publish token
in the vault, ran `keyblind run -- npm publish`. It works.

Ask me anything!
```

---

## Launch Checklist

- [ ] Create Product Hunt account or claim maker profile at producthunt.com
- [ ] Upload thumbnail (`demo/thumbnail.png`)
- [ ] Create 5 gallery screenshots (use `demo/screenshot-*.html` or terminal screenshots)
- [ ] Fill in tagline, description, topics, URL
- [ ] Schedule for Tuesday June 9, 12:01 AM PT
- [ ] Copy first comment (ready above)
- [ ] Post first comment immediately after launch goes live
- [ ] Share on Twitter/X and LinkedIn
- [ ] Respond to every PH comment within first 4 hours (critical for ranking)
- [ ] Add "Featured on Product Hunt" badge to landing page after launch
