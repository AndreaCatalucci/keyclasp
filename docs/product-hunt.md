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
Encrypted secrets vault for coding-agent workflows. Sandbox .env files with
deterministic fakes and inject real values into guarded child processes.
Seven optional backends, one CLI, and no editor lock-in. MIT. Zero telemetry.
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
Show the core feature set: vault, sandbox, guarded execution, TOTP, sharing, and backends.
Caption: "Local-first secrets, deterministic sandboxing, and guarded runtime injection."

### Image 4: Agent Workflow
Terminal showing `keyblind init`, `keyblind sandbox`, and `keyblind run`.
Caption: "Local-first secret workflows for AI-assisted development."


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

- Guarded CLI workflows for secrets, sandboxing, TOTP, sharing, lifecycle, and audit summaries
- Local-first backends — local, 1Password, Bitwarden, env, AWS, GCP, Azure
- CLI workflows for vault setup, sandboxing, and runtime injection

Key differentiator from Cloak (launched last week): Keyblind protects the
process boundary and works independently of the editor. Seven backends vs one.
Deterministic sandbox vs random placeholders.

Availability: Free — Unlimited secrets, optional backend adapters, and the complete CLI. No accounts or payment required.

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
