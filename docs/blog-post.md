**Title:** How I Built a Tool That Blinds AI to Your API Keys (And Why Every Developer Needs It)

**Description:** 100,000+ LLM conversations with exposed secrets were found indexed by search engines in 2025. Here's how to make sure yours aren't next.

**Tags:** `security` `privacy` `ai` `api-keys` `devtools` `open-source` `typescript` `show-hn`

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

The existing solutions often depend on a particular editor. Keyclasp instead protects the project files and commands that every coding agent works with.

## Enter Keyclasp: Guarded Secret Workflows

Keyclasp is a local encrypted vault and CLI. It replaces real `.env` values with deterministic fakes and injects credentials only into commands that need them.

Here's the architecture:

```
┌───────────────┐     ┌─────────────────┐     ┌─────────────────┐
│ Coding Agent  │ ──→ │ Sandboxed Files │     │ Encrypted Vault │
│ sees fakes    │     │ and Commands    │ ──→ │ and Backends    │
└───────────────┘     └─────────────────┘     └─────────────────┘
```

When a test, build, or development server needs credentials, run it through `keyclasp run -- <command>`. Keyclasp injects the values into that child process, blocks obvious environment dumps, and stops detected output leaks.

## The Sandbox Trick

Keyclasp's killer feature is `.env` sandboxing:

```bash
# Real .env
OPENAI_API_KEY=sk-proj-abc123xyz
DATABASE_URL=postgresql://user:pass@localhost/db

# After: keyclasp sandbox
OPENAI_API_KEY=sandbox_f4e2a9b1c3d5_OPENAI_API_KEY
DATABASE_URL=sandbox_a1b2c3d4e5f6_DATABASE_URL
```

Your real values are encrypted and stored in the vault. The `.env` file now contains deterministic fake values **the same fake every time**, so your git diffs stay clean. AI agents reading your `.env` see only the fakes.

When you're ready to work: `keyclasp unsandbox`. Real values restored instantly.

## Seven Secret Backends

Keyclasp doesn't force you into a single way of managing secrets:

| Backend | What It Does |
|---------|-------------|
| **Local Vault** | AES-256-GCM encrypted SQLite on your machine |
| **1Password** | Reads/writes via `op` CLI |
| **Bitwarden** | Reads via `bw` CLI |
| **Environment** | Reads from `process.env` (read-only) |
| **AWS Secrets Manager** | Full CRUD via `aws` CLI |
| **GCP Secret Manager** | Full CRUD via `gcloud` CLI |
| **Azure Key Vault** | Full CRUD via `az` CLI |

Use your password manager. Use your cloud provider. Use the local vault. Mix and match. Keyclasp abstracts the "where" so your AI tools don't care.

## Zero Network, Zero Telemetry

The default vault is fully local: no account, analytics, or network calls. Optional remote backends use their provider CLIs and networks. Local encryption uses AES-256-GCM with PBKDF2 key derivation at 600,000 iterations, and the key is wrapped with a machine fingerprint.

## Works With Any Coding Agent

Keyclasp protects files and commands instead of depending on an editor extension:

```bash
keyclasp import .env
keyclasp sandbox .env
keyclasp run -- npm test
```

The same workflow works whether you use Claude Code, Cursor, Copilot, Windsurf, Cline, Zed, or a terminal-only agent.

## The Competition

[Cloak](https://getcloak.dev) launched two days before Keyclasp (May 25, 2026). It's a Rust CLI and editor extension that sandboxes `.env` files. Keyclasp adds guarded command execution, secret lifecycle commands, and optional backends.

Keyclasp's bet is that the safest integration point is the process boundary: keep plaintext out of project files and inject it only into the trusted commands that need it.

## What's Next

Keyclasp v0.2.0 shipped with:
- Guarded command execution and deterministic `.env` sandboxing
- 7 secret backends (local, cloud, and password managers)
- Secret rotation and expiry tracking
- Encrypted, expiring secret sharing
- Guarded command execution with output leak detection

The roadmap includes secret scanning across repos, automatic secret rotation, and deeper CI/CD integration.

## Try It

```bash
npm install -g keyclasp
keyclasp init
echo "sk-your-key" | keyclasp set OPENAI_API_KEY
keyclasp sandbox
```

Your `.env` is now safe from AI agents. Your secrets are encrypted. Your peace of mind is restored.

---

**[Keyclasp on GitHub](https://github.com/AndreaCatalucci/keyclasp)** | **[npm](https://www.npmjs.com/package/keyclasp)**

*MIT Licensed. Built with TypeScript, SQLite, and paranoia.*
Disclosure: It's MIT-licensed open source free to use. No accounts, no telemetry, no network calls. Your secrets stay on your machine.
