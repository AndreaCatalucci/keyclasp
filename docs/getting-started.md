# Getting Started

## Installation

```bash
npm install -g keyblind
```

## Initialize Your Vault

```bash
keyblind init
```

You'll be prompted to create a passphrase. This passphrase encrypts your vault. **Do not lose it** — there is no recovery mechanism.

## Connect to Claude Code

```bash
keyblind setup-mcp
```

This auto-configures Keyblind as an MCP server. Then restart Claude Code and you can say _"list my keyblind secrets"_ or _"use my OPENAI_API_KEY"_.

For other editors (Cursor, Copilot, Windsurf, etc.), see [Editors Guide](editors.md).

## Store Your First Secret

```bash
echo "sk-abc123..." | keyblind set OPENAI_API_KEY
```

Or type it securely:

```bash
keyblind set OPENAI_API_KEY -
# Paste your key and press Ctrl+D
```

## Use in Claude Code

After `keyblind setup-mcp` and restart, just ask naturally:

```
> list my keyblind secrets
> resolve my OPENAI_API_KEY
> store a secret called DATABASE_URL
```

Keyblind resolves secrets at runtime — the plaintext never appears in the conversation transcript. You'll see "Called keyblind (ctrl+o to expand)" instead of the actual value.

## Web Dashboard

```bash
keyblind start --http
```

Then sign in at [app.keyblind.dev](https://app.keyblind.dev) with your license key.

## Sandbox Your .env

```bash
# Replace real values with deterministic fakes
keyblind sandbox

# Restore real values when you need them
keyblind unsandbox
```

The fakes are HMAC-SHA256 derived — same input always produces same output, so git diffs stay clean.

## Next Steps

- [Full Command Reference](commands.md)
- [MCP Tools Reference](mcp-integration.md)
- [Security Model](security.md)
- [FAQ](faq.md)
