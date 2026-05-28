# Getting Started

## Installation

```bash
# npm (recommended)
npm install -g keyblind

# Homebrew (macOS)
brew install keyblind

# Quick run (no install)
npx keyblind init
```

## Initialize Your Vault

```bash
keyblind init
```

You'll be prompted to create a passphrase. This passphrase encrypts your vault. **Do not lose it** — there is no recovery mechanism.

## Store Your First Secret

```bash
keyblind set OPENAI_API_KEY
# Paste your key and press Ctrl+D
```

Or pipe it in:

```bash
echo "sk-abc123..." | keyblind set OPENAI_API_KEY
```

## Use with Claude Code

Add to your `.mcp.json`:

```json
{
  "mcpServers": {
    "keyblind": {
      "command": "npx",
      "args": ["-y", "keyblind", "start"]
    }
  }
}
```

Then in Claude Code, ask for the secret:

```
> Read my OPENAI_API_KEY from keyblind
```

Keyblind resolves it at runtime — the plaintext never appears in the conversation transcript.

## Use with Cursor / Windsurf / Cline / Zed

Same MCP configuration. See [MCP Integration](./mcp-integration.md) for editor-specific setup.

## Sandbox Your .env

```bash
# Replace real values with deterministic fakes
keyblind sandbox

# Restore real values when you need them
keyblind unsandbox
```

The fakes are HMAC-SHA256 derived — same input always produces same output, so git diffs stay clean.
