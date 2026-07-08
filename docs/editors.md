# MCP Server Configuration by Editor

Keyblind uses the MCP stdio transport — it works with any editor that speaks Model Context Protocol.

## One-Command Setup (Claude Code)

```bash
keyblind setup-mcp
```

This auto-configures Claude Code globally (`--scope user`). Works from any directory. Restart Claude Code and you're done.

Under the hood, it runs: `claude mcp add --scope user keyblind -- keyblind start`

## Manual Setup for Other Editors

### Claude Code (manual)

```bash
claude mcp add --scope user keyblind -- keyblind start
```

Or add to `.mcp.json` (project root):

```json
{
  "mcpServers": {
    "keyblind": {
      "command": "keyblind",
      "args": ["start"]
    }
  }
}
```

With biometric gate (requires Touch ID before secrets are resolved):

```bash
keyblind unlock
claude mcp add keyblind -- keyblind start --biometric
```

> Session expires after 15 minutes. No license key is required.

### Cursor

**File**: `.cursor/mcp.json` (project root)

```json
{
  "mcpServers": {
    "keyblind": {
      "command": "keyblind",
      "args": ["start"]
    }
  }
}
```

After creating the file, Cursor will show "New MCP server detected" — click **Enable**. MCP tools only work in **Agent mode** (Cmd+I then select "Agent").

### GitHub Copilot

**Option A — Project-level** (`.vscode/mcp.json`):
```json
{
  "servers": {
    "keyblind": {
      "command": "keyblind",
      "args": ["start"]
    }
  }
}
```

**Option B — VS Code Settings** (`settings.json`):
```json
{
  "chat.mcp.servers": {
    "keyblind": {
      "command": "keyblind",
      "args": ["start"]
    }
  }
}
```

### Windsurf

**File**: `.windsurf/mcp.json` (project root)

```json
{
  "mcpServers": {
    "keyblind": {
      "command": "keyblind",
      "args": ["start"]
    }
  }
}
```

### Cline

**File**: `~/.cline/mcp_settings.json` (global) or `.cline/mcp.json` (project)

```json
{
  "mcpServers": {
    "keyblind": {
      "command": "keyblind",
      "args": ["start"]
    }
  }
}
```

### Zed

**File**: `~/.zed/settings.json` (global)

```json
{
  "mcp_servers": {
    "keyblind": {
      "command": "keyblind",
      "args": ["start"]
    }
  }
}
```

## Troubleshooting

**Server not appearing?**
1. Run `keyblind setup-mcp` for automatic setup
2. Verify Keyblind is initialized: `keyblind list`
3. Check the config file path matches your editor
4. Restart the editor after adding the config

**"keyblind: command not found"?**
- Install globally: `npm install -g keyblind`
- Verify with `which keyblind`

**Biometric gate not working?**
- macOS only — requires Touch ID hardware
- Run `keyblind unlock` first to create a session
- Sessions expire after 15 minutes

**Project vaults?**
Add `--project` to isolate secrets per project:
```json
{
  "args": ["start", "--project", "my-project"]
}
```
