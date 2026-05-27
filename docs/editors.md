# MCP Server Configuration by Editor

Keyblind uses the MCP stdio transport — it works with any editor that speaks Model Context Protocol.
The configuration format is standardized: a JSON file with a command and args.

## Universal Config (`.mcp.json`)

Most modern editors support a `.mcp.json` at your project root:

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

With biometric gate (requires Touch ID before each session):

```json
{
  "mcpServers": {
    "keyblind": {
      "command": "npx",
      "args": ["keyblind", "start", "--biometric"]
    }
  }
}
```

> **Note**: If using `--biometric`, run `keyblind unlock` first to authenticate and create a session.

## Editor-Specific Configurations

### Claude Code

**File**: `.mcp.json` (project root) or `~/.claude/settings.json`

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

Or via Claude Code CLI:
```bash
claude mcp add keyblind -- npx keyblind start
```

### Cursor

**File**: `.cursor/mcp.json` (project root)

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

After creating the file, Cursor will show "New MCP server detected" — click **Enable**. MCP tools only work in **Agent mode** (Cmd+I then select "Agent").

### GitHub Copilot

**File**: `.vscode/mcp.json` (project root) or VS Code `settings.json`

**Option A — Project-level** (`.vscode/mcp.json`):
```json
{
  "servers": {
    "keyblind": {
      "command": "npx",
      "args": ["keyblind", "start"]
    }
  }
}
```

**Option B — VS Code Settings** (`settings.json`):
```json
{
  "chat.mcp.servers": {
    "keyblind": {
      "command": "npx",
      "args": ["keyblind", "start"]
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
      "command": "npx",
      "args": ["keyblind", "start"]
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
      "command": "npx",
      "args": ["keyblind", "start"]
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
      "command": "npx",
      "args": ["keyblind", "start"]
    }
  }
}
```

## Troubleshooting

**Server not appearing?**
1. Verify Keyblind is initialized: `keyblind list`
2. Check the config file path matches your editor
3. Restart the editor after adding the config
4. Look for error logs in the editor's output panel

**"keyblind: command not found"?**
- Use `npx keyblind` instead of `keyblind` in the command
- Or install globally: `npm install -g keyblind`

**Biometric gate not working?**
- macOS only — requires Touch ID hardware
- Run `keyblind unlock` first to create a session
- Sessions expire after 15 minutes

**Project vaults?**
Add `--project` to isolate secrets per project:
```json
{
  "args": ["keyblind", "start", "--project", "my-project"]
}
```
