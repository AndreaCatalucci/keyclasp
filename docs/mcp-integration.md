# MCP Integration

Keyblind works with every MCP-compatible AI tool.

## Claude Code

**One-command setup:**
```bash
keyblind setup-mcp
```

Or manually via `~/.claude/.mcp.json` or project `.mcp.json`:

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

## Cursor

Add to Cursor's MCP config (`~/.cursor/mcp.json`):

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

## Windsurf

Add to `~/.codeium/windsurf/mcp_config.json`:

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

## Cline (VS Code)

In Cline settings → MCP Servers, add:

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

## GitHub Copilot

Add to `.github/copilot-instructions.md`:

```markdown
Use the keyblind MCP server to resolve secrets. Never paste API keys directly.
```

Configure in VS Code settings:

```json
{
  "github.copilot.mcp": {
    "keyblind": {
      "command": "keyblind",
      "args": ["start"]
    }
  }
}
```

## Zed

Add to `~/.config/zed/mcp.json`:

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

## MCP Tools Reference

| Tool | Description | Parameters |
|------|-------------|------------|
| `resolve_secret` | Get a secret value | `name: string` |
| `store_secret` | Store a secret | `name: string, value: string` |
| `list_secrets` | List all secrets | none |
| `delete_secret` | Delete a secret | `name: string` |
| `sandbox_env` | Sandbox .env file | `path: string?` |
| `unsandbox_env` | Restore .env file | `path: string?` |
| `audit_log` | View audit log | `limit: number?` |
| `totp_code` | Generate TOTP code | `name: string` |
| `totp_store` | Store TOTP config | `name: string, uri: string` |
| `totp_list` | List TOTP configs | none |
| `totp_delete` | Delete TOTP config | `name: string` |
| `create_share_link` | Create share link | `name: string, ttl?: string, max_views?: number` |
| `receive_share` | Receive shared secret | `fragment: string, target_name?: string` |
| `deadman_status` | Check dead man's switch | none |
| `deadman_checkin` | Check in to dead man's switch | none |
| `sso_status` | Check SSO auth status | none |
