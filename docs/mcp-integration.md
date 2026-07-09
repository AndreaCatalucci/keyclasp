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
| `create_alias` | Create a local alias pointer | `target: string, alias: string` |
| `list_aliases` | List alias metadata only | none |
| `delete_alias` | Delete an alias pointer | `alias: string` |
| `sandbox_env` | Sandbox .env file | `path: string?` |
| `unsandbox_env` | Restore .env file | `path: string?` |
| `audit_log` | View audit log | `limit: number?` |
| `totp_code` | Generate TOTP code | `name: string` |
| `totp_store` | Store TOTP config | `name: string, uri: string` |
| `totp_list` | List TOTP configs | none |
| `totp_delete` | Delete TOTP config | `name: string` |
| `create_share_link` | Create share link | `name: string, ttl?: string, max_views?: number` |
| `receive_share` | Receive shared secret | `fragment: string, target_name?: string` |
| `vault_status` | Safe vault status | none |
| `config_status` | Safe project config summary | none |
| `backend_status` | Backend availability summary | none |
| `capabilities` | Tool safety metadata | none |
| `recent_activity` | Redacted audit summary | `limit?: number` |
| `generate_secret` | Generate and store a secret | `name: string, length?: number, symbols?: boolean` |
| `rotate_secret` | Rotate a secret | `name: string, value?: string, length?: number, symbols?: boolean, expiresAt?: string` |
| `secret_history` | List history metadata | `name: string, limit?: number` |
| `rollback_secret` | Restore from history | `name: string, version?: number` |
| `check_expired` | List expired secret names | none |
| `expiring_soon` | List expiring secret metadata | `days?: number` |
| `set_config` | Set safe project config | `key: string, value: string|number|boolean` |
| `set_backend` | Switch active backend | `name: string` |

`resolve_secret` explicitly returns plaintext in MCP response content so the caller can use the value at runtime. When the requested name is an alias, the response may include safe alias metadata such as the requested alias and resolved target. Clients and agents must not paste the plaintext value into prompts, logs, or chat transcripts. Status, capability, alias, activity, history, expiry, and list tools return metadata only.

Alias tools manage local-vault metadata pointers only. They do not duplicate secret values, and external backend alias parity is deferred.
