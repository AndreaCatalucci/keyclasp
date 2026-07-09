# Keyblind Commands For Agents

Use this reference for exact commands and MCP tool names. Keep operational output redacted unless the user explicitly asks for a value.

## Setup

```bash
keyblind init
keyblind setup-mcp
claude mcp add --scope user keyblind -- keyblind start
keyblind start
keyblind start --biometric
keyblind start --biometric-every-time
```

Use `keyblind setup-mcp` for Claude Code user-scope setup. Use `keyblind start` as the stdio MCP command for manual MCP configuration in other agents/editors.

## Safe Discovery

```bash
keyblind list
keyblind aliases
keyblind doctor
keyblind config
keyblind backends
keyblind version
```

Use these before asking for missing credentials. `keyblind list` and `keyblind aliases` expose names/metadata only. `keyblind version` exposes package or local/dev identity only.

## Store, Generate, Rotate

```bash
keyblind set <name>
keyblind set <name> -
keyblind generate <name>
keyblind rotate <name>
keyblind history <name>
keyblind rollback <name>
```

Prefer `keyblind set <name> -` when a human can enter the value into a secure prompt. Prefer `generate` or `rotate` when the agent does not need to know the value.

## Run Commands With Secrets

```bash
keyblind run -- npm test
keyblind run -- npm start
keyblind run --env OPENAI_API_KEY:AI_TOKEN -- npm test
keyblind run --allow-unsafe -- env
```

By default, `keyblind run` injects canonical secret names plus persistent aliases. `--env SOURCE:TARGET` creates a transient per-command mapping only. Avoid `--allow-unsafe` unless the user accepts disabled preflight and output leak protection.

## .env Sandboxing

```bash
keyblind import .env
keyblind sandbox .env
keyblind unsandbox .env
keyblind watch .env
keyblind install-hook
```

Use `import` before sandboxing an existing real `.env`. Use `sandbox` before letting an agent inspect or edit env files. Use `unsandbox` only for local restoration when the user asks.

## Aliases

```bash
keyblind alias <target> <alias>
keyblind aliases
keyblind unalias <alias>
```

Use aliases when a tool expects a different variable name than the canonical stored secret. Prefer `keyblind run --env SOURCE:TARGET -- <command>` for one-off mappings.

## TOTP And Sharing

```bash
keyblind totp set <name> <otpauth-uri>
keyblind totp code <name>
keyblind totp list
keyblind share <name> --ttl 24h --max-views 1
keyblind receive <url-or-fragment>
```

Use TOTP by name during authenticated workflows. Treat share URLs/fragments as sensitive handoff material.

## Backends

```bash
keyblind config backend local
keyblind config backend 1password
keyblind config backend bitwarden
keyblind config backend env
keyblind config backend aws
keyblind config backend gcp
keyblind config backend azure
keyblind migrate --from local --to aws
```

Verify backend availability with `keyblind backends` before switching. External backends may require the provider CLI/session to be configured outside the agent.

## MCP Tool Names

- `resolve_secret`: Resolve a secret at runtime.
- `store_secret`: Encrypt and store a secret.
- `list_secrets`: List secret names.
- `delete_secret`: Delete a secret.
- `create_alias`, `list_aliases`, `delete_alias`: Manage aliases.
- `sandbox_env`, `unsandbox_env`: Sandbox and restore env files.
- `audit_log`, `recent_activity`: Inspect redacted activity.
- `vault_status`, `config_status`, `backend_status`, `capabilities`: Inspect safe status.
- `totp_code`, `totp_store`, `totp_list`, `totp_delete`: Manage TOTP.
- `create_share_link`, `receive_share`: Share encrypted secrets.
- `generate_secret`, `rotate_secret`, `secret_history`, `rollback_secret`: Manage generated/rotated secrets and history.
- `check_expired`, `expiring_soon`: Inspect expiry metadata.
- `set_config`, `set_backend`: Update safe configuration.

Prefer status/list tools before value-returning tools. Use value-returning tools only for a specific local action that cannot be handled by `keyblind run`.
