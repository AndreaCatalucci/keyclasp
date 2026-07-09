# CLI Command Reference

## Vault Management

| Command | Description |
|---------|-------------|
| `keyblind init` | Initialize a new vault |
| `keyblind set <name>` | Store a secret (reads value from stdin) |
| `keyblind set <name> -` | Store a secret (prompts securely) |
| `keyblind get <name>` | Retrieve a secret |
| `keyblind list` | List all secret names |
| `keyblind delete <name>` | Delete a secret |
| `keyblind generate <name>` | Generate a strong random secret |
| `keyblind rotate <name>` | Update a secret value |

## MCP Setup

```bash
keyblind setup-mcp              # Auto-configure Claude Code MCP (one command)
```

Runs `claude mcp add --scope user keyblind -- keyblind start`. Works from any directory.

## Import / Export

```bash
keyblind import .env            # Import all vars from .env
keyblind export --json          # Export vault as encrypted JSON
keyblind export --env           # Export user-facing secrets as .env format
```

## Sandbox

```bash
keyblind sandbox [.env]         # Replace .env with HMAC deterministic fakes
keyblind unsandbox [.env]       # Restore real values
```

## TOTP / 2FA

```bash
keyblind totp set <name> <uri>  # Store a TOTP config from otpauth:// URI
keyblind totp code <name>       # Generate current 6 or 8 digit code
keyblind totp list              # List all TOTP configurations
keyblind totp delete <name>     # Delete a TOTP config
```

## Secret Sharing

```bash
keyblind share <name> --ttl 24h --max-views 1
keyblind receive <url-or-fragment>
```

The secret is encrypted into the URL fragment — never sent to any server.

## Server

```bash
keyblind start                  # MCP server (stdio — for AI agents)
keyblind start --biometric      # Require a 15-minute biometric session
keyblind start --biometric-every-time  # Require biometrics for every secret access
```

## Run with Secrets

```bash
keyblind run -- npm start       # Run command with all secrets as env vars and guarded output
keyblind run -- npm test        # Secrets injected; detected output leaks are redacted and terminated
keyblind run --allow-unsafe -- env  # Disable preflight and output leak protection for this command
```

## Versioning & History

```bash
keyblind history <name>         # View secret version history
keyblind rollback <name>        # Restore previous version
keyblind check --expired        # List secrets past expiry
keyblind expiring               # List secrets expiring within 30 days
```

## Sync

```bash
keyblind sync export            # Export encrypted sync bundle
keyblind sync import <bundle>   # Import encrypted sync bundle
keyblind migrate --from local --to aws  # Migrate secrets between backends
```

## Utilities

```bash
keyblind doctor                 # 9-point health check
keyblind config <key> <val>     # Set config (backend, projectName, expiryDays, autoSandbox)
keyblind config                 # Show current config
keyblind backends               # List backends with availability
keyblind completions [bash|zsh|fish]  # Generate shell completions
keyblind install-hook           # Install pre-commit hook for secret detection
keyblind watch [.env]           # Watch .env and auto-sandbox on change
keyblind unlock                 # Touch ID authentication
```

## Backends

| Backend | Description |
|---------|-------------|
| `local` | AES-256-GCM encrypted SQLite (default) |
| `1password` | 1Password CLI integration |
| `bitwarden` | Bitwarden CLI integration |
| `env` | Environment variables |
| `aws` | AWS Secrets Manager |
| `gcp` | GCP Secret Manager |
| `azure` | Azure Key Vault |

Switch backends: `keyblind config backend 1password`
