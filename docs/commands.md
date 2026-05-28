# CLI Command Reference

## Vault Management

| Command | Description |
|---------|-------------|
| `keyblind init` | Initialize a new vault |
| `keyblind set <name>` | Store a secret (reads value from stdin) |
| `keyblind get <name>` | Retrieve a secret |
| `keyblind list` | List all secret names |
| `keyblind delete <name>` | Delete a secret |
| `keyblind generate <name>` | Generate a random secret |

## Import / Export

```bash
keyblind import .env          # Import all vars from .env
keyblind export --json        # Export vault as encrypted JSON
keyblind export --env         # Export user-facing secrets as .env format
```

## Sandbox

```bash
keyblind sandbox              # Replace .env with HMAC fakes
keyblind unsandbox            # Restore real values
```

## TOTP / 2FA

```bash
keyblind totp set my-app      # Store a TOTP URI
keyblind totp code my-app     # Generate a 6-digit code
keyblind totp list            # List all TOTP configs
keyblind totp delete my-app   # Delete a TOTP config
keyblind totp qr my-app       # Show QR code for setup
```

## Secret Sharing

```bash
keyblind share OPENAI_API_KEY --ttl 24h --max-views 1
keyblind receive <url-or-fragment>
```

The secret is encrypted into the URL fragment — never sent to any server.

## Dead Man's Switch

```bash
keyblind deadman setup --days 30 --contact email@example.com
keyblind deadman checkin
keyblind deadman status
keyblind deadman disable
```

## SSO / OIDC

```bash
keyblind sso configure --provider google --client-id X --domain example.com
keyblind sso login
keyblind sso logout
keyblind sso status
```

Supports Google, Okta, Azure AD, and generic OIDC providers.

## Server

```bash
keyblind start --http                     # Local HTTP on port 3100
keyblind start --http --port 4000         # Custom port
keyblind start --http --https --domain example.com --email admin@example.com
keyblind start --http --https --domain example.com --staging  # Test Let's Encrypt
```

## Versioning & History

```bash
keyblind history <name>                   # View secret version history
keyblind rollback <name>                  # Restore previous version
keyblind check --expired                  # List expired secrets
```

## Sync

```bash
keyblind sync export                      # Export encrypted sync bundle
keyblind sync import <bundle>             # Import encrypted sync bundle
keyblind migrate --from local --to aws    # Migrate secrets between backends
```

## Team Vaults (Pro/Team)

```bash
keyblind team init                        # Initialize team vault
keyblind team push                        # Push to team vault
keyblind team pull                        # Pull from team vault
keyblind team list                        # List team secrets
```

## License

```bash
keyblind activate <license-key>           # Activate Pro/Team license
keyblind deactivate                       # Deactivate license
keyblind status                           # Show license + vault status
```

## Utilities

```bash
keyblind doctor                           # 9-point health check
keyblind config backend <name>            # Set active backend
keyblind backends                         # List backends with availability
keyblind completions bash|zsh|fish        # Generate shell completions
keyblind install-hook                     # Install pre-commit hook
keyblind watch                            # Watch .env for changes
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
