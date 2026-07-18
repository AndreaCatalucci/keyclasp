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
| `keyblind alias <target> <alias>` | Create a local alias for a secret |
| `keyblind aliases` | List aliases (metadata only) |
| `keyblind unalias <alias>` | Delete an alias |
| `keyblind generate <name>` | Generate a strong random secret |
| `keyblind rotate <name>` | Update a secret value |

Aliases are local-vault metadata pointers only; external backend alias parity is deferred. `keyblind get WORLD` can resolve a persistent alias like `WORLD -> HELLO`, but `keyblind aliases` never returns plaintext.

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

## Run with Secrets

```bash
keyblind run -- npm start       # Run command with all secrets as env vars and guarded output
keyblind run -- npm test        # Secrets injected; detected output leaks are redacted and terminated
keyblind run --env HELLO:WORLD -- printenv WORLD  # Transient per-command env mapping
keyblind run --allow-unsafe -- env  # Disable preflight and output leak protection for this command
```

By default, `keyblind run` injects canonical secret names plus persistent alias names. `--env SOURCE[:TARGET]` is only for that command invocation and does not create alias metadata.

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
keyblind version                # Show package or local/dev version
```

## Package Versioning

`package.json.version` is the publishable npm semver.
Do not bump it for local development.
Local git checkouts report a derived identity such as `0.6.0-dev+git.abc1234.dirty`; packaged or gitless installs report the plain package version.

```bash
keyblind version
npm version patch               # or minor / major for an intentional release
npm publish
npm version prerelease --preid beta
npm publish --tag beta          # deliberate prerelease channel, not latest
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
