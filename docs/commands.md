# CLI Command Reference

## Vault Management

| Command | Description |
|---------|-------------|
| `keyclasp init` | Initialize a new vault |
| `keyclasp set <name>` | Store a secret (reads value from stdin) |
| `keyclasp set <name> -` | Store a secret (prompts securely) |
| `keyclasp get <name>` | Retrieve a secret |
| `keyclasp list` | List all secret names |
| `keyclasp delete <name>` | Delete a secret |
| `keyclasp alias <target> <alias>` | Create a local alias for a secret |
| `keyclasp aliases` | List aliases (metadata only) |
| `keyclasp unalias <alias>` | Delete an alias |
| `keyclasp generate <name>` | Generate a strong random secret |
| `keyclasp rotate <name>` | Update a secret value |

Aliases are local-vault metadata pointers only; external backend alias parity is deferred. `keyclasp get WORLD` can resolve a persistent alias like `WORLD -> HELLO`, but `keyclasp aliases` never returns plaintext.

## Import / Export

```bash
keyclasp import .env            # Import all vars from .env
keyclasp export --json          # Export vault as encrypted JSON
keyclasp export --env           # Export user-facing secrets as .env format
```

## Sandbox

```bash
keyclasp sandbox [.env]         # Replace .env with HMAC deterministic fakes
keyclasp unsandbox [.env]       # Restore real values
```

## TOTP / 2FA

```bash
keyclasp totp set <name> <uri>  # Store a TOTP config from otpauth:// URI
keyclasp totp code <name>       # Generate current 6 or 8 digit code
keyclasp totp list              # List all TOTP configurations
keyclasp totp delete <name>     # Delete a TOTP config
```

## Secret Sharing

```bash
keyclasp share <name> --ttl 24h --max-views 1
keyclasp receive <url-or-fragment>
```

The secret is encrypted into the URL fragment — never sent to any server.

## Run with Secrets

```bash
keyclasp run -- npm start       # Run command with all secrets as env vars and guarded output
keyclasp run -- npm test        # Secrets injected; detected output leaks are redacted and terminated
keyclasp run --env HELLO:WORLD -- printenv WORLD  # Transient per-command env mapping
keyclasp run --allow-unsafe -- env  # Disable preflight and output leak protection for this command
```

By default, `keyclasp run` injects canonical secret names plus persistent alias names. `--env SOURCE[:TARGET]` is only for that command invocation and does not create alias metadata.

## Versioning & History

```bash
keyclasp history <name>         # View secret version history
keyclasp rollback <name>        # Restore previous version
keyclasp check --expired        # List secrets past expiry
keyclasp expiring               # List secrets expiring within 30 days
```

## Sync

```bash
keyclasp sync export            # Export encrypted sync bundle
keyclasp sync import <bundle>   # Import encrypted sync bundle
keyclasp migrate --from local --to aws  # Migrate secrets between backends
```

## Utilities

```bash
keyclasp doctor                 # 9-point health check
keyclasp config <key> <val>     # Set config (backend, projectName, expiryDays, autoSandbox)
keyclasp config                 # Show current config
keyclasp backends               # List backends with availability
keyclasp completions [bash|zsh|fish]  # Generate shell completions
keyclasp install-hook           # Install pre-commit hook for secret detection
keyclasp watch [.env]           # Watch .env and auto-sandbox on change
keyclasp version                # Show package or local/dev version
```

## Package Versioning

`package.json.version` is the publishable npm semver.
Do not bump it for local development.
Local git checkouts report a derived identity such as `0.6.0-dev+git.abc1234.dirty`; packaged or gitless installs report the plain package version.

```bash
keyclasp version
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

Switch backends: `keyclasp config backend 1password`
