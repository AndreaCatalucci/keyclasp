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
| `keyclasp status` | Show vault location, secret count, and decryptability check |

`keyclasp set` overwrites an existing name, so it doubles as an update/rotate command.

## Run with Secrets

```bash
keyclasp run -- npm start       # Run command with all secrets as env vars and guarded output
keyclasp run -- npm test        # Secrets injected; detected output leaks are redacted and terminated
keyclasp run --env HELLO:WORLD -- printenv WORLD  # Transient per-command env mapping
keyclasp run --allow-unsafe -- env  # Disable preflight and output leak protection for this command
```

By default, `keyclasp run` injects every stored secret under its own name. `--env SOURCE[:TARGET]` (repeatable) restricts injection to specific secrets and can rename them for the child process.

## Utilities

```bash
keyclasp version                # Show package or local/dev version
keyclasp help                   # Show usage
```

## Package Versioning

`package.json.version` is the publishable npm semver.
Do not bump it for local development.
Local git checkouts report a derived identity such as `1.0.0-dev+git.abc1234.dirty`; packaged or gitless installs report the plain package version.

```bash
keyclasp version
npm version patch               # or minor / major for an intentional release
npm publish
npm version prerelease --preid beta
npm publish --tag beta          # deliberate prerelease channel, not latest
```
