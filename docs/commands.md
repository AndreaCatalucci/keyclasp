# CLI Command Reference

## Vault Management

| Command | Description |
|---------|-------------|
| `keyclasp init` | Initialize a new vault |
| `keyclasp set [scope] <name>` | Store a secret (reads value from stdin) |
| `keyclasp set [scope] <name> -` | Store a secret (prompts securely) |
| `keyclasp get [scope] <name>` | Retrieve a secret after macOS Touch ID approval |
| `keyclasp list [scope]` | List secret names in one scope |
| `keyclasp delete [scope] <name>` | Delete a secret from one scope |
| `keyclasp status [scope]` | Show vault location, scoped secret count, and decryptability check |

`keyclasp set` overwrites an existing name, so it doubles as an update/rotate command.

`[scope]` means `--project <name> --environment <name>`. The short forms are `-p` and `-E`; `--project=<name>` and `--environment=<name>` are also accepted. If omitted, each dimension defaults to `default` (or `KEYCLASP_PROJECT` / `KEYCLASP_ENVIRONMENT` when set). Coding agents should always pass both flags explicitly and never depend on ambient scope.

## Run with Secrets

```bash
keyclasp run --project app --environment prod --env API_KEY -- npm test
keyclasp run --project app --environment prod -- npm start  # Operator-only whole-scope injection
keyclasp run -p app -E dev --env HELLO:WORLD -- npm test
keyclasp run -p app -E dev --allow-unsafe -- env  # Disable both output safeguards
```

`--env SOURCE[:TARGET]` (repeatable) restricts injection to specific secrets and can rename them for the child process. Coding agents must always use this form.

With no `--env`, `keyclasp run` would inject every secret in the selected project/environment under its own name. Keyclasp therefore requires a fresh macOS Touch ID approval before resolving any value. The operation fails closed on non-macOS systems or when biometrics are unavailable, denied, or cancelled.

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
