# CLI Command Reference

## Vault Management

| Command | Description |
|---------|-------------|
| `keyclasp init` | Initialize a new vault |
| `keyclasp set <name>` | Store a secret (reads value from stdin) |
| `keyclasp set <name> -` | Store a secret (prompts securely) |
| `keyclasp get <name>` | Retrieve a secret |
| `keyclasp list` | List secret names in the resolved scope |
| `keyclasp list --all` | List project/environment/name triples vault-wide |
| `keyclasp delete <name>` | Delete a secret |
| `keyclasp status` | Show vault location, secret count, and decryptability check |
| `keyclasp projects` | List distinct project names in use |
| `keyclasp environments` | List distinct environment names in use |

`keyclasp set` overwrites an existing name, so it doubles as an update/rotate command.

## Projects and environments

Secrets are keyed by `(project, environment, name)`. Secret operations accept `--project`/`-p` and `--environment`/`-E`. Each field resolves independently in this order:

1. Explicit command flag
2. `KEYCLASP_PROJECT` or `KEYCLASP_ENVIRONMENT`
3. The context saved by `keyclasp use`
4. `default`

```bash
keyclasp set DATABASE_URL - --project myapp --environment prod
keyclasp get DATABASE_URL --project myapp --environment prod
keyclasp list --project myapp --environment prod
keyclasp status --project myapp --environment prod
```

Passing only `--project` to `list` shows every environment in that project. Passing only `--environment` shows that environment across projects. Scripts and coding agents should pass both flags explicitly so shared context cannot change their scope.

`keyclasp use <project> <environment>` saves an interactive convenience context. Clear it with `keyclasp use --clear`. Coding agents should not use persisted context.

## Rename scopes

Renames are atomic and abort without changes if the destination already contains any colliding secret name.

```bash
keyclasp rename --project OLD --to-project NEW
keyclasp rename --project APP --environment OLD --to-environment NEW
keyclasp rename --all-projects --environment OLD --to-environment NEW
keyclasp rename --project APP --environment ENV --to-project NEW_APP --to-environment NEW_ENV
```

## Bulk delete

Bulk deletion has no non-interactive bypass. It requires a TTY and typed project or environment confirmation. If the selected scope changes while the prompt is open, Keyclasp aborts so newly added secrets are not deleted unseen.

```bash
keyclasp delete --bulk --project APP
keyclasp delete --bulk --project APP --environment ENV
keyclasp delete --bulk --environment ENV --all-projects
```

## Run with Secrets

```bash
keyclasp run --project myapp --environment prod -- npm start
keyclasp run --project myapp --environment prod --env HELLO:WORLD -- npm test
keyclasp run --project myapp --environment prod --allow-unsafe -- env
```

By default, `keyclasp run` injects every stored secret in the resolved scope under its own name. `--env SOURCE[:TARGET]` (repeatable) restricts injection to specific secrets and can rename them for the child process. `--allow-unsafe` disables command preflight and output leak protection for that invocation.

Use `--` before the child command when possible. Separator-free legacy forms remain supported; once the child command begins, its arguments are preserved even when they are named `--project`, `-p`, `--environment`, or `-E`.

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
