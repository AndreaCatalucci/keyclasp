# CLI Command Reference

## Vault Management

| Command | Description |
|---------|-------------|
| `keyclasp init` | Initialize a new vault (passphrase wrap, or empty for machine-only) |
| `keyclasp set <name>` | Store a secret (reads value from stdin) |
| `keyclasp set <name> -` | Store a secret (prompts securely) |
| `keyclasp get <name>` | Retrieve a secret after platform operator authorization |
| `keyclasp list` | List secret names in the resolved scope |
| `keyclasp list --all` | List project/environment/name triples vault-wide |
| `keyclasp delete <name>` | Delete a secret |
| `keyclasp status` | Show vault mode, effective authorization state, location, and secret count without unlocking or decrypting values |
| `keyclasp projects` | List distinct project names in use |
| `keyclasp environments` | List distinct environment names in use |

`keyclasp set` overwrites an existing name, so it doubles as an update/rotate command.

A passphrase vault is locked in each new process until you enter the wrap passphrase in a TTY. Non-TTY `set` / `run --env` fail locked instead of reading the passphrase from a pipe. `list`, `delete`, and `rename` still work while locked. `status` is metadata-only and exits 0 without proving that a value can be decrypted or injected. Machine-only vaults do not prompt for effectively unlocked named runs. Old XOR key files are refused; migrate with `scripts/migrate-vault-key-wrap.mjs` from a clone of this repo.

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
keyclasp run --project myapp --environment prod --env API_KEY -- npm test
keyclasp run --project myapp --environment prod --env HELLO:WORLD -- npm test
keyclasp run --project myapp --environment prod -- npm start  # Broad operator-only run
```

`env`, `printenv`, and `export` are blocked by default because they dump injected secrets. `--allow-unsafe` disables that preflight and output leak protection; it does not bypass operator authentication.

`--env SOURCE[:TARGET]` (repeatable) restricts injection to specific secrets and can rename them for the child process. A named run uses normal vault-mode behavior when every selected secret is effectively unlocked. If any selected secret is locked, the complete named run requires platform operator authorization. Coding agents must always use explicit mappings.

Supplying `--env` without a value, using a malformed mapping, targeting the same child variable twice, or naming a missing secret fails before child launch. Keyclasp never treats an invalid explicit selection as permission to inject the whole scope.

With no `--env`, `keyclasp run` requests every stored secret in the resolved scope and always requires operator authorization, even when the scope is empty. macOS requires Touch ID and then the normal passphrase unlock when one exists. Linux requires one non-empty vault-passphrase entry that both authorizes and unlocks; Linux machine-only fails closed. `--allow-unsafe` disables output safeguards for that invocation but never bypasses authorization.

## `keyclasp lock|unlock`

```bash
keyclasp lock --project myapp
keyclasp lock --environment prod
keyclasp lock --project myapp --environment prod
keyclasp unlock --project myapp --environment prod API_KEY
```

Lock rules are authenticated and bound to the vault identity. Each command requires at least one explicit scope flag; a positional secret requires both. Omitting the secret applies the rule to all existing and future secrets matching the supplied scope. Resolution prefers exact secret, exact project/environment, project-only or environment-only, then unlocked. Locked wins equal-specificity conflicts; a more-specific unlock overrides a broader lock. Both mutations require operator authorization. `unlock` changes only policy—it never changes passphrase/machine custody or rewrites vault mode.

## `keyclasp backup create|restore`

```bash
keyclasp backup create /secure/path/keyclasp-backup
keyclasp backup restore /secure/path/keyclasp-backup
```

Both operations require platform operator authorization. Create refuses an existing destination and atomically publishes a consistent SQLite snapshot, its matching key file, authenticated authorization policy, and a data-key-authenticated manifest with owner-only permissions. Linux uses one live-vault passphrase prompt for create and one backup-passphrase prompt for restore; machine-only Linux fails closed. Restore verifies every file, vault identity, mode, policy generation, and manifest before replacing live state. A durable journal and lifecycle lock make interruption recoverable.

If backup creation fails before publication, Keyclasp removes the incomplete staging directory. If the destination was renamed into place but syncing its parent directory fails, Keyclasp reports that durability is indeterminate and leaves the destination for inspection; verify it before deciding whether to keep it. Restore keeps an authenticated journal until rollback or post-commit cleanup is durable, so the next Keyclasp command can finish the recorded operation.

Rename cannot move an effectively locked secret. Add a sufficiently specific unlock rule first, perform the rename, then add the intended destination rule. Broader source rules remain in force for future matching secrets.

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
