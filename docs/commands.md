# CLI command reference

Keyclasp `0.2.0-beta.2` supports macOS `arm64` and glibc Linux `arm64` or `x64` on Node.js 24 or 26. macOS `x64` and Windows installation and stateful commands fail closed. Every coding-agent command should pass `--project`, `--environment`, and the minimum required `--env` mappings explicitly.

## Vault and passphrase

| Command | Behavior |
|---|---|
| `keyclasp init` | Require a non-empty passphrase and create an interactive-default dual-key vault |
| `keyclasp init --machine-only` | Explicitly create an unattended machine-default vault |
| `keyclasp passphrase set` | Enroll the interactive key in a machine-only vault |
| `keyclasp passphrase rotate` | Rewrap the interactive key without rewriting record ciphertext |
| `keyclasp status` | Report custody counts and effective policy after any required startup recovery |
| `keyclasp doctor` | Report the disabled, status-only hardware adapter |

Passphrase removal is unavailable in this beta. macOS requires Touch ID before enrollment or rotation and then requests the required passphrase. Linux uses a confirmed new passphrase for first enrollment and the current passphrase for rotation.

## Scoped records

| Command | Behavior |
|---|---|
| `keyclasp set NAME` | Read a piped value, or prompt in a terminal, and create or replace one scoped record |
| `keyclasp set NAME -` | Prompt without echoing the value |
| `keyclasp list [--all]` | List names; `--all` includes each project and environment |
| `keyclasp get NAME` | Print one value after operator authorization |
| `keyclasp delete NAME` | Delete one record |
| `keyclasp delete --bulk ...` | Delete a stable scope snapshot after typed TTY confirmation |
| `keyclasp rename ...` | Atomically move records and re-encrypt their authenticated identity |

Secrets are keyed by `(project, environment, name)`. Scope resolves from an explicit flag, `KEYCLASP_PROJECT` or `KEYCLASP_ENVIRONMENT`, persisted interactive context, then `default`. `keyclasp use PROJECT ENVIRONMENT` changes the persisted context; agents should never use it.

## Guarded run

```bash
keyclasp run --project myapp --environment prod --env API_KEY -- npm test
keyclasp run --project myapp --environment prod --env STORED:EXPECTED -- npm start
```

`--env SOURCE[:TARGET]` is repeatable. Keyclasp validates the complete selection before decrypting any record. Missing sources, malformed mappings, duplicate child variables, and invalid values fail before child launch and never widen into a broad run.

A named run is unattended when every selected record is effectively unlocked and machine-key protected. If any selected record is interactive, the complete request requires authorization and interactive-key unlock before any value is decrypted. Omitting `--env` requests the whole scope and always requires authorization.

macOS authorizes with Touch ID and requests the passphrase when interactive records are selected. Linux uses one passphrase entry for both authorization and unlock; machine-only vaults cannot satisfy that gate.

The child inherits the caller's environment in addition to selected vault values. Keyclasp blocks common environment dumps and scans stdout and stderr for injected values of at least eight characters. `--allow-unsafe` disables those two safeguards for one invocation; it never bypasses authorization. The child remains trusted code and may transmit or persist a credential.

## Custody rules

```bash
keyclasp lock --project myapp
keyclasp lock --environment prod
keyclasp lock --project myapp --environment prod
keyclasp unlock --project myapp --environment prod API_KEY
keyclasp inherit --project myapp --environment prod API_KEY
keyclasp lock --default
keyclasp unlock --default
```

Scoped commands require at least one explicit scope flag. An exact secret requires both project and environment. Rules resolve in this order: exact secret, exact project/environment, project-only or environment-only, then the vault-wide default. Locked wins an equal-specificity project/environment conflict. `lock --default` selects the interactive fallback; `unlock --default` explicitly selects the machine fallback. Upgraded vaults report `legacy machine default` until one of those authorized choices is made.

`lock` moves matching existing records into interactive custody. `unlock` moves them into machine custody. `inherit` removes the exact matching override and moves records according to the next effective rule. Default changes preview how many records move in each direction. Tightening completes only after obsolete live SQLite data is cleaned up and verified; interrupted cleanup resumes on the next command. When no machine records remain, the old machine key is retired.

## Managed backup and restore

```bash
keyclasp backup create /secure/path/keyclasp-backup
keyclasp backup restore /secure/path/keyclasp-backup
```

Both commands require operator authorization. A backup contains one consistent database snapshot, the complete key bundle, authorization policy, custody inventory, and a manifest authenticated by every data-key class used by records.

- macOS uses Touch ID; Linux needs an enrolled passphrase. Key unlock requests follow the record classes present in the backup, so unused interactive keys do not add a macOS passphrase prompt.
- Mixed or machine-only backups restore only on the source machine. An all-interactive backup can move with its passphrase; records stay interactive and receive a fresh target-machine key.
- Restore can replace a damaged vault after authorization and complete backup validation. It preserves damaged files as owner-only evidence and reports their location.
- Stop external SQLite clients first. Busy or changing live files stop restore without replacement. Restore treats the database, WAL, and SHM as a set, validates the result, and resumes interrupted publication or rollback.

The manifest authenticates one internally consistent backup; it does not prove that the backup is the newest valid copy. Retained backups and external filesystem snapshots remain usable after a live-vault lock or passphrase change. Delete them only under an explicit retention decision, and rotate provider credentials when an earlier copy must be revoked.

## Projects, environments, rename, and bulk delete

```bash
keyclasp projects
keyclasp environments
keyclasp use PROJECT ENVIRONMENT
keyclasp use --clear
keyclasp rename --project OLD --to-project NEW
keyclasp rename --project APP --environment OLD --to-environment NEW
keyclasp rename --all-projects --environment OLD --to-environment NEW
keyclasp rename --project APP --environment ENV --to-project NEW_APP --to-environment NEW_ENV
keyclasp delete --bulk --project APP --environment ENV
```

Rename aborts without changes on a destination collision. Bulk delete has no non-interactive bypass and aborts if the selected scope changes while confirmation is open.
