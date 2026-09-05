# CLI command reference

Keyclasp `0.2.0-beta.1` supports macOS `arm64` and glibc Linux `arm64` or `x64` on Node.js 24 or 26. macOS `x64` and Windows installation and stateful commands fail closed. Every coding-agent command should pass `--project`, `--environment`, and the minimum required `--env` mappings explicitly.

## Vault and passphrase

| Command | Behavior |
|---|---|
| `keyclasp init` | Empty input creates machine-only custody; a non-empty passphrase creates machine and interactive keys |
| `keyclasp passphrase set` | Enroll the interactive key in a machine-only vault |
| `keyclasp passphrase rotate` | Rewrap the interactive key without rewriting record ciphertext |
| `keyclasp status` | Report custody counts and effective policy without loading a data key |
| `keyclasp doctor` | Report the disabled, status-only hardware adapter |

Passphrase removal is unavailable in this beta. macOS requires Touch ID before enrollment or rotation and then requests the required passphrase. Linux uses a confirmed new passphrase for first enrollment and the current passphrase for rotation.

## Scoped records

| Command | Behavior |
|---|---|
| `keyclasp set NAME` | Read a value from stdin and create or replace one scoped record |
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

macOS authorizes with Touch ID and then requests the interactive passphrase. Linux uses one passphrase entry for both authorization and unlock. A machine-only vault cannot satisfy an operator gate.

Keyclasp blocks common environment dumps and scans stdout and stderr for injected values of at least eight characters. `--allow-unsafe` disables those two safeguards for one invocation; it never bypasses authorization. The child remains trusted code and may transmit or persist a credential.

## Custody rules

```bash
keyclasp lock --project myapp
keyclasp lock --environment prod
keyclasp lock --project myapp --environment prod
keyclasp unlock --project myapp --environment prod API_KEY
keyclasp inherit --project myapp --environment prod API_KEY
```

Each command requires at least one explicit scope flag. An exact secret requires both project and environment. Rules resolve in this order: exact secret, exact project/environment, project-only or environment-only, then unlocked. Locked wins an equal-specificity project/environment conflict.

`lock` moves matching existing records into interactive custody. `unlock` moves them into machine custody. `inherit` removes the exact matching override and moves records according to the next effective rule. Each operation updates the authenticated policy, record ciphertext, custody metadata, and future-record default as one exclusive lifecycle transaction.

## Managed backup and restore

```bash
keyclasp backup create /secure/path/keyclasp-backup
keyclasp backup restore /secure/path/keyclasp-backup
```

Both commands require operator authorization. A backup contains one consistent database snapshot, the complete key bundle, authorization policy, custody inventory, and a manifest authenticated by every data-key class used by records.

- Backup creation requests only the classes present in its consistent inventory: machine-only does not prompt for an unused interactive key; mixed requests both; all-interactive requests only the interactive key. Linux machine-only management remains blocked by the platform authorization policy.
- Mixed or machine-only backups require the source machine identity and restore only on that machine.
- An all-interactive backup can restore on another supported machine with its passphrase. Restore creates a new target-machine key and keeps every record interactive.
- Emergency restore is dispatched before ordinary live-vault migration or journal recovery, so an authenticated backup can replace a damaged key, database, policy, or pending journal. No unsafe bypass is available: authorization and complete backup validation still precede live mutation.
- Healthy restore copies the exact DB/WAL/SHM state, checkpoints and validates only that transaction-owned copy, then preserves the byte-identical raw live set as rollback material before publication. Proven damaged state is quarantined as owner-only evidence. Busy or changing live files stop without replacement.
- Restore validates the published database, key classes, policy anchor, and every record before commit. Its per-operation journal makes publication, rollback, and cleanup restartable after repeated interruption.

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
