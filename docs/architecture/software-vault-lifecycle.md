# Software vault lifecycle

Scope: managed software-vault backup, restore, interrupted-restore recovery, and post-transition SQLite sanitization. Hardware custody and ordinary secret execution are outside this view.

Verification basis: KC-W02 working tree based on `c0d96fc9f4fc79db4da44d64d8c9e48421d24b9f`; inspected `src/cli.ts`, `src/recovery.ts`, `src/vault-files.ts`, `src/vault.ts`, `src/policy.ts`, `src/software/key-bundle.ts`, `src/lifecycle-lock.ts`, and the focused recovery, custody-sanitization, lifecycle, and authorization tests. The source check is recorded in the canonical production-readiness plan.

```mermaid
C4Container
  title Keyclasp software vault lifecycle
  Person(operator, "Operator", "Authorizes custody, backup, and emergency restore")
  Container(cli, "Keyclasp CLI", "TypeScript CLI", "Resumes pending work before dispatch and routes emergency restore before live parsing")
  Container(lock, "Lifecycle lock", "SQLite coordination DB", "Excludes other cooperating Keyclasp processes")
  Container(recovery, "Backup and recovery", "src/recovery.ts", "Authenticates backups, selects restore policy, and validates application state")
  Container(files, "Vault file authority", "src/vault-files.ts", "Classifies copies and publishes exact file sets using restartable transitions")
  Container(custody, "Custody and policy", "src/policy.ts and src/vault.ts", "Commits rules and record custody, then completes durable sanitization and key retirement")
  ContainerDb(vault, "Software vault file set", "SQLite and owner-only files", "vault.db, vault.db-wal, vault.db-shm, key bundle, policy, and journals")
  ContainerDb(backup, "Managed backup", "Owner-only directory", "Snapshot, key bundle, policy, and authenticated manifest")

  Rel(operator, cli, "Invokes and authorizes")
  Rel(cli, lock, "Acquires exclusive lock")
  Rel(cli, recovery, "Dispatches backup or live-independent restore")
  Rel(recovery, backup, "Reads, authenticates, and validates")
  Rel(recovery, files, "Requests classification, publication, rollback, and readback")
  Rel(recovery, vault, "Validates key classes, records, and policy anchors")
  Rel(files, vault, "Inventories and transitions exact DB/WAL/SHM and managed files")
  Rel(cli, custody, "Requests authorized rule or default changes and resumes pending cleanup")
  Rel(custody, files, "Requests closed SQLite checkpoint, compaction, sidecar cleanup, and validation")
  Rel(custody, vault, "Commits the pending phase, re-encrypts records, and retires obsolete machine keys")
```

The healthy-live branch first proves that no observable external process holds the SQLite files, captures an exact owner-only DB/WAL/SHM inventory, and copies that complete state into the transaction-owned staging directory. It validates the live key/database/policy relationship and checkpoints committed WAL content only in that stable copy. The raw live file set remains byte-identical until the durable publication journal exists and becomes the exact rollback set. The damaged-live branch never checkpoints the raw live database; it inventories and quarantines DB/WAL/SHM, recognized recovery files, and exact pending-transaction directories only after the backup has passed authentication and full record validation. Busy, changing, newly appearing, or operationally unreadable live files stop before publication and are never treated as damage.

Every v2 restore journal has a transaction-specific authentication key and authenticates its transaction ID, branch, pending-transaction directories, exact staged and previous hashes, and ordered operations. Its deterministic temporary journal and key are either promoted to a durable first journal or removed as recognizable orphans on restart. Staging copies into an exact transaction-owned partial path, verifies and syncs it, and then atomically publishes the staged file. A durable publication journal precedes live renames. Recovery evaluates both endpoints of every rename: an authenticated pre-state may be executed, an authenticated post-state may be recorded as complete, and a mixed or unknown state stops without mutation. Pre-commit recovery walks publication operations backward. It then persists a rollback-cleanup journal before exact unlinks; committed recovery does the same with a committed-cleanup journal. Staging cleanup is journaled too. Observed absence completes an interrupted unlink, so repeated process deaths converge on the complete prior or verified new set.

Before commit, the published database must have no attachable old WAL or SHM, match the journal's authenticated post-publication hashes, pass SQLite `quick_check`, and pass vault identity, bundle generation, key-class inventory, policy-anchor, and every-record AAD/GCM authentication. Tests additionally require `integrity_check` and synthetic canary equality. Synthetic canaries are not part of production restore admission.

A machine-to-interactive policy commit sets an authenticated `custody_sanitization_required` database phase in the same transaction as record re-encryption and the policy anchor. Success waits for the closed file set to enable and verify secure deletion, checkpoint and truncate WAL, use delete journaling, compact the database, remove explicitly named WAL/SHM sidecars, fsync, pass `integrity_check`, and authenticate every current record. An interruption leaves the database phase in place, so the next exclusive startup repeats the idempotent cleanup before ordinary dispatch. If the inventory has no machine record, a custody journal advances the bundle and database generation to a fresh machine key; recovery reconciles that commit point before the sanitization phase can clear. Partial transitions retain and revalidate the existing machine key for remaining machine records.

The authenticated sanitation version makes this a one-time upgrade gate for pre-KC-W02 and legacy-migrated vaults even when no record changes class in the triggering command. Machine-only inventories sanitize without interactive unlock. Mixed and all-interactive inventories require the interactive key for complete record validation; all-interactive legacy migration carries its supplied passphrase through cleanup and machine-key retirement in the same startup.

The lifecycle lock coordinates Keyclasp processes only. An external SQLite client that ignores the protocol can still race raw files, so operators must stop all such clients before restore. Keyclasp checks observable file holders before classification and again immediately before publication, then rechecks the exact live inventory. `SQLITE_BUSY`, an observable holder, or a file identity change fails closed.
