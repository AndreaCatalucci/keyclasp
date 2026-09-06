# Operator migration and rollback runbook

Status: **prepared only; do not execute for KC-Q01.** KC-Q01 is not qualified. This runbook requires a replacement candidate with Gates A-C passed and separate authorization for installation and real-vault work.

The commands below are operator templates. Replace every angle-bracket placeholder, review the resolved paths, and keep values out of terminal arguments and logs.

## Roles and stop conditions

- The release owner supplies one qualified artifact and receipt.
- The operator owns the real vault, backup destination, default-custody decision, retained-copy inventory, and credential rotation.
- Stop on any hash mismatch, unsupported host, failed physical receipt, observable external SQLite holder, unexpected prompt, failed backup drill, failed readback, or unresolved incident evidence.
- Never rebuild at installation time or substitute a registry package for the qualified file.

## Read-only preflight

These checks do not authorize vault mutation:

```bash
uname -m
node --version
npm --version
shasum -a 256 <qualified-candidate.tgz>
stat -f '%Lp %z %N' <qualified-candidate.tgz>  # macOS
stat -c '%a %s %n' <qualified-candidate.tgz>  # Linux
keyclasp version
```

Require the receipt's exact SHA-256, a supported native host, and Node 24 or 26. Review `keyclasp status --project <project> --environment <environment>` only after authorizing metadata access to the real vault. `status` may resume pending managed lifecycle work; treat it as a vault-reading operation, not a harmless package check.

Inventory every Keyclasp process and external SQLite client. Stop them before backup or restore. The Keyclasp lifecycle lock cannot exclude a raw client that ignores the protocol.

## Authorized backup and isolated restore drill

These steps access the real vault and write an operator-owned backup. They require explicit rollout authorization and operator authentication.

1. Choose a new owner-only backup destination outside the live vault and outside automatic sharing.
2. Run:

   ```bash
   keyclasp backup create <owner-only-backup-directory>
   ```

3. Record backup path, time, custody inventory, source host class, and receipt hash. Do not record values.
4. Copy the backup to an isolated supported drill host only if its custody inventory permits that target.
5. With a new isolated `KEYCLASP_HOME`, run:

   ```bash
   KEYCLASP_HOME=<isolated-vault-directory> keyclasp backup restore <owner-only-backup-directory>
   KEYCLASP_HOME=<isolated-vault-directory> keyclasp status --project <project> --environment <environment>
   ```

6. Verify bounded metadata and synthetic canaries through trusted children. Do not print values.

The successful drill is the rollback checkpoint. Do not continue without it.

## Installation and migration

After a successful drill and a second explicit authorization:

1. Stop every Keyclasp process, coding agent using Keyclasp, and external SQLite client.
2. Recheck the candidate SHA-256 immediately before installation.
3. Install only the explicit qualified file using the operator-approved global or isolated channel. Do not use `npm install keyclasp@...` and do not publish as part of this step.
4. Confirm `keyclasp version` and the installed package/helper hashes against the receipt before opening the real vault.
5. Run an authorized scoped status check. Allow required managed migration or sanitation to finish; stop if it reports recovery required or cannot prove writer exclusion.
6. Review the preview and make one explicit default decision:

   ```bash
   keyclasp lock --default    # interactive fallback
   keyclasp unlock --default  # explicit unattended machine fallback
   ```

   The interactive fallback is the production-security default. Keeping machine fallback is an explicit weaker operational choice and must be recorded.
7. Verify scoped metadata, custody counts, pending sanitation state, and bounded trusted-child canaries. Never use `get` from an agent session.

## Rollback

Rollback is permitted only from the successful pre-install backup drill and only after the operator stops all clients.

Rollback criteria include failed migration, failed sanitation or integrity validation, helper identity failure, authorization regression, value readback mismatch, Linux process-group failure, or any mixed/unknown managed-file state.

1. Preserve the failed live directory and logs as owner-only incident evidence. Do not edit, checkpoint, or compact suspected damaged DB/WAL/SHM files.
2. Reinstall the previously approved runtime if package rollback is required.
3. Restore with the managed command:

   ```bash
   keyclasp backup restore <owner-only-backup-directory>
   ```

4. Verify bounded metadata and canaries. If restore reports busy, changing, or unknown state, stop rather than forcing replacement.
5. Record the outcome and keep failed receipts.

## Retained copies and revocation

A pre-fix live directory, filesystem snapshot, crash capture, copied backup, or child-created copy may still contain machine-decryptable ciphertext or plaintext. Live sanitation, passphrase changes, and key retirement do not revoke those copies.

- Inventory every retained pre-fix and rollback copy.
- Apply an approved retention and destruction decision.
- Rotate each provider credential when any retained or exposed copy must lose access.
- Preserve required incident evidence before destruction.

## Completion

Gate D closes only after the real target passes backup, isolated restore drill, exact-file installation, explicit default decision, migration/sanitation, status, bounded readback, rollback readiness, retained-copy disposition, and required provider rotation. Publication and registry smoke testing are separate authorized actions and must use the same qualified file.
