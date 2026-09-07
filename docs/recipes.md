# Local developer recipes

These recipes are for coding agents running on local developer machines.

## Select only required credentials

```bash
keyclasp run --project myapp --environment prod \
  --env API_KEY --env DATABASE_URL -- npm test
```

The child must accept those variables in the stored format. `--env SOURCE:TARGET` renames a variable; it does not convert its value.

## Moving a vault

Use a managed backup rather than copying a live vault directory:

```bash
# On the source machine:
keyclasp backup create /secure/path/keyclasp-backup
# On the destination, after transferring that complete directory securely:
keyclasp backup restore /secure/path/keyclasp-backup
```

Every record must be interactive to restore on another supported machine. Review `status`, enroll a passphrase if necessary, and lock the intended records on the source before creating the backup. `lock --default` alone does not override more-specific unlock rules. Mixed and machine-only backups require the source machine identity. Both backup commands require operator authorization; Linux machine-only management is blocked.

Stop other Keyclasp processes and external SQLite clients before restoring. Restore validates the backup before replacing live files and preserves damaged live state in a reported owner-only evidence directory. Keep that evidence until you decide its retention. After restore, check `status` and perform a named run with a dummy record prepared for this purpose.

Store and transfer backups with owner-only access. A valid backup can still be outdated. Locking the live vault or changing its passphrase cannot revoke earlier backups and snapshots; rotate credentials at their providers when those copies must lose access.

## Older key formats

Old XOR (`keyclasp:v2`) key files are refused. On the original machine, use the repository's `scripts/migrate-vault-key-wrap.mjs`; it is not included in the npm package. Keep the old-format `.bak` copies protected until you have verified the new wrap and decided their retention. Deleting a file does not guarantee erasure from snapshots or storage media.
