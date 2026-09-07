# Recipes

## CI

Create an ephemeral machine-custody vault inside the job. Supply `SECRET_API_KEY` from the CI secret store, turn off shell tracing, and remove that bootstrap variable before launching the child:

```bash
(
  set -eu
  set +x
  ci_vault=$(mktemp -d)
  export KEYCLASP_HOME="$ci_vault"
  trap 'rm -rf -- "$ci_vault"' EXIT

  keyclasp init --machine-only
  printf '%s' "$SECRET_API_KEY" | \
    keyclasp set API_KEY --project myapp --environment ci
  unset SECRET_API_KEY
  keyclasp run --project myapp --environment ci --env API_KEY -- npm test
)
```

Install `keyclasp@0.2.0-beta.2` first. An empty passphrase does not select machine custody; `--machine-only` is required. Interactive records cannot serve unattended jobs.

The CI store remains the credential source. Keyclasp does not protect against a compromised job. The child inherits the caller's environment, so remove other exported credentials too; `--env` selects vault records only. Never print or trace the bootstrap value.

## Containers

Use a supported glibc image and install the pinned beta without credentials:

```dockerfile
FROM node:24-slim
RUN npm install -g keyclasp@0.2.0-beta.2
```

At runtime, provision a new temporary vault inside the container using the CI recipe. Supply the bootstrap credential through your orchestrator's secret facility; do not put it in the Dockerfile, build arguments, image layers, or command-line literals. Apply the same install-script policy as other npm installations.

Do not mount a laptop vault into the container. Machine custody depends on the source machine identity, and copying the files does not make that vault portable. Treat each ephemeral container as a new vault and discard it at job completion. An all-interactive managed backup can move between supported machines, but it requires interactive authorization and its passphrase, so it is not an unattended provisioning recipe.

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
