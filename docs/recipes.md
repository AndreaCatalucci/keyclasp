# Recipes

Common patterns and workflows.

## CI/CD

Run the vault-backed command through `keyclasp run` instead of exporting secrets into the job environment directly:

```bash
keyclasp init <<< ""
echo "$SECRET_API_KEY" | keyclasp set SECRET_API_KEY --project myapp --environment ci
keyclasp run --project myapp --environment ci --env SECRET_API_KEY -- npm test
```

CI should `init` as machine-only **inside** the job (empty passphrase). Unattended jobs can use only records in machine custody; interactive-custody records require a passphrase entry in a TTY. Do not mount a laptop vault into CI or a container and assume its custody and machine binding match the job.

Treat the CI job's own secret store as the source of truth; Keyclasp only narrows what the test/build process itself can see and print.

## Container Use

```dockerfile
FROM node:24-slim
COPY keyclasp-0.2.0-beta.1.tgz /tmp/keyclasp-0.2.0-beta.1.tgz
RUN npm install -g /tmp/keyclasp-0.2.0-beta.1.tgz
```

Before publication, use only the exact candidate tarball and SHA-256 from the release-candidate receipt. After protected publication, `keyclasp@beta` may replace the local path only after the registry artifact passes the receipt integrity check.

Mount the vault at runtime instead of copying credentials into the image:

```bash
docker run --mount type=bind,source="$HOME/.keyclasp",target=/root/.keyclasp your-image \
  keyclasp run --project myapp --environment ci --env SECRET_API_KEY -- npm test
```

## Least-Privilege Injection

Prefer explicit `--env` mappings so a command only receives the secrets it actually needs:

```bash
keyclasp run --project myapp --environment prod --env SECRET_API_KEY --env DATABASE_URL -- npm test
```

## Moving a Vault to Another Machine

Create and restore a managed backup instead of copying a live `~/.keyclasp/` directory:

```bash
keyclasp backup create ./keyclasp-backup
keyclasp backup restore ./keyclasp-backup
```

The backup command snapshots the database, key bundle, and policy consistently and authenticates them during restore. Mixed-custody and machine-only backups remain bound to the source machine. Only an all-interactive backup is portable, and restore requires its managed backup passphrase. Use owner-only transport and storage for every backup.

Old XOR (`keyclasp:v2`) key files are refused. On the original machine, clone this repository and run `scripts/migrate-vault-key-wrap.mjs` before using a new CLI. After you confirm the new wrap, shred `.keyclasp.key.*.bak`. Those backups are still the old wrap. The script is not shipped in the published npm package.
