# Recipes

Common patterns and workflows.

## CI/CD

Run the vault-backed command through `keyclasp run` instead of exporting secrets into the job environment directly:

```bash
keyclasp init <<< "$VAULT_PASSPHRASE"
echo "$SECRET_API_KEY" | keyclasp set SECRET_API_KEY --project myapp --environment ci
keyclasp run --project myapp --environment ci --env SECRET_API_KEY -- npm test
```

Treat the CI job's own secret store as the source of truth; Keyclasp only narrows what the test/build process itself can see and print.

## Container Use

```dockerfile
FROM node:24-slim
RUN npm install -g github:AndreaCatalucci/keyclasp
```

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

Copy the vault directory (`~/.keyclasp/`) to the new machine, then re-run `keyclasp status` there. If the key file was generated with a non-empty passphrase, it unlocks on the new machine once the passphrase-derived key is available; a machine-only key (empty passphrase) is bound to the original machine's identity and will not unlock elsewhere. Prefer setting a real passphrase during `keyclasp init` if you plan to move the vault.
