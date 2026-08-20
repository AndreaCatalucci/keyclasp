# Recipes

Common patterns and workflows.

## CI/CD

Run the vault-backed command through `keyclasp run` instead of exporting secrets into the job environment directly:

```bash
keyclasp init <<< ""
echo "$SECRET_API_KEY" | keyclasp set SECRET_API_KEY --project myapp --environment ci
keyclasp run --project myapp --environment ci --env SECRET_API_KEY -- npm test
```

CI must `init` as machine-only **inside** the job (empty passphrase). A passphrase vault cannot unlock in a later non-TTY process. Do not mount a laptop passphrase vault into CI or a container and expect `run --env` to work.

Treat the CI job's own secret store as the source of truth; Keyclasp only narrows what the test/build process itself can see and print.

## Container Use

```dockerfile
FROM node:24-slim
RUN npm install -g keyclasp
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

Copy the vault directory (`~/.keyclasp/`) to the new machine. A passphrase vault unlocks there after you enter the wrap passphrase in a TTY (`set`, `get`, `run`, or `status` value check). A machine-only vault will not unlock on different hardware. Prefer a real passphrase during `keyclasp init` if you plan to move the vault.

Old XOR (`keyclasp:v2`) key files are refused. On the original machine, clone this repository and run `scripts/migrate-vault-key-wrap.mjs` before using a new CLI. After you confirm the new wrap, shred `.keyclasp.key.*.bak`. Those backups are still the old wrap. The script is not shipped in the published npm package.
