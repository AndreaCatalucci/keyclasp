# Recipes

Common patterns and workflows.


## Pre-commit Hook

```bash
keyclasp install-hook
```

This installs a git hook that blocks commits containing real API keys (detected via pattern matching).

## Local Container Use

```dockerfile
FROM node:24-slim
RUN npm install -g keyclasp
```

Mount the vault at runtime instead of copying credentials into the image:

```bash
docker run --mount type=bind,source="$HOME/.keyclasp",target=/root/.keyclasp your-image \
  keyclasp run -- npm test
```

## Sharing a Secret with a Teammate

```bash
# You
keyclasp share DATABASE_URL --ttl 1h --max-views 1

# Them (within 1 hour)
keyclasp receive https://github.com/AndreaCatalucci/keyclasp#v1.abc.def
```

## Migrating from .env to Keyclasp

```bash
# 1. Import existing .env
keyclasp import .env

# 2. Verify everything imported
keyclasp list

# 3. Sandbox the .env (replace with fakes)
keyclasp sandbox

# 4. Commit the sandboxed .env
git add .env && git commit -m "Sandbox secrets with keyclasp"
```

## Setting Up TOTP for a Service

```bash
# From QR code URI
keyclasp totp set github "otpauth://totp/GitHub:user?secret=ABCDEFGH&issuer=GitHub"

# Generate code when needed
keyclasp totp code github
```

## Multi-Machine Sync

```bash
# Machine A
keyclasp sync export > bundle.enc

# Transfer bundle.enc to Machine B (USB, AirDrop, etc.)
# Machine B
keyclasp sync import bundle.enc
```

The bundle is encrypted with your vault key — safe to transfer over any channel.
