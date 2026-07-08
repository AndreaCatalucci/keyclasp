# Recipes

Common patterns and workflows.


## Pre-commit Hook

```bash
keyblind install-hook
```

This installs a git hook that blocks commits containing real API keys (detected via pattern matching).

## Local Container Use

```dockerfile
FROM node:24-slim
RUN npm install -g keyblind
COPY .keyblind /root/.keyblind
RUN keyblind sandbox
```

## Sharing a Secret with a Teammate

```bash
# You
keyblind share DATABASE_URL --ttl 1h --max-views 1

# Them (within 1 hour)
keyblind receive https://keyblind.dev/share#v1.abc.def
```

## Migrating from .env to Keyblind

```bash
# 1. Import existing .env
keyblind import .env

# 2. Verify everything imported
keyblind list

# 3. Sandbox the .env (replace with fakes)
keyblind sandbox

# 4. Commit the sandboxed .env
git add .env && git commit -m "Sandbox secrets with keyblind"
```

## Setting Up TOTP for a Service

```bash
# From QR code URI
keyblind totp set github "otpauth://totp/GitHub:user?secret=ABCDEFGH&issuer=GitHub"

# Generate code when needed
keyblind totp code github
```

## Multi-Machine Sync

```bash
# Machine A
keyblind sync export > bundle.enc

# Transfer bundle.enc to Machine B (USB, AirDrop, etc.)
# Machine B
keyblind sync import bundle.enc
```

The bundle is encrypted with your vault key — safe to transfer over any channel.
