# Getting Started

## Install Keyclasp

```bash
npm install -g keyclasp
keyclasp init
```

Choose a strong vault passphrase and store it safely. Keyclasp cannot recover a lost passphrase.

## Store Your First Secret

Use the secure prompt so the value does not enter shell history:

```bash
keyclasp set OPENAI_API_KEY - --project myapp --environment prod
# Paste the value, then press Ctrl+D
```

Confirm that the vault contains the name without printing its value:

```bash
keyclasp list --project myapp --environment prod
keyclasp status --project myapp --environment prod
```

## Run Commands With Secrets

```bash
keyclasp run --project myapp --environment prod --env OPENAI_API_KEY -- npm test
keyclasp run --project myapp --environment prod --env OPENAI_API_KEY -- npm start
```

Keyclasp injects stored secrets into the child process environment. It blocks obvious environment-dump commands by default and watches stdout and stderr for injected values. If it detects a leak, it redacts the value and terminates the child process.

When a command expects another variable name:

```bash
keyclasp run --project myapp --environment prod --env OPENAI_API_KEY:AI_TOKEN -- npm test
```

Or restrict injection to only what's needed:

```bash
keyclasp run --project myapp --environment prod --env OPENAI_API_KEY -- npm test
```

Omitting `--env` requests whole-scope injection. That operator-only path requires a fresh macOS Touch ID approval and is unavailable on systems without macOS biometrics. Coding agents must always use explicit scope flags and explicit `--env` mappings.

## Next Steps

- [CLI command reference](commands.md)
- [Recipes](recipes.md)
- [Security design](security.md)
- [FAQ](faq.md)
