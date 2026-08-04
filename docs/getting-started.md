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
keyclasp set OPENAI_API_KEY -
# Paste the value, then press Ctrl+D
```

Confirm that the vault contains the name without printing its value:

```bash
keyclasp list
keyclasp status
```

## Run Commands With Secrets

```bash
keyclasp run -- npm test
keyclasp run -- npm start
```

Keyclasp injects stored secrets into the child process environment. It blocks obvious environment-dump commands by default and watches stdout and stderr for injected values. If it detects a leak, it redacts the value and terminates the child process.

When a command expects another variable name:

```bash
keyclasp run --env OPENAI_API_KEY:AI_TOKEN -- npm test
```

Or restrict injection to only what's needed:

```bash
keyclasp run --env OPENAI_API_KEY -- npm test
```

## Next Steps

- [CLI command reference](commands.md)
- [Recipes](recipes.md)
- [Security design](security.md)
- [FAQ](faq.md)
