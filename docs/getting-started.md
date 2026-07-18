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

## Prepare an Existing Project

If the project already contains a real `.env`, import it before sandboxing:

```bash
keyclasp import .env
keyclasp sandbox .env
```

Sandboxing replaces real values with deterministic fakes. The project keeps the same variable names and stable fake values, so a coding agent can inspect configuration without reading credentials and repeated runs do not create noisy diffs.

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

## Restore a Sandboxed File

```bash
keyclasp unsandbox .env
```

Restore real values only for a trusted local workflow. Sandbox the file again before letting a coding agent inspect or edit the project.

## Next Steps

- [CLI command reference](commands.md)
- [Recipes](recipes.md)
- [Security design](security.md)
- [FAQ](faq.md)
