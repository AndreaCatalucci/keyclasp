# Getting Started

## Install Keyblind

```bash
npm install -g keyblind
keyblind init
```

Choose a strong vault passphrase and store it safely. Keyblind cannot recover a lost passphrase.

## Store Your First Secret

Use the secure prompt so the value does not enter shell history:

```bash
keyblind set OPENAI_API_KEY -
# Paste the value, then press Ctrl+D
```

Confirm that the vault contains the name without printing its value:

```bash
keyblind list
keyblind status
```

## Prepare an Existing Project

If the project already contains a real `.env`, import it before sandboxing:

```bash
keyblind import .env
keyblind sandbox .env
```

Sandboxing replaces real values with deterministic fakes. The project keeps the same variable names and stable fake values, so a coding agent can inspect configuration without reading credentials and repeated runs do not create noisy diffs.

## Run Commands With Secrets

```bash
keyblind run -- npm test
keyblind run -- npm start
```

Keyblind injects stored secrets into the child process environment. It blocks obvious environment-dump commands by default and watches stdout and stderr for injected values. If it detects a leak, it redacts the value and terminates the child process.

When a command expects another variable name:

```bash
keyblind run --env OPENAI_API_KEY:AI_TOKEN -- npm test
```

## Restore a Sandboxed File

```bash
keyblind unsandbox .env
```

Restore real values only for a trusted local workflow. Sandbox the file again before letting a coding agent inspect or edit the project.

## Next Steps

- [CLI command reference](commands.md)
- [Recipes](recipes.md)
- [Security design](security.md)
- [FAQ](faq.md)
