---
name: keyblind-agent
description: Use Keyblind from Codex to discover secret names and run commands with secrets injected only at the process boundary. Use when a coding task needs credentials for tests, builds, API calls, package registries, cloud CLIs, or deploys; when stored secret names must be matched to environment variables; or when a command fails because a required credential is missing.
---

# Keyblind for Codex

Use Keyblind as the boundary between Codex and plaintext credentials. Work with secret names and command output, never secret values.

## Workflow

1. Determine which environment variables the target command expects from project configuration, documentation, or its error output.
2. Confirm Keyblind is available with `command -v keyblind` when availability is unknown.
3. Discover metadata without revealing values:

   ```bash
   keyblind status
   keyblind list
   keyblind aliases
   ```

4. Match the required environment variables to the listed secret names or aliases.
5. Run the command through Keyblind.

## Choose the Injection Form

Prefer explicit `--env` mappings so the child process receives only the secrets it needs. Repeat `--env` for multiple secrets.

```bash
# Inject one secret under the same environment variable name
keyblind run --env OPENAI_API_KEY -- npm test

# Map a stored name to the environment variable expected by the command
keyblind run --env OPENAI_KEY:OPENAI_API_KEY -- npm test

# Inject several selected secrets
keyblind run --env AWS_ACCESS_KEY_ID --env AWS_SECRET_ACCESS_KEY -- aws s3 ls
```

Use the short form only when the command legitimately needs the full configured environment. With no `--env` option, Keyblind injects every stored secret and persistent alias under its own name.

```bash
keyblind run -- npm test
```

Always place Keyblind options before `--`; everything after `--` is the child command and its arguments.

## Safety Rules

- Do not run `keyblind get`, `keyblind export --env`, or any other command that prints plaintext secrets.
- Do not inspect injected values with `env`, `printenv`, shell expansion, debug logging, or equivalent commands. Verify behavior through the target command instead.
- Do not paste secret values into prompts, source files, command arguments, logs, test snapshots, commits, or summaries.
- Treat the child command as trusted code: it can read every secret injected into it. Use explicit `--env` mappings for least privilege when possible.
- Keep the default output guard enabled. It redacts detected injected values and terminates a command that prints one.
- Never add `--allow-unsafe` unless the user explicitly authorizes disabling both command preflight and output leak protection for that invocation.
- Apply the usual authorization rules to the child command. Keyblind changes how credentials reach it; it does not authorize a deployment, mutation, or other external action.

## Handle Failures

- If Keyblind is unavailable, report that installation or PATH configuration is required. Do not fall back to asking for plaintext credentials.
- If the vault is not initialized or cannot be unlocked, report the exact Keyblind error and let the user complete the interactive setup or unlock step.
- If a secret is missing, run `keyblind list` again, compare names, and report the required name. Do not invent a value or read one from an unsafe file.
- If Keyblind blocks a command as an environment dump, choose a narrower behavioral verification. Do not bypass the block.
- If output leak detection terminates the command, report the redacted failure and fix the target command's logging before retrying.
- Otherwise, preserve and report the child command's exit status and safe output as normal.
