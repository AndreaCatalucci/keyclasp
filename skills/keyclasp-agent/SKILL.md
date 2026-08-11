---
name: keyclasp-agent
description: Use Keyclasp from Codex to discover secret names and run commands with secrets injected only at the process boundary. Use when a coding task needs credentials for tests, builds, API calls, package registries, cloud CLIs, or deploys; when stored secret names must be matched to environment variables; or when a command fails because a required credential is missing.
---

# Keyclasp for Codex

Use Keyclasp as the boundary between Codex and plaintext credentials. Work with secret names and command output, never secret values.

## Workflow

1. Determine the Keyclasp project, environment, and environment variables the target command expects from explicit user context, project configuration, documentation, or safe error output.
2. Confirm Keyclasp is available with `command -v keyclasp` when availability is unknown.
3. Discover metadata without revealing values:

   ```bash
   keyclasp status --project <project> --environment <environment>
   keyclasp list --project <project> --environment <environment>
   ```

4. Match the required environment variables to the listed secret names.
5. Run the command through Keyclasp.

## Choose the Injection Form

Prefer explicit `--env` mappings so the child process receives only the secrets it needs. Repeat `--env` for multiple secrets.

```bash
# Inject one secret under the same environment variable name
keyclasp run --project <project> --environment <environment> --env OPENAI_API_KEY -- npm test

# Map a stored name to the environment variable expected by the command
keyclasp run --project <project> --environment <environment> --env OPENAI_KEY:OPENAI_API_KEY -- npm test

# Inject several selected secrets
keyclasp run --project <project> --environment <environment> \
  --env AWS_ACCESS_KEY_ID --env AWS_SECRET_ACCESS_KEY -- aws s3 ls
```

Always pass both `--project` and `--environment`; never depend on `default`, environment variables, or another ambient scope. Never omit `--env`. With no `--env` option, Keyclasp treats the request as operator-only whole-scope injection and requires macOS Touch ID. Agents must not request or attempt to satisfy that prompt.

Always place Keyclasp options before `--`; everything after `--` is the child command and its arguments.

## Safety Rules

- Do not run `keyclasp get` or any other command that prints a plaintext secret.
- Do not run scoped commands without explicit `--project` and `--environment` flags.
- Do not run `keyclasp run` without at least one explicit `--env` mapping. Whole-scope injection is a biometric-gated operator action.
- Do not inspect injected values with `env`, `printenv`, shell expansion, debug logging, or equivalent commands. Verify behavior through the target command instead.
- Do not paste secret values into prompts, source files, command arguments, logs, test snapshots, commits, or summaries.
- Treat the child command as trusted code: it can read every secret injected into it. Use explicit `--env` mappings for least privilege when possible.
- Keep the default output guard enabled. It redacts detected injected values and terminates a command that prints one.
- Never add `--allow-unsafe` unless the user explicitly authorizes disabling both command preflight and output leak protection for that invocation.
- Apply the usual authorization rules to the child command. Keyclasp changes how credentials reach it; it does not authorize a deployment, mutation, or other external action.

## Handle Failures

- If Keyclasp is unavailable, report that installation or PATH configuration is required. Do not fall back to asking for plaintext credentials.
- If the vault is not initialized or cannot be unlocked, report the exact Keyclasp error and let the user complete the interactive setup or unlock step.
- If a secret is missing, run `keyclasp list` again with the same explicit project/environment, compare names, and report the scope and required name. Do not invent a value or read one from an unsafe file.
- If Keyclasp blocks a command as an environment dump, choose a narrower behavioral verification. Do not bypass the block.
- If output leak detection terminates the command, report the redacted failure and fix the target command's logging before retrying.
- Otherwise, preserve and report the child command's exit status and safe output as normal.
