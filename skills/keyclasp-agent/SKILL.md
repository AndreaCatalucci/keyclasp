---
name: keyclasp-agent
description: Use Keyclasp from Codex to discover secret names and run commands with secrets injected only at the process boundary. Use when a coding task needs credentials for tests, builds, API calls, package registries, cloud CLIs, or deploys; when stored secret names must be matched to environment variables; or when a command fails because a required credential is missing.
---

# Keyclasp for Codex

Use Keyclasp as the boundary between Codex and plaintext credentials. Work with secret names and command output, never secret values.

## Workflow

1. Determine which environment variables the target command expects from project configuration, documentation, or its error output.
2. Confirm Keyclasp is available with `command -v keyclasp` when availability is unknown.
3. Determine the project and environment to use (see "Always Scope Explicitly" below) — from the task at hand, not by assuming a default.
4. Discover metadata without revealing values, scoped to that project/environment:

   ```bash
   keyclasp status --project <project> --environment <environment>
   keyclasp list --project <project> --environment <environment>
   ```

5. Match the required environment variables to the listed secret names.
6. Run the command through Keyclasp, passing the same `--project`/`--environment` flags.

## Always Scope Explicitly

Every secret lives under a `(project, environment, name)` triple, not just a name — the same name can hold different values in different scopes. Always pass `--project` and `--environment` explicitly on every Keyclasp invocation (`status`, `list`, `run`, etc.), rather than relying on ambient state:

```bash
keyclasp list --project myapp --environment prod
keyclasp run --project myapp --environment prod --env OPENAI_API_KEY -- npm test
```

Do not use `keyclasp use` (persisted project/environment context) or assume one is already set. It writes shared state to a context file meant for a human's interactive shell — a coding agent's invocations should never depend on it, since parallel or later invocations (this agent or another) could see a different persisted context than the one intended, silently resolving the wrong scope. If the project or environment isn't obvious from the task, ask rather than guess.

## Choose the Injection Form

Prefer explicit `--env` mappings so the child process receives only the secrets it needs. Repeat `--env` for multiple secrets.

```bash
# Inject one secret under the same environment variable name
keyclasp run --project myapp --environment prod --env OPENAI_API_KEY -- npm test

# Map a stored name to the environment variable expected by the command
keyclasp run --project myapp --environment prod --env OPENAI_KEY:OPENAI_API_KEY -- npm test

# Inject several selected secrets
keyclasp run --project myapp --environment prod --env AWS_ACCESS_KEY_ID --env AWS_SECRET_ACCESS_KEY -- aws s3 ls
```

Never omit `--env`. With no `--env` option, Keyclasp treats the request as operator-only whole-scope injection and requires Touch ID or an interactive vault passphrase. Agents must not request or attempt to satisfy that prompt.

Always place Keyclasp options (including `--project`/`--environment`) before `--`; everything after `--` is the child command and its arguments.

## Safety Rules

- Do not run `keyclasp get` or any other command that prints a plaintext secret.
- Do not run `keyclasp run` without at least one explicit `--env` mapping. Whole-scope injection is an operator action (Touch ID or interactive vault passphrase).
- Do not inspect injected values with `env`, `printenv`, shell expansion, debug logging, or equivalent commands. Verify behavior through the target command instead.
- Do not paste secret values into prompts, source files, command arguments, logs, test snapshots, commits, or summaries.
- Treat the child command as trusted code: it can read every secret injected into it. Use explicit `--env` mappings for least privilege when possible.
- Keep the default output guard enabled. It redacts detected injected values and terminates a command that prints one.
- Never add `--allow-unsafe` unless the user explicitly authorizes disabling both command preflight and output leak protection for that invocation.
- Apply the usual authorization rules to the child command. Keyclasp changes how credentials reach it; it does not authorize a deployment, mutation, or other external action.

## Handle Failures

- If Keyclasp is unavailable, report that installation or PATH configuration is required. Do not fall back to asking for plaintext credentials.
- If the vault is not initialized or cannot be unlocked, report the exact Keyclasp error and let the user complete the interactive setup or unlock step.
- If a secret is missing, run `keyclasp list --project <project> --environment <environment>` again with the same scope, compare names, and report the required name and scope. A "not found" error may mean the name is wrong, or the project/environment is — check both before assuming the secret was never stored. Do not invent a value or read one from an unsafe file.
- If Keyclasp blocks a command as an environment dump, choose a narrower behavioral verification. Do not bypass the block.
- If output leak detection terminates the command, report the redacted failure and fix the target command's logging before retrying.
- Otherwise, preserve and report the child command's exit status and safe output as normal.
