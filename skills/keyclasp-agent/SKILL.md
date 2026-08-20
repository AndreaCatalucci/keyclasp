---
name: keyclasp-agent
description: Keyclasp process-boundary injection. Use when a command needs credentials, fails for a missing env var, or another skill must inject secrets without exposing values.
---

# Keyclasp Agent

**Secret names** only. Values cross the **process boundary** inside `keyclasp run`, never this conversation.

## 1. Name the command, env vars, and scope

Read project config, docs, and error output. Pass `--project` and `--environment` on every Keyclasp command. Never `keyclasp use`, never ambient context. If scope is unknown:

```bash
keyclasp projects
keyclasp environments
keyclasp list --all
```

Done when the child command, required env-var names, `--project`, and `--environment` are known.

## 2. Confirm the vault can inject

`command -v keyclasp` when availability is unknown, then:

```bash
keyclasp status --project <project> --environment <environment>
keyclasp list --project <project> --environment <environment>
```

`list` prints names. `status` exit 0 does not mean `run --env` can inject: if `Values:` is `locked`, stop. Map each required env var to a listed name (`--env STORE:EXPECTED` when they differ).

Done when the binary exists, status is not locked, and every required name is listed, or the missing-name failure has been handled.

## 3. Run at the process boundary

Keyclasp options before `--`. Repeat `--env` once per secret.

```bash
keyclasp run --project <project> --environment <environment> --env OPENAI_API_KEY -- npm test
keyclasp run --project <project> --environment <environment> --env OPENAI_KEY:OPENAI_API_KEY -- npm test
```

Done when this form has run, or a failure below was handled without exposing a value.

## Safety

- Never run `keyclasp get`. If the user needs plaintext, tell them to run it in their terminal.
- Never omit `--env` (whole-scope injection is operator-only).
- Never pass `--allow-unsafe` unless the user authorizes that one invocation.
- Never write a secret value into prompts, files, command arguments, logs, snapshots, commits, or summaries. Never inspect injection with `env`, `printenv`, shell expansion, or debug dumps. Verify through child behavior, or a check that reports only set vs length.
- Never invent a value or read one from a project file. Do not run `init` / `set` / `delete` / `rename`. If the user wants a value stored, tell them to run `keyclasp set NAME -` in their terminal.
- The child is trusted code and receives every injected secret. Keyclasp does not authorize the child's external actions.

## Failures

- **Missing binary**: report that install or PATH is required. Do not ask for plaintext.
- **Not initialized / locked / old-format key**: report the exact Keyclasp error. Do not prompt or pipe a passphrase. A **machine-only** vault (empty passphrase at `init`) is what agents can use; a passphrase vault stays locked in each new process.
- **`Secret "NAME" not found` / name missing from this scope**: `keyclasp list --all`, then report the required name and the scope you used.
- **`BLOCKED` environment dump**: prove the variable is set without printing it.
- **`BLOCKED: command output contained an injected secret`**: report the redacted failure (`[KEYCLASP_REDACTED]`) and fix the child's logging before retrying.
- **Anything else**: preserve the child's exit status and safe output.
