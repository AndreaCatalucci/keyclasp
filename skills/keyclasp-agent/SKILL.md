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

`list` prints names. `status` is metadata-only: it never loads a data key or decrypts a value. A machine-only or dual-key vault can serve a named request unattended when every selected secret is effectively unlocked and machine-key protected. Stop for a locked selection or any prompt. Map each required env var to a listed name (`--env STORE:EXPECTED` when they differ).

Done when the binary exists, status and list show that every requested name is eligible for an unattended named run, or the missing or locked state has been reported.

## 3. Match the child's input contract

`--env SOURCE:TARGET` changes only the environment-variable name. It does not convert the stored value into the format expected by `TARGET`. Before mapping to a different name, verify both contracts: project configuration or an operator instruction identifies the stored format, and the child tool's configuration or documentation accepts that format. Do not infer compatibility from similar names. Stop when the stored format cannot be established without exposing the value.

When the child expects the secret as a command argument, inject it under a shell-safe target name (`--env SOURCE:SAFE_NAME` when necessary) and expand that target inside the Keyclasp-launched child shell. Quote the child command so the calling shell passes `$SAFE_NAME` literally and Keyclasp injects it before expansion. This degraded fallback exposes the value through downstream process arguments and potentially process accounting, telemetry, or crash reports. Use it only in software mode, when the child has no compatible environment, stdin, or file-descriptor input and the project or operator accepts that exposure. Stop instead of using this fallback when `keyclasp status` reports hardware mode.

For example, a PostgreSQL connection URI must reach `psql` as its dbname or connection-string input, such as through `-d`; mapping that URI to `PGDATABASE` can make libpq fall back to a local socket:

```bash
keyclasp run --project myapp --environment prod --env DATABASE_URL -- \
  sh -c 'psql -d "$DATABASE_URL" "$@" 2>/dev/null || { status=$?; printf "%s\n" "psql probe failed" >&2; exit "$status"; }' sh \
  -X -v ON_ERROR_STOP=1 -At -c 'SELECT 1'
```

The second `sh` supplies `$0`; the remaining arguments become `"$@"`. The probe suppresses raw connection diagnostics because `psql` can echo fragments of a malformed URI that exact-value redaction will not catch. Run the smallest safe probe that exercises the same connection path before a consequential command.

Done when each mapping or child-side expansion matches the child's documented input contract and a safe probe has run when practical.

## 4. Run at the process boundary

Keyclasp options before `--`. Repeat `--env` once per secret.

```bash
keyclasp run --project <project> --environment <environment> --env OPENAI_API_KEY -- npm test
keyclasp run --project <project> --environment <environment> --env OPENAI_KEY:OPENAI_API_KEY -- npm test
```

Done when this form has run, or a failure below was handled without exposing a value.

## Safety

- Never run `keyclasp get`. If the user needs plaintext, give them the exact operator command to run in their terminal.
- Never omit `--env` (broad runs are operator-only).
- Never pass `--allow-unsafe` unless the user authorizes that one invocation.
- Never write a secret value into prompts, files, agent-authored arguments, logs, snapshots, commits, or summaries. Never inspect injection with `env`, `printenv`, or debug dumps. Verify through child behavior, or a check that reports only set vs length. If a trusted child requires the secret as an argument, expand it only inside the Keyclasp-launched child as described above and account for process-list exposure.
- Never invent a value or read one from a project file. Do not run `init`, `set`, `delete`, `rename`, `lock`, `unlock`, `inherit`, `passphrase`, or `backup`. Give the user the exact operator command for a requested state change.
- The child is trusted code and receives every injected secret. Keyclasp does not authorize the child's external actions.

## Failures

- **Missing binary**: report that install or PATH is required. Do not ask for plaintext.
- **Not initialized / locked / old-format key**: report the exact Keyclasp error. Do not prompt or pipe a passphrase. Agents may use only effectively unlocked machine-class records; the vault can be machine-only or dual-key.
- **`Secret "NAME" not found` / name missing from this scope**: `keyclasp list --all`, then report the required name and the scope you used.
- **`BLOCKED` environment dump**: prove the variable is set without printing it.
- **`BLOCKED: command output contained an injected secret`**: report the redacted failure (`[KEYCLASP_REDACTED]`) and fix the child's logging before retrying.
- **Unexpected localhost or Unix-socket connection**: injection may have succeeded while the child ignored or misinterpreted the value. Verify only that the selected variable is set, then recheck the child's expected value format. Do not retry the same mapping unchanged.
- **Anything else**: preserve the child's exit status and safe output.
