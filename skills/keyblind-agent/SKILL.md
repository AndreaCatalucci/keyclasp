---
name: keyblind-agent
description: Use Keyblind from coding-agent sessions to set up MCP access, store and reference secrets by name, run commands with injected secrets, sandbox .env files, manage aliases/TOTP/backends, and avoid leaking secret values into prompts, logs, diffs, or chat. Use when a task involves API keys, environment variables, .env files, MCP secret resolution, project setup that needs credentials, or commands that must run with secrets available at runtime.
---

# Keyblind Agent

Use Keyblind as the runtime boundary between the agent and real credentials. Treat secret names, aliases, and redacted metadata as safe to discuss; treat secret values as unsafe unless the user explicitly asks to reveal a value.

## Default Workflow

1. Check availability before relying on Keyblind:
   - Prefer MCP tools if a Keyblind MCP server is connected.
   - Otherwise use the `keyblind` CLI.
   - If neither is available, ask the user to install/configure Keyblind instead of inventing a fallback that exposes secrets.
2. Discover names, not values:
   - Use `list_secrets`, `list_aliases`, `vault_status`, `backend_status`, or CLI equivalents.
   - Do not print or summarize plaintext secret values.
3. Run tools with injected credentials:
   - Prefer `keyblind run -- <command>` for tests, scripts, dev servers, deploys, and CLIs that need environment variables.
   - Use `keyblind run --env SOURCE:TARGET -- <command>` when a tool expects a different environment variable name for one invocation.
   - Create a persistent alias only when the project will repeatedly need the alternate name.
4. Sandbox project files before agent editing:
   - Run `keyblind sandbox [.env]` before inspecting or modifying `.env` files.
   - Use `keyblind unsandbox [.env]` only when the user explicitly wants real values restored locally.
5. Store or rotate secrets without exposing them:
   - Prefer secure prompts (`keyblind set NAME -`) or MCP store/generate/rotate tools.
   - If the agent receives a secret value in chat, recommend rotating it after storing because it has already entered the transcript.

## Safety Rules

- Do not paste secret values into messages, code comments, commits, issue text, PR bodies, logs, or test snapshots.
- Do not use `keyblind get` or `resolve_secret` unless plaintext is strictly required for a user-approved local action.
- If plaintext is required for a command, inject it into the process environment with `keyblind run` instead of reading it into the model context.
- Keep `.env` files sandboxed in branches used by agents. Commit fake values only when the project intentionally tracks env templates.
- Use `keyblind run --allow-unsafe` only after the user accepts that preflight and output leak protection are disabled.
- When debugging failures, inspect command exit status, redacted output, Keyblind status, backend status, aliases, and audit metadata before requesting any secret value.

## Common Tasks

- **Set up a project for agent use**: run `keyblind init` if needed, store required secrets, create aliases for tool-specific names, run `keyblind sandbox`, then configure MCP with `keyblind setup-mcp`.
- **Run tests or builds needing credentials**: run `keyblind run -- npm test`, `keyblind run -- npm run build`, or the project-specific command.
- **Prepare a repository for safe agent collaboration**: import `.env` into Keyblind, sandbox it, verify secret names with `keyblind list`, and install the pre-commit hook when appropriate.
- **Use external secret managers**: inspect `keyblind backends`, switch with `keyblind config backend <backend>`, then verify availability before running dependent work.
- **Handle 2FA automation**: store TOTP configs with Keyblind and request current codes by name only when an authenticated workflow needs them.

## Reference

Read `references/keyblind-commands.md` when you need exact CLI syntax, MCP tool names, backend options, or command-selection guidance.
