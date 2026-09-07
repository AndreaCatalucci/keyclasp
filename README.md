# Keyclasp: Runtime Secrets for Coding Agents

Keyclasp stores credentials in a local encrypted vault and injects selected values into commands your coding agent runs. The agent works with secret names instead of copying API keys into prompts or project files.

**Run only trusted commands.** The child receives the actual credential and can send it over the network, write it to disk, or pass it to another process. Keyclasp catches some accidental output leaks; it does not sandbox the child or isolate secrets from other processes running as your OS user.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

## Try it with a dummy credential

Requires Node.js 24 or 26 on macOS arm64 or glibc Linux arm64/x64. Windows, Intel Macs, and Alpine/musl Linux are unsupported. This is a software beta; hardware custody is unavailable.

Install the published version explicitly. The npm `latest` tag still points to `0.1.1` as of September 7, 2026.

```bash
npm install -g keyclasp@0.2.0-beta.2
keyclasp version
```

The version output should identify `0.2.0-beta.2`. If npm reports blocked install scripts, allow Keyclasp's install script under your npm policy and rerun installation; it verifies the bundled native binding. See [installation details](docs/getting-started.md).

Run this block in Bash or Zsh. It uses a temporary vault, a dummy value, and explicit unattended **machine custody**. No passphrase or Touch ID prompt is expected. The subshell leaves your usual vault setting unchanged.

```bash
(
  set -eu
  demo_vault=$(mktemp -d)
  export KEYCLASP_HOME="$demo_vault"
  trap 'rm -rf -- "$demo_vault"' EXIT

  keyclasp init --machine-only
  printf '%s' 'dummy-key-for-keyclasp' | \
    keyclasp set DEMO_KEY --project demo --environment local
  keyclasp run --project demo --environment local --env DEMO_KEY -- \
    node -e 'if (!process.env.DEMO_KEY) process.exit(1); console.log("Credential received")'
)
```

After initialization and storage messages, expect `Credential received` and exit status 0. The temporary vault is then deleted. This checks injection without printing the credential.

For real credentials, start with `keyclasp init` in your own terminal and enter a non-empty passphrase. New records then require interactive custody. A locked run requires Touch ID followed by the vault passphrase on macOS, or one passphrase entry on Linux. [Getting started](docs/getting-started.md) covers secure entry, opting a record into unattended use, and the fresh-machine checklist.

## Configure your coding agent

Installing the CLI does not configure an agent. Give the agent the packaged [Keyclasp skill](skills/keyclasp-agent/SKILL.md); find its installed path with `printf '%s/keyclasp/skills/keyclasp-agent/SKILL.md\n' "$(npm root -g)"`. Load it through your agent's skill mechanism, or add the following to the project's agent instructions:

```text
Use Keyclasp for credentials. Read its installed skills/keyclasp-agent/SKILL.md.
Use project myapp and environment dev explicitly. Inspect names with list and
custody with status. Inject only the required named secrets with run --env.
Stop for locked records or authorization prompts; ask me to handle setup in
my terminal. Never retrieve plaintext with get or request a secret in chat.
```

Replace `myapp` and `dev` with your chosen scope and give the agent the resolved skill path. In your terminal, store credentials and explicitly unlock only the records the agent may use unattended. Then ask the agent to run your trusted command:

```bash
keyclasp run --project myapp --environment dev --env API_KEY -- npm test
```

Mapping `--env STORED_KEY:API_KEY` changes the child's variable name, not the value's format. The child also inherits the caller's environment: `--env` limits vault selection, not credentials already exported in the shell. Project and environment names are namespaces, not isolation boundaries.

## What Keyclasp protects

- Values are encrypted locally with AES-256-GCM. Keyclasp has no account, cloud service, or runtime telemetry.
- Explicit `--env` selections keep unrelated vault records out of a run.
- The default guard blocks common environment dumps. On an exact injected-value match in stdout or stderr, it emits `[KEYCLASP_REDACTED]`, stops forwarding output, terminates the supervised process group where OS permissions allow, and exits with status 2.

Output scanning covers values of at least eight characters. Transformed values, fragments, files, and network traffic are outside that protection. `--allow-unsafe` disables command preflight and output scanning; it does not bypass authorization. A child that changes privilege may become impossible for Keyclasp to terminate.

Machine custody uses software-derived machine identity, not Secure Enclave or TPM, and does not provide theft resistance. Passphrase custody uses a separate key. Neither protects against root or a compromised OS. Names and policy metadata remain plaintext, and memory cleanup is best effort. Keyclasp has not received a professional third-party security audit. See the [security model](docs/security.md).

## How does it compare with 1Password `op run`?

Both inject credentials into subprocess environments and mask secret output. These are already features of [1Password `op run`](https://www.1password.dev/cli/reference/commands/run).

| | Keyclasp | 1Password `op run` |
|---|---|---|
| Credential source | Local software vault; no account | 1Password secret references or Environments |
| Selection | Explicit project, environment, and secret names | References; service accounts can restrict access to vaults or Environments |
| Output behavior | Detects exact values of at least eight characters and stops the run | Conceals secrets on stdout and stderr by default |

If you already keep project credentials in 1Password, `op run` may be enough. Keyclasp is for a local-only workflow with explicit per-record machine or passphrase custody. Both still entrust credentials to the child; 1Password also documents the [same-user environment-access limit](https://www.1password.dev/cli/secrets-environment-variables).

## Guides

- [Getting started and fresh-machine trial](docs/getting-started.md)
- [Command reference](docs/commands.md)
- [CI, containers, and moving a vault](docs/recipes.md)
- [Security model](docs/security.md), [FAQ](docs/faq.md), and [supported platforms](docs/software-beta-support.md)

## Development and attribution

```bash
git clone https://github.com/AndreaCatalucci/keyclasp.git
cd keyclasp
npm ci
npm test
```

Keyclasp began as a fork of [Keyblind](https://github.com/aarifmms/keyblind), created by Mohammed Aarif Shaikh. Attribution is retained in [LICENSE](LICENSE) and [NOTICE](NOTICE). Keyclasp is available under the [MIT License](LICENSE).
