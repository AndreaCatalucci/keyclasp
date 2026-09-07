# Getting started

These instructions are for coding agents running on local developer machines.

Start with the [isolated dummy demo](../README.md#try-it-with-a-dummy-credential). It needs no real credential and leaves your existing vault alone.

## Install

```bash
npm install -g keyclasp@beta
keyclasp version
```

The published beta supports macOS arm64 and glibc Linux arm64/x64 with Node.js 24 or 26. See the [support matrix](software-beta-support.md) for exclusions.

Keyclasp bundles its SQLite native bindings and checks their hashes during installation. Its install script must be allowed by your npm configuration. A normal install does not download native code separately. To build the bundled source instead, set `npm_config_build_from_source=true` for installation; this requires Xcode Command Line Tools on macOS, or Python and a C++ toolchain on Linux.

The macOS Touch ID helper is ad hoc signed, without Developer ID signing or notarization. Fresh-machine approval and physical Touch ID checks remain outstanding for this beta. Do not disable Gatekeeper or change the package to work around a failure; record the error and stop.

## After the demo

The README demo leaves a temporary vault containing only a dummy credential. To remove it, run this in the same demo terminal while `demo_vault` still names the directory you created:

```bash
rm -r -- "$demo_vault"
```

Then close that terminal. This discards its `KEYCLASP_HOME` override; a new terminal uses your normal configuration. Closing the terminal without cleanup leaves the dummy vault in temporary storage.

## Create your vault and store a credential

Run these commands yourself in a terminal. By default, the vault lives in `~/.keyclasp/`; `KEYCLASP_HOME` selects a different directory. Check that variable before using real credentials. An existing vault is not replaced by `init`.

```bash
keyclasp init
keyclasp set API_KEY - --project myapp --environment dev
```

`init` asks for a non-empty vault passphrase. `set` asks for that passphrase to unlock interactive custody, then prompts for the credential without echoing it. Enter real values only in that terminal prompt. Keep the passphrase safe: a backup still needs its passphrase and does not recover a forgotten one.

```bash
keyclasp list --project myapp --environment dev
keyclasp status --project myapp --environment dev
keyclasp run --project myapp --environment dev --env API_KEY -- \
  node -e 'if (!process.env.API_KEY) process.exit(1); console.log("Credential received")'
```

The run requires Touch ID and then the passphrase on macOS; Linux uses one passphrase entry for authorization and unlock. Cancellation must stop the run before the child starts. `list` and `status` show metadata, not proof of decryption. Startup recovery of an older or interrupted vault can request a passphrase before either command completes.

## Allow a record for unattended agent use

In your terminal, explicitly move only the intended record to machine custody:

```bash
keyclasp unlock --project myapp --environment dev API_KEY
```

This requires operator authorization. The same named run can then proceed without a prompt. Machine custody relies on software-derived machine identity and is weaker than passphrase custody. Follow the [agent configuration steps](../README.md#configure-your-coding-agent) before handing work to an agent.

To require interaction again:

```bash
keyclasp lock --project myapp --environment dev API_KEY
```

A vault created with `init --machine-only` first needs `keyclasp passphrase set` before records can be locked. See [custody rules](commands.md#custody-rules) for inheritance and defaults. Upgraded vaults keep their labelled legacy machine default until you explicitly change it.

## Back up

```bash
keyclasp backup create /secure/path/keyclasp-backup
```

Use the managed command to keep the database, keys, policy, and manifest together. A backup with any machine record is same-machine only. An all-interactive backup is portable with its passphrase. Backups authenticate a saved state but do not prove it is the newest copy. Live locking and passphrase changes do not revoke old copies; rotate the provider credential when revocation matters. See [moving a vault](recipes.md#moving-a-vault).

## Fresh-machine trial and completion checklist

The minimum human trial is installation, a successful demo, and an interactive run that starts only after approval. Use a fresh supported machine and dummy credentials throughout.

- [ ] Install `keyclasp@beta` and confirm the version. Record the OS, architecture, and Node version.
- [ ] Follow the README demo. The run prints `Credential available: true`. Use the optional cleanup above, then close the demo terminal.
- [ ] In a new terminal, create a separate temporary vault for interactive checks. If `mktemp` fails, stop before continuing:

```bash
trial_vault=$(mktemp -d)
export KEYCLASP_HOME="$trial_vault"
keyclasp init
keyclasp set API_KEY - --project myapp --environment dev
```

Choose a non-empty trial passphrase and enter `dummy-key-for-keyclasp` at the credential prompt. Follow the prompts yourself; do not give the passphrase to an agent.

- [ ] Run the command below and approve authorization. Expect `Credential received`.
- [ ] Run it again and cancel authorization. The child must not print `Credential received`. On macOS, check the physical Touch ID dialog; on Linux, check the terminal passphrase flow.

```bash
keyclasp run --project myapp --environment dev --env API_KEY -- \
  node -e 'if (!process.env.API_KEY) process.exit(1); console.log("Credential received")'
```

Record each result and any safe error output. After testing, remove only this trial directory with `rm -r -- "$trial_vault"` and close the terminal.

Automated checks of injection and output-leak handling have passed on macOS arm64/Node 26. They do not complete this human trial. Physical Touch ID, Linux execution, and fresh-machine human onboarding remain unverified in this documentation pass.

### Optional follow-up checks

Before deleting the trial vault, you can also test the [unattended agent setup](#allow-a-record-for-unattended-agent-use): unlock the dummy record, verify a named run needs no prompt, and lock it again to restore interaction. A configured agent should use explicit scope and `--env`, and stop for locked records.

To check output protection, use only the dummy record in the trial vault:

```bash
keyclasp run --project myapp --environment dev --env API_KEY -- \
  node -e 'console.log(process.env.API_KEY)'
printf 'Exit status: %s\n' "$?"
```

Authorize the run if the record is locked. Expect `[KEYCLASP_REDACTED]`, a blocked-output error, and exit status 2. The dummy value must not appear. This check needs a value at least eight characters long.
