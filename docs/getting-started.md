# Getting started

Start with the [isolated dummy demo](../README.md#try-it-with-a-dummy-credential). It needs no real credential and leaves your existing vault alone.

## Install

```bash
npm install -g keyclasp@0.2.0-beta.2
keyclasp version
```

The published beta supports macOS arm64 and glibc Linux arm64/x64 with Node.js 24 or 26. The npm `latest` tag is still `0.1.1` as of September 7, 2026; use the pinned command above. See the [support matrix](software-beta-support.md) for exclusions.

Keyclasp bundles its SQLite native bindings and checks their hashes during installation. Its install script must be allowed by your npm configuration. A normal install does not download native code separately. To build the bundled source instead, set `npm_config_build_from_source=true` for installation; this requires Xcode Command Line Tools on macOS, or Python and a C++ toolchain on Linux.

The macOS Touch ID helper is ad hoc signed, without Developer ID signing or notarization. Fresh-machine approval and physical Touch ID checks remain outstanding for this beta. Do not disable Gatekeeper or change the package to work around a failure; record the error and stop.

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

Use dummy values only. On a supported machine, install the pinned beta and run the README demo. Then open a separate terminal for an interactive trial, set `KEYCLASP_HOME` to a new `mktemp -d` directory, and follow the create/store/run steps above using a dummy `API_KEY`. Keep that directory until the checks are complete, then delete only that trial directory.

- [ ] Record OS, architecture, Node version, and `keyclasp version`; installation succeeds.
- [ ] README demo prints `Credential received`, exits 0, and removes its temporary vault.
- [ ] Interactive initialization rejects an empty passphrase; secure entry does not echo the dummy value.
- [ ] Approving the locked run succeeds; cancelling it prevents child output. On macOS, check the physical Touch ID dialog; on Linux, check the terminal passphrase flow.
- [ ] Unlocking the dummy record allows a named unattended run; locking it restores the prompt.
- [ ] Configure the agent and ask it to run the dummy check. It uses explicit scope and `--env`, and stops when the record is locked.
- [ ] With a machine-custody dummy record, run the leak check below. Expect `[KEYCLASP_REDACTED]`, a blocked-output error, and exit status 2; the dummy value must not appear.

```bash
keyclasp run --project myapp --environment dev --env API_KEY -- \
  node -e 'console.log(process.env.API_KEY)'
printf 'Exit status: %s\n' "$?"
```

The leak check needs a dummy value at least eight characters long. Run it only in the trial vault. Record failed steps and their safe error output; a successful injection check does not complete the human checks.

Automated isolated macOS arm64/Node 26 injection and leak checks have passed for the published beta. Physical Touch ID, Linux execution, and fresh-machine human onboarding remain unverified in this documentation pass. The checklist above is a trial procedure, not a completed acceptance record.
