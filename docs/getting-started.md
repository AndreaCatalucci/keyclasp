# Getting Started

Requires **Node.js 24+**. An unlocked named `keyclasp run --env ...` uses normal vault-mode behavior: passphrase mode prompts normally and machine mode is unattended. Locked named runs and broad runs require Touch ID on macOS or one non-empty passphrase on Linux; Linux machine-only fails closed. Windows operator authorization is deferred.

## Install Keyclasp

```bash
npm install -g keyclasp
keyclasp init
```

Enter a passphrase, or press Enter for a machine-only key. A passphrase vault needs that passphrase again in each new terminal (`set`, `get`, `run`, `status`). A machine-only vault stays on this machine and is the mode agents and CI should use. Keyclasp cannot recover a lost passphrase.

If a new CLI refuses an old XOR key file, clone this repository and run `scripts/migrate-vault-key-wrap.mjs` on the original machine.

The install compiles a native SQLite binding. If it fails, install a C++ toolchain (Xcode Command Line Tools on macOS, `build-essential` plus Python on Linux) and retry.

Or clone, build, and link:

```bash
git clone https://github.com/AndreaCatalucci/keyclasp.git
cd keyclasp
npm install
npm run build
npm link
keyclasp init
```

## Try It Without a Real API Key

Use the secure prompt so the value does not enter shell history. Paste the value and press Enter, not Ctrl+D.

```bash
keyclasp set DEMO_SECRET - --project demo --environment local
# Paste any 8+ character string, then press Enter

keyclasp list --project demo --environment local
keyclasp status --project demo --environment local
```

`list` prints names only. Prove injection without printing the value:

```bash
keyclasp run --project demo --environment local --env DEMO_SECRET -- \
  node -e 'const v = process.env.DEMO_SECRET; console.log(v ? "injected, " + v.length + " chars" : "missing")'
```

`env`, `printenv`, and `export` are blocked on purpose. If the child prints the secret, Keyclasp redacts it as `[KEYCLASP_REDACTED]` and terminates the process.

## Store a Real Secret

```bash
keyclasp set SECRET_API_KEY - --project myapp --environment prod
# Paste the value, then press Enter

keyclasp list --project myapp --environment prod
keyclasp status --project myapp --environment prod
```

## Run Commands With Secrets

```bash
keyclasp run --project myapp --environment prod --env SECRET_API_KEY -- npm test
keyclasp run --project myapp --environment prod --env SECRET_API_KEY -- npm start
```

Keyclasp injects stored secrets into the child process environment. It blocks obvious environment-dump commands by default and watches stdout and stderr for injected values. If it detects a leak, it redacts the value and terminates the child process.

When a command expects another variable name:

```bash
keyclasp run --project myapp --environment prod --env SECRET_API_KEY:API_TOKEN -- npm test
```

Explicit `--env` mappings use each selected secret's effective lock state. Unlocked mappings use normal vault-mode behavior. If any mapping is locked, the entire run requires platform operator authorization before unlock. Omitting `--env` is a broad run and always requires authorization. Coding agents must always use explicit scope flags and mappings.

To require operator authorization for matching named production runs, or override a broader rule for one secret:

```bash
keyclasp lock --project myapp --environment prod
keyclasp unlock --project myapp --environment prod READ_ONLY_TOKEN
keyclasp status --project myapp --environment prod
```

Before depending on the vault as the only local copy, create a managed backup:

```bash
keyclasp backup create /secure/path/keyclasp-backup
```

## Next Steps

- [CLI command reference](commands.md)
- [Recipes](recipes.md)
- [Security design](security.md)
- [FAQ](faq.md)
