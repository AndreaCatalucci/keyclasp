# Getting Started

Requires **Node.js 24+**. `set`, `list`, `status`, and `keyclasp run --env ...` work on macOS, Linux, and Windows. `keyclasp get` and whole-scope `keyclasp run` (no `--env`) ask for Touch ID when available, otherwise the vault passphrase.

## Install Keyclasp

```bash
npm install -g github:AndreaCatalucci/keyclasp
keyclasp init
```

Enter a passphrase, or press Enter for a machine-only key (that vault will not unlock on another machine). Keyclasp cannot recover a lost passphrase.

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

Use the secure prompt so the value does not enter shell history. Paste the value and press Enter — not Ctrl+D.

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

Omitting `--env` requests whole-scope injection. That operator-only path asks for Touch ID when available, or the vault passphrase when it is not. Coding agents must always use explicit scope flags and explicit `--env` mappings.

## Next Steps

- [CLI command reference](commands.md)
- [Recipes](recipes.md)
- [Security design](security.md)
- [FAQ](faq.md)
