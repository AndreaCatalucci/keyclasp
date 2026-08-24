# Getting started

The software beta supports macOS `arm64` and glibc Linux `arm64` or `x64` with Node.js 24 or 26. macOS `x64`, Windows, musl Linux, and every other platform are unsupported. Hardware mode remains unavailable.

## Install and initialize

```bash
# After protected beta publication and registry-integrity verification:
npm install -g keyclasp@beta
keyclasp init
```

Before publication, install only the exact local tarball and SHA-256 named in the release-candidate receipt. Do not treat the registry command as evidence that this beta has been published.

Press Enter for a machine-only vault, or enter a non-empty passphrase to create both the machine and interactive keys. The machine key serves unattended records. The passphrase wraps the separate interactive key; losing it makes interactive records unrecoverable unless a tested backup exists.

The install uses `better-sqlite3@13.0.3`. Its reviewed prebuilds are carried inside the exact Keyclasp tarball, and Keyclasp verifies the selected native binding's SHA-256 before loading it. Installation does not download native code. Set `npm_config_build_from_source=true` to compile the bundled reviewed sources instead. A source build needs Xcode Command Line Tools on macOS or Python plus a C++ toolchain on Linux.

The beta is not published yet. Before publication, install the reviewed `.tgz` file directly.

## Add and run a dummy secret

```bash
keyclasp set DEMO_SECRET - --project demo --environment local
keyclasp list --project demo --environment local
keyclasp status --project demo --environment local
keyclasp run --project demo --environment local --env DEMO_SECRET -- \
  node -e 'const v=process.env.DEMO_SECRET; console.log(v ? `injected ${v.length} chars` : "missing")'
```

The secure prompt keeps the value out of shell history. `list` and `status` read names and metadata only. They do not prove that a value can be decrypted.

Use `--env STORED_NAME:CHILD_NAME` when the child expects a different variable. Always pass explicit project and environment flags in scripts and agent work.

## Enroll interactive custody

If the vault started machine-only, enroll the interactive key before locking records:

```bash
keyclasp passphrase set
keyclasp lock --project demo --environment local DEMO_SECRET
```

macOS requires Touch ID and then the passphrase for a locked run. Linux uses one passphrase entry for both authorization and key unlock. Return a record to machine custody with `unlock`; remove its exact override with `inherit`.

```bash
keyclasp unlock --project demo --environment local DEMO_SECRET
keyclasp inherit --project demo --environment local DEMO_SECRET
```

## Back up the complete vault

```bash
keyclasp backup create /secure/path/keyclasp-backup
```

Keep the database, key bundle, policy, and manifest together by using the managed command. Mixed backups are same-machine only. An all-interactive backup can be restored on another supported machine with its passphrase.

## Agent use

An agent may run a named selection only when its effective state is unlocked. It must stop for `get`, broad runs, locked selections, passphrase entry, policy changes, and recovery operations. The child process is trusted and can use every injected value.

Next: [commands](commands.md), [security](security.md), [FAQ](faq.md), and [recipes](recipes.md).
