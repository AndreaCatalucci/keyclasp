# Software system context

Scope: the current Keyclasp software-vault boundary for interactive and unattended custody, trusted child execution, and managed backups. Native hardware custody remains unavailable.

Verification basis: KC-Q01 blocker-remediation implementation `e6e2de43b7d6a4168ab7a16278487fe20eb3b100`; inspected `src/cli.ts`, `src/platform.ts`, `scripts/install-native-binding.mjs`, `src/policy.ts`, `src/vault.ts`, `src/software/key-bundle.ts`, `src/vault-files.ts`, `src/recovery.ts`, `src/software/runtime.ts`, the complete source suite, and the diagnostic package matrix. The view matches the current combined implementation, including install-time and runtime rejection outside Node 24 and 26. This source basis is not a replacement qualification receipt.

```mermaid
C4Context
  title Keyclasp software-vault system context
  Person(operator, "Operator", "Initializes the vault and authorizes interactive, policy, backup, and recovery operations")
  Person(agent, "Coding agent", "Selects secret names and scopes but never handles their values")
  System(keyclasp, "Keyclasp software CLI", "Authenticates policy, manages custody, injects selected values, and coordinates recovery")
  System_Ext(auth, "OS authorization service", "Presents the supported operator-authentication ceremony")
  System_Ext(child, "Trusted child", "Receives selected values in its process environment")
  SystemDb_Ext(vault, "Local software vault", "Owner-only key bundle, policy, SQLite DB/WAL/SHM, and lifecycle journals")
  SystemDb_Ext(backup, "Operator-managed backup storage", "Retains authenticated managed backup sets under operator policy")
  System_Ext(snapshots, "External snapshots and prior copies", "Remain valid outside in-place cleanup and require retention or rotation decisions")
  System_Ext(provider, "Credential provider", "Rotates or revokes the underlying credential when prior copies must lose access")
  System_Ext(hardware, "Hardware custody", "Unavailable and outside the software system")
  System_Ext(remote, "Remote secrets service", "Not used; outside the local-only product")

  Rel(operator, keyclasp, "Invokes and authorizes")
  Rel(agent, keyclasp, "Requests explicit scope and named injection")
  Rel(keyclasp, auth, "Requests bounded operator authorization")
  Rel(keyclasp, child, "Launches without a shell and injects selected values")
  Rel(keyclasp, vault, "Reads, mutates, sanitizes, and validates")
  Rel(keyclasp, backup, "Creates, authenticates, and restores managed sets")
  Rel(operator, backup, "Controls destination, retention, and restore drills")
  Rel(operator, snapshots, "Controls retention outside Keyclasp")
  Rel(operator, provider, "Requests provider-side rotation or revocation")
```

Keyclasp relies on the OS user boundary and on the selected child being trusted. The coding agent works with names and explicit scope; only the trusted child receives values. The software CLI can overwrite buffers it owns, but it does not control JavaScript strings, child environments, OS caches, swap, crash collectors, filesystem snapshots, or copies retained outside the live vault.

Managed-backup authentication proves origin and internal consistency, not freshness. Live-file sanitization and machine-key retirement cannot revoke external snapshots, copied backups, or credentials already used elsewhere. Those copies remain under operator retention policy, and provider-side rotation is the revocation boundary. Hardware custody and any remote secrets service are outside this software system.
