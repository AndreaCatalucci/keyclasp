---
title: "Simpler secure onboarding"
status: decided
date: 2026-08-21
---

# Simpler secure onboarding

## Brief

Preserve the important security promises while making Keyclasp feel like a small local tool rather than a security service that users must operate.

The product allows unattended use when a machine-mode caller names only effectively unlocked secrets with `--env`. A passphrase-mode unlocked named run prompts for the vault passphrase as its normal unlock. Explicit selection limits what reaches the child; it is not authentication against another process running as the same user. Omitting `--env`, running `get`, changing authorization rules, managing recovery, or naming an effectively locked secret requires operator authorization. macOS uses Touch ID and then also asks for the vault passphrase when one exists. Linux uses a non-empty vault passphrase as the equivalent operator credential and unlocks the vault with the same prompt. Authenticated `lock` and `unlock` rules apply that gate to existing and future matching secrets.

This contract does not need stored capabilities or operator authorization on every command. It needs one authority that distinguishes exact named injection from whole-scope access, chooses the platform credential, never widens a failed or empty selection, and owns plaintext until it launches the child.

## Design hypotheses

### A. Scoped run with an operator gate

One short-lived security process opens the vault, enforces the request policy, launches the child, and exits. Named `--env` runs whose selected secrets are effectively unlocked use only the selected mode's normal unlock. Broad runs, human `get`, sensitive administration, and locked named runs require the platform operator credential: Touch ID on macOS or a non-empty vault passphrase on Linux. On macOS, Touch ID cannot fall back to a passphrase; a passphrase vault asks for both in sequence.

User experience:

```text
keyclasp init
keyclasp set API_KEY -
keyclasp run --env API_KEY -- npm test
# Machine mode runs unattended; passphrase mode asks for its passphrase
keyclasp run -- npm test
# Whole-scope request: Touch ID on macOS, passphrase on Linux
```

This removes the long-running broker, automation key, capability store, policy creation and renewal, workload manifests, and unattended sandbox profiles. It keeps device binding, unattended exact-secret injection, and user-presence authorization for broad access. The authorized child remains trusted with every secret it receives.

### B. Brokered unattended mode

A native broker stores narrowly scoped capabilities so an agent can run approved commands later without Touch ID. This provides the strongest unattended-agent promise, but it necessarily retains the installation, update, IPC, policy, audit, and process-supervision complexity described in the brokered security plan.

### C. Portable passphrase mode

Keep the current small TypeScript CLI, use a strong passphrase wrap, and treat the child command as trusted. This is the simplest cross-platform implementation. It protects a stolen vault from someone without the passphrase, but it is deliberately portable and cannot honestly promise that copied key material is useless on another machine.

### D. External hardware token

Use a FIDO2 or PIV token as the common hardware root on macOS, Windows, and Linux. This avoids Apple program membership and provides a uniform physical boundary, but requires users to buy and carry hardware. Touch-required tokens also do not solve unattended execution.

## Third-party components checked

### `hardware-enclave`: rejected integration candidate

GoDaddy's MIT-licensed Rust crate provides P-256 signing and ECIES encryption through macOS Secure Enclave, Windows TPM 2.0, and Linux TPM2 or keyring. Its current API also includes Touch ID and Windows Hello presence checks, zeroizing buffers, process hardening, tamper-evident files, and secret-delivery helpers.

This was evaluated as a way to replace most platform hardware adapters. The bounded correction failed its lifecycle review, so the status probe now uses a Keyclasp-owned Rust, Swift, and C adapter. The crate remains evidence, not a candidate dependency.

The crate does not carry or lend Keyclasp a GoDaddy code-signing identity. Cargo compiles its Rust code and Swift CryptoKit bridge into the final `keyclasp-core` executable. That executable has one macOS code identity: an ad-hoc local identity for an account-free build, or Keyclasp's future Developer ID identity for a signed public release.

The Secure Enclave key is separate from the executable signature. `hardware-enclave` asks the device to create a unique, non-exportable P-256 key; GoDaddy does not own or supply that private key. The library can require the host executable to have suitable signing capabilities for policies that depend on them.

The project is young. Before public use, Keyclasp should pin an audited release, review its platform fallbacks and unsafe/FFI code, verify behavior on physical machines, and decide whether to vendor an audited revision.

### `sshenc`: broker implementation reference

`sshenc` uses the same hardware layer to run a cross-platform SSH agent over Unix sockets or Windows named pipes. It proves the hardware layer can support an installed broker and contains useful lifecycle, IPC, release, and platform-packaging examples. Its protocol is limited to SSH signing, so Keyclasp cannot use the agent directly for arbitrary secrets.

### `age-plugin-se`: macOS key-wrap reference

This MIT-licensed Swift tool creates a Secure Enclave identity, makes copied identity files useless on another Mac, and can require Touch ID for decryption. It is a good macOS reference or prototype dependency. Calling it as a general decrypt subprocess would release plaintext outside the Keyclasp authority, so it should not become the final broker boundary.

### Secretive: macOS broker reference

Secretive is an MIT-licensed Secure Enclave SSH agent. Its app, agent, Keychain storage, Touch ID prompts, and auditable release process are useful design references. Like `sshenc`, it brokers signatures rather than arbitrary vault values.

### 1Password CLI: complete substitute

1Password already provides a signed desktop broker, verified local IPC, biometric authorization, and per-terminal sessions on macOS, Windows, and Linux. Using it would remove most implementation work, but would replace Keyclasp's local-only, no-account product model rather than supply an embeddable broker.

## Open-source vault foundations checked

### Bitwarden Secrets Manager

Bitwarden Secrets Manager already provides an encrypted remote store, projects, machine accounts, scoped access tokens, and a `bws run` command. Building on it would remove Keyclasp's local vault and synchronization work.

It does not satisfy Keyclasp's device-bound local threat model by itself. A machine access token is the authority to decrypt its assigned secrets; copying that token to another machine grants the same scoped access until expiry or revocation. Protecting the token with Secure Enclave or TPM would recreate the local hardware component Keyclasp still needs. It also changes onboarding from a local `init` into account, project, machine-account, and token setup.

### Bitwarden Agent Access

Agent Access is a closer architectural match: an Apache-2.0 open protocol, Rust SDK, CLI, and relay for fine-grained, user-mediated, just-in-time credential requests. `aac run` can inject selected fields into a child process. The protocol sends end-to-end encrypted credential requests through a relay and expects the credential-holding client or its policy engine to approve or deny each request.

This could support an optional remote Keyclasp provider:

```text
agent -> keyclasp run -> Agent Access -> trusted Bitwarden client -> approve/deny
```

It is not ready to become Keyclasp's sole security boundary. Bitwarden labels it early preview and the v0 protocol draft leaves asserted caller identity, purpose metadata, capability negotiation, and structured authorization errors open. The protocol also excludes client architecture, so it does not itself mandate Touch ID, hardware-bound keys, or Keyclasp's exact command policy. Its current design is online and relay-based, which conflicts with Keyclasp's local, offline default.

### OpenBao or Vault Agent

OpenBao Agent and Vault Agent already authenticate to a server, fetch secrets, inject environment variables, supervise a child, renew leases, and restart the child after rotation. OpenBao keeps the server and agent open source.

They suit centrally managed teams and dynamic credentials. For an individual local tool they add a server, authentication method, policy administration, and an agent configuration file. Their local token or auto-auth credential remains the authority; hardware-binding that bootstrap credential still needs a platform component.

### Infisical

Infisical provides an open-source server and `infisical run`, with projects, environments, folders, tags, and machine identities. It is a better fit than Bitwarden Password Manager for teams that want a central secrets service.

Its CLI also starts with a user login or machine credential. An agent that obtains the machine credential can use the server permissions attached to it. This is server-side least privilege, not local Touch-ID authorization.

### `age` and Passage

`age` is the smallest reusable local storage foundation. Passage shows how to build a file-based password store on it, while `age-plugin-se` and `age-plugin-yubikey` provide device or token-bound recipients. This can simplify encryption and recovery formats, but Keyclasp must still enforce operations and launch the trusted child without returning plaintext to the TypeScript process.

## Secure Enclave persistence comparison

The first physical test invalidated the assumption that an ad-hoc executable could create a permanent Secure Enclave Keychain item. macOS launched the user-approved executable, then rejected `SecKeyCreateRandomKey` with `errSecMissingEntitlement`. Gatekeeper approval controls whether code may launch; it does not validate Keychain entitlements.

Two persistence designs remain:

1. **Permanent Keychain item under a stable signed identity.** macOS owns lookup and deletion, and deleting the item invalidates the enrolled key even if old Keyclasp files remain. This provides the stronger revocation boundary. It also couples enrollment and updates to an accepted signing identity, blocks the account-free beta on the tested host, and requires Keychain namespace, duplicate, rollback, and orphan-key handling.
2. **CryptoKit Secure Enclave key with a file-backed opaque `dataRepresentation`.** Keyclasp stores the device-bound representation in its authenticated, atomic metadata and reopens it for each operation. This removes the Keychain namespace and signing-identity dependency from the key lifecycle and matches Keyclasp's existing file-backed vault. Deleting one copy cannot revoke copies of the representation retained elsewhere on the same Mac, so recovery, deletion, backup, and rollback semantics need explicit review.

**Leading hypothesis:** the CryptoKit representation is the better Keyclasp design if an ad-hoc physical spike proves creation, restart/reopen, copied-Mac failure, update continuity, and fail-closed tamper handling. It removes more lifecycle complexity than it adds and can remain the GA design after Developer ID signing. Touch ID belongs to the native request policy for broad and effectively locked runs; the device-binding key does not need to force a biometric prompt for every effectively unlocked named run. The permanent Keychain design remains the fallback when cryptographic revocation of every retained local handle is a release requirement.

The next experiment should test the CryptoKit path without changing the public CLI or current status-only core. Treat successful creation alone as insufficient: the test must restart the process, reopen the representation without Touch ID for an effectively unlocked exact named request, require Touch ID for a broad or effectively locked request before release, reject modified metadata, and document what deletion can and cannot guarantee.

## Design tree

```text
Must Keyclasp remain local and work offline?
├── Yes → local vault + reviewed platform hardware adapter
└── No
    ├── human approves remote requests → Bitwarden Agent Access
    └── centrally managed machine access → OpenBao, Vault, or Infisical

Must named agent runs work without a human prompt?
├── Yes → machine mode + explicit --env selection + trusted-child boundary
└── No  → passphrase mode, or strict platform authorization

Must a malicious same-user agent be constrained beyond named-secret selection?
├── Yes → future broker + exact stored capabilities
└── No  → short-lived native authority; whole-scope access stays operator-only

Must copied files be useless on another machine?
├── Yes → platform hardware key or external token
└── No  → passphrase portability is sufficient
```

## Leading concept

Ship the **software beta first**, then add hardware mode explicitly:

- passphrase mode is deliberately portable with the passphrase;
- machine mode is the default for unattended local agents and uses software-derived machine binding, not hardware security;
- named `--env` runs use the mode's normal unlock, with machine mode unattended and passphrase mode prompting for its passphrase;
- whole-scope runs and `get` always require platform operator authorization;
- macOS uses Touch ID plus the vault passphrase when one exists, while Linux uses one non-empty vault-passphrase prompt for authorization and unlock;
- an effective authorization lock applies the same platform gate to named runs;
- an effective lock adds no second prompt to a Linux passphrase vault because the successful authorization entry also unlocks it;
- hardware mode is an explicit later choice on physically qualified Macs;
- one short-lived native security core owns hardware key use, decryption, authorization, and child launch without importing the software implementation;
- explicit project, environment, and secret names remain the normal agent contract.

Keep Bitwarden Agent Access as a future provider protocol, not the v1 storage or authorization boundary. It becomes attractive for a later team or remote-agent mode after its protocol stabilizes.

The no-subscription beta remains a goal, not a proven distribution path. The tested permanent-Keychain ad-hoc artifact failed with `errSecMissingEntitlement`. Source, Homebrew, or direct distribution becomes eligible only after the selected device-binding design passes physical qualification under that exact identity. A later Developer ID build should not require a different vault design.

## Why this is technically smaller

Compared with the brokered plan, the first release does not need:

- a resident service or privileged installer;
- an automation device key;
- capability creation, storage, expiry, revocation, or replay handling;
- command and repository digest policies;
- unattended network and filesystem profiles;
- IPC between a presentation client and a long-lived authority;
- background lifecycle, recovery, and upgrade handling for a daemon.

The native process must still own decryption and child launch. Returning a vault key or plaintext to the TypeScript CLI would recreate the bypass that the secure design is intended to remove.

## Product boundary

There is no design that simultaneously provides all three of these without meaningful machinery:

1. no prompt for agents;
2. resistance to a malicious same-user agent;
3. trivial, account-free installation.

The first release accepts the current boundary: explicit `--env` selection scopes machine-mode unattended use but does not authenticate the caller. Passphrase mode still requires its normal unlock. A future broker and stored capabilities are required only if Keyclasp later promises resistance to a malicious process running as the same user.

## Beta release hypothesis

Treat the first software beta and the first hardware-backed beta as separate milestones.

The leading release hypothesis is a **software beta first**. Passphrase mode supports deliberate portability with the passphrase. Machine mode is the default for unattended local agents but uses software-derived machine binding, not Secure Enclave custody. Both modes can promise a local encrypted vault, explicit named-secret injection, no secret values in the shell command or Keyclasp stdout, platform operator authorization for `get` and whole-scope runs, and no account, network service, or telemetry. On Linux, those operator-only operations require a passphrase vault; machine-only mode cannot satisfy them. The product must state that the selected child and other same-user processes remain trusted and that output redaction is containment rather than an exfiltration boundary.

Before that beta, Keyclasp should:

- validate every explicit `--env` mapping before decrypting any selected value;
- bind encrypted records to their project, environment, and secret name so swapping ciphertext between rows fails authentication;
- choose and implement the strict-run setting, including authenticated storage and operator-approved downgrade;
- repair and verify owner-only vault permissions, including existing vault directories and SQLite side files;
- test the packed artifact from clean macOS, Linux, and Windows environments and publish the exact supported matrix;
- complete a focused dependency and release review, then publish a tagged prerelease with checksums and explicit beta limitations.

The hardware work remains an experimental track behind the status-only `keyclasp doctor` boundary. It becomes a supported beta only after the chosen device-binding path passes physical creation, restart/reopen, effectively unlocked named use, Touch-ID-gated broad and effectively locked use, tamper rejection, recovery, update continuity, and copied-Mac failure under the exact distributed code identity.

This split keeps the native prototype from blocking feedback on the working product while preventing software machine-identity wrapping from being advertised as hardware-backed security.

All three modes share command-level contracts, not cryptographic implementations. `src/runtime.ts` carries scope, command metadata, and status. `src/software/` implements passphrase and machine behavior, while `src/hardware/` and `native/keyclasp-core/` own optional hardware behavior. The CLI depends on the shared contract. Hardware code cannot import the software vault or return a data key or secret plaintext through the contract.

## Frontier decisions

1. Whether Homebrew/source installation provides a supported identity for the selected hardware persistence design. Treat it as an experiment until the exact artifact passes physical proof.
2. Whether the CryptoKit opaque representation has acceptable update, deletion, and recovery semantics. Keep hardware status-only until the complete physical spike passes.
3. Whether Intel/T2 Macs can join the first hardware support matrix. Defer them unless separate physical evidence is added.
4. Revisit Bitwarden Agent Access only after its draft defines asserted caller identity, request context, and stable approval semantics.

## Decisions

- Keyclasp remains local and offline by default.
- Passphrase and machine modes ship as the standard software modes. Hardware mode is an optional implementation selected explicitly on supported systems.
- The first public beta is software-only. Hardware mode has a separate physical qualification and release milestone.
- Software and hardware implementations conform to shared command-level contracts and keep key custody, decryption, and platform code private to each implementation.
- Effectively unlocked named `--env` runs use the mode's normal unlock: passphrase mode prompts and machine mode remains unattended. Broad runs, `get`, lock/unlock mutations, recovery, and effectively locked named runs require operator authorization. macOS uses Touch ID and then the vault passphrase when one exists; Linux uses one non-empty vault-passphrase prompt for both authorization and unlock. Authenticated authorization rules cannot be weakened by a flag or environment variable.
- Explicit secret selection is a scope boundary, not authentication against another same-user process.
- Remote stores and Bitwarden Agent Access remain optional future providers rather than the v1 security boundary.
- A third-party hardware crate supplies code, not a trusted publisher identity. Keyclasp owns and audits its final executable and release signature.

## Remaining uncertainty

- Prove that the exact locally built code identity can be enrolled and upgraded without relying on restricted Apple entitlements.
- Decide whether a Homebrew build or a first-run local compile produces the least surprising macOS installation.
- Select and physically qualify the Keyclasp-owned device-binding persistence path; keep the rejected `hardware-enclave` revisions as evidence only.
- Revisit Bitwarden Agent Access after its draft defines asserted caller identity, request context, and stable approval semantics.
