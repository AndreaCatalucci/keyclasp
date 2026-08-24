# Keyclasp macOS hardware beta

**Status: blocked draft. There is no installable hardware beta yet.** The current native artifact is status-only, and the tested ad-hoc harness failed permanent Secure Enclave creation with `errSecMissingEntitlement`. Do not use this guide to package or advertise the current artifact as hardware mode.

If a later physical test accepts an ad-hoc direct archive, macOS will identify it as coming from an unidentified developer. Developer ID remains a general-availability requirement, but the pre-GA signing and persistence path must pass hardware-custody, recovery, authorization, and release-evidence gates first.

For a future ad-hoc artifact that has passed those gates, if Gatekeeper blocks the exact downloaded artifact, try to open it once, then use **System Settings → Privacy & Security → Open Anyway**. Do not disable Gatekeeper, remove quarantine recursively, or approve a rebuilt or modified binary. Managed Macs may prohibit this approval.

For a future accepted beta, compare the archive checksum with the published `.sha256` file before use. Run `keyclasp doctor` after installation. Stop if it reports a protocol mismatch, damaged enrollment, required recovery, missing Touch ID, or unavailable Secure Enclave hardware.

The run policy is explicit:

- `keyclasp run --env NAME -- command` injects only the named secrets; it requires Touch ID before decrypting any secret when at least one selected record is in interactive custody;
- `keyclasp run -- command` requests every secret in the resolved scope and always requires Touch ID; and
- `keyclasp lock`, `keyclasp unlock`, and `keyclasp inherit` require Touch ID and atomically set the custody class for matching existing and future secrets.

An invalid explicit selection fails without launching the child and never widens into whole-scope injection. The beta does not fall back from required Touch ID to a recovery passphrase; recovery is a separate deliberate operation.

This beta has no telemetry. Diagnostic and test reports must contain metadata only, never secret values, data keys, recovery passphrases, or decrypted vault contents.
