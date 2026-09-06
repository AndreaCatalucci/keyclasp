# KC-Q01 physical and platform checklist

Candidate SHA-256: `7fdf6c4fbd09a4e2d0e2d7203227ffa11f080658d58e379480f3761878042323`.

Status: **unexecuted.** KC-Q01 did not authorize physical authentication. Do not fill this checklist from source tests, mocks, containers, emulation, or historical receipts. Because KC-Q01 already failed release-blocking gates, use this checklist only for a new candidate after its source and local matrix are green.

## Evidence rules

- Record candidate ID, SHA-256 before and after, package version, exact host, OS/build, architecture, Node/npm, native path, start/end time, and operator.
- Use synthetic values and bounded metadata only. Never include a passphrase or credential value.
- Preserve cancellations and failures. Do not replace a failed receipt with a later pass.
- A source or artifact change invalidates the receipt.

## Physical macOS arm64

Owner: release operator with a supported Apple Silicon Mac and enrolled Touch ID.

- [ ] Verify candidate SHA-256 and mode before installation.
- [ ] Install into an isolated prefix; verify helper path, bundle manifest, executable hash, arm64 slice, identifier, designated requirement, hardened-runtime flag, and no entitlements.
- [ ] Confirm the distribution profile is explicit. KC-Q01 is ad hoc signed; Developer ID/notarization remains unavailable.
- [ ] Approve a protected operation.
- [ ] Cancel a protected operation; confirm exit 2, no passphrase prompt after cancellation, no child launch, and no state mutation.
- [ ] Record unavailable-biometry and timeout behavior without fallback.
- [ ] Exercise locked and mixed named runs, broad run, `get`, lock/unlock/inherit/default changes, machine-only backup, emergency restore, and post-restore readback.
- [ ] Confirm helper environment containment and post-install helper identity.
- [ ] Verify candidate SHA-256 after the sequence.

## Physical or clean glibc Linux arm64

Owner: release operator with a clean native arm64 host.

- [ ] Verify Node 24 and 26 prebuilt installs.
- [ ] Verify Node 24 and 26 forced-source builds.
- [ ] Enter one passphrase for authorization and interactive unlock; confirm empty, wrong, cancelled, and noninteractive cases fail before decryption or mutation.
- [ ] Exercise machine-only gated rejection, locked/mixed operations, backup/restore, emergency restore with damaged live state, and interrupted recovery.
- [ ] Prove wrapper `SIGTERM` completes within the approved bound and leaves no child or descendant.
- [ ] Restore the same synthetic backup and verify bounded custody metadata and canary results.

## Physical or clean glibc Linux x64

Repeat the Linux arm64 checklist on a native x64 host. Local amd64 emulation is diagnostic evidence only and does not close this item.

## Exact unsupported hosts

- [ ] macOS x64: normal install and forced diagnostic runtime reject before vault creation.
- [ ] Windows: normal install returns `EBADPLATFORM`; every forced diagnostic stateful command returns the Windows fail-closed message and creates no state.
- [ ] Unsupported Node versions: installation or runtime rejects before state creation, consistent with the final product contract.

## Completion

The physical gate passes only when all supported native-host rows identify one unchanged replacement candidate and every unsupported row fails closed. Attach transcripts and hashes to the replacement receipt; do not edit KC-Q01 to make it pass.
