# KC-Q01 evidence receipt

## Verdict

**Not qualified.** The candidate is reproducible and passed the available exact-artifact F1-F6 checks, macOS functional matrix, package checks, and musl rejection. It failed combined-source acceptance, every available supported Linux cell's wrapper-signal gate, and the unsupported Node gate. Physical authorization, Windows/macOS x64 hosts, independent assurance, CI, publication, installation into the operator environment, and rollout were not executed.

This receipt does not supersede or rewrite the [`2026-09-05` audit](../../security/audits/2026-09-05/audit.md) or the [historical rc receipt](../0.2.0-beta.1-rc-receipt.md).

## Candidate identity

| Field | Value |
| --- | --- |
| Packet | `KC-Q01` |
| Candidate ID | `KC-Q01-31aac732-7fdf6c4f` |
| Source revision | `31aac732317e40597eeee02695b019a2045228ad` |
| Source tree | `33319e06779a6147815fbd23876404fbd4c657d5` |
| Package version | `0.2.0-beta.1` |
| Candidate file | Local-only `candidate/KC-Q01-31aac732-7fdf6c4f-keyclasp-0.2.0-beta.1.tgz`; intentionally excluded from Git |
| Mode and size | `0600`; `11,416,708` bytes |
| SHA-1 | `39b22b6a2361d70e3776b4a6a3604ec51d344d5e` |
| SHA-256 | `7fdf6c4fbd09a4e2d0e2d7203227ffa11f080658d58e379480f3761878042323` |
| npm integrity | `sha512-W/ehemfXRiHSUsn19QcY9LLD8+Bn5SyfaMhwWT8ikV2TN9AShD2FfL+A4kpqLAIL4nUSzd4zbdccz7d09xbpAg==` |
| Package manifest | 171 regular files; SHA-256 `11c2e2283690191f040265f7b976a9f83e8e2d9fd25adb43f2dc6e222463ff5d` |
| Unsigned helper | SHA-256 `c9aaafcc933ec880c2afc313fa64cba7f5f30471b89b604ad49d3648e40a7ddd` |
| Packaged signed helper | arm64, ad hoc hardened runtime, no entitlements; SHA-256 `f0e8ecfea105db34fce8e812e2cda05763c644f55403d501de4be927b1337a65` |

The package version was fixed by the requested source revision. KC-Q01 is unique by candidate ID, path, and hash, not by a new prerelease version. A release candidate still needs a new version decision and a new source revision.

The SHA-256 was checked again after artifact tests and remained unchanged.

## Gate ledger

| Gate | Status | Evidence |
| --- | --- | --- |
| Frozen source and build inputs | Passed | Commit, tree, lockfile, toolchain, environment, native hashes, workflow action pins, and package allowlist are recorded in [build-provenance.md](./build-provenance.md). |
| Two clean builds | Passed | Both generated the same unsigned helper SHA-256 and the same tarball SHA-256. |
| Source acceptance | **Failed** | Aggregate isolated result: 551 passed, 5 skipped, 2 failed. See below. |
| F1-F6 exact candidate | Passed for available synthetic checks | F1-F4 and F6 passed on macOS arm64 Node 26 prebuilt; F5 passed through the installed Linux Node 26 arm64 CLI before that cell reached its independent signal failure. |
| macOS arm64 matrix | Passed | Node 24.20.0 and 26.8.1, reviewed prebuilt and forced source build. Physical Touch ID is separate and unavailable. |
| glibc Linux matrix | **Failed** | Every arm64/x64 Node 24/26 prebuilt/source cell failed to finish wrapper process-group supervision within 10 seconds after `SIGTERM`. Other checks completed in bounded reruns. |
| Unsupported musl | Passed | arm64 and x64, Node 24 and 26, rejected install and forced-install runtime before vault creation. |
| Unsupported Node | **Failed** | Node 22.23.2 emitted an engine warning; after the reviewed install script ran, `init --machine-only` succeeded and created `vault.db`. |
| macOS x64 and Windows exact host | Unavailable | No exact host or authorized CI execution was available. Source fail-closed contracts passed inside the remaining source suite. |
| Hardware boundary | Passed | Exact candidate `doctor` returned 1, reported `hardware_mode=disabled`, and created no vault state. |
| Dependency advisory | Passed | Full and production-only `npm audit` reported zero advisories. |
| Dedicated malicious-package analysis | Unavailable | No dedicated scanner was installed. Lockfile integrity, bundled-source manifests, install scripts, package contents, and npm advisories were checked separately. |
| Physical authorization and recovery | Unexecuted | Physical authentication was outside KC-Q01 authorization. |
| Independent external assurance | Unexecuted | Handoff prepared; no reviewer was commissioned or contacted. |
| CI, signing, publication, rollout | Unexecuted | Outside authorization. The helper is ad hoc signed and full Xcode is unavailable. |

## Source checks

The monolithic source run reported the two failures below and was stopped while the exhaustive recovery matrix was still progressing. The two affected files were rerun individually, and the other 30 files then completed as one run: 516 passed and 5 platform cases skipped. The aggregate isolated result is 551 passed, 5 skipped, and 2 failed.

1. `tests/biometric.test.ts`: the frozen checked-in `keyclasp-macos-helper-candidate.json` names source `c0d96fc9f4fc79db4da44d64d8c9e48421d24b9f`, so `build-macos-biometric-helper.mjs --check` rejects frozen merge `31aac732…`.
2. `tests/lock-cli.test.ts`: the assertion expects `Values: not inspected by status`; the merged CLI prints `Values: not displayed by status`.

Independent source checks:

- Passed: TypeScript build, release inventory check, JavaScript syntax checks, Git whitespace check, and a bounded tracked-source scan for common private-key and token signatures.
- Failed: Shellcheck reported existing SC1007 warnings in three shell files and SC2016 in `scripts/sign-notarize-macos-ga.sh`.
- Unavailable: a dedicated secret scanner.

No assertion or product implementation was changed to make these checks green. The qualification harness was updated only to understand the merged helper manifest, explicit machine-only initialization, current legacy fixture semantics, and bounded signal waits.

## Exact-candidate F1-F6 evidence

| Finding | Status | Exact check |
| --- | --- | --- |
| F1 custody remanence | Passed | Transitioned 500 synthetic machine records to interactive custody, confirmed `secure_delete=1`, and used a fresh process to inspect the closed DB/WAL/SHM set. Current inventory was 500 interactive and 0 machine; 0 prior machine representations authenticated with the current machine key. |
| F2 self-overlapping output | Passed | `abcd123a` on stdout and stderr produced `[KEYCLASP_REDACTED]`, returned 2, and did not expose the raw value. |
| F3 stale-WAL restore | Passed | An abrupt writer left a WAL containing a newer synthetic value; managed restore returned the backup value rather than replaying live WAL state. |
| F4 restartable rollback | Passed | Recovery after `crash-after-all-published` converged to the authenticated live state. The 30-file source run separately completed the exhaustive primitive-boundary matrix. |
| F5 emergency CLI restore | Passed | Installed Linux Node 26 arm64 CLI restored an authenticated backup after the live key was replaced with corrupt bytes, then read back the synthetic value. |
| F6 machine-only backup | Passed | Authorized backup creation completed without calling the supplied interactive-unlock hook. Linux's separate machine-only management rejection remained intact. |

Only synthetic values and temporary vaults were used. No real credential or operator vault was read.

## Platform and native-build results

| Platform | Node | Prebuilt | Forced source | Classification |
| --- | ---: | --- | --- | --- |
| macOS arm64 | 24.20.0 | Passed | Passed | Local host; no physical Touch ID |
| macOS arm64 | 26.8.1 | Passed | Passed | Local host; F1-F4/F6 repeated on prebuilt |
| glibc Linux arm64 | 24.20.0 | Failed at wrapper signal | Failed at wrapper signal | Native container |
| glibc Linux arm64 | 26.8.1 | Failed at wrapper signal | Failed at wrapper signal | Native container; F1-F6 completed before final failure in the bounded prebuilt rerun |
| glibc Linux x64 | 24.20.0 | Failed at wrapper signal | Failed at wrapper signal | Local amd64 emulation |
| glibc Linux x64 | 26.8.1 | Failed at wrapper signal | Failed at wrapper signal | Local amd64 emulation |

For each bounded Linux failure, the guarded wrapper and the `--allow-unsafe` wrapper both failed to finish within 10 seconds after the harness sent `SIGTERM`. The ready sentinel existed; the receipt does not claim whether every descendant had exited. The container was destroyed after the failed check.

The exact Linux x64 results are emulation evidence, not physical-host evidence. The [physical checklist](./physical-platform-checklist.md) remains open.

## Dependency, package, and provenance evidence

- Lockfile SHA-256: `14a8ae1f9227d8a634752797e1a6d37cae8d08ce24b8d51241f92efb5b057f5f`.
- Production tree: `better-sqlite3@13.0.3` and `node-addon-api@8.9.2`; manifest SHA-256 `0ae267b546499a7d78bfd5c55609a2d7f3ecd55ccbce8687afd10e1a77db71ed`.
- SBOM: SPDX 2.3, 96 packages; SHA-256 `86f732207c02f2a3cfcc4e3f0a0da350c1f34ef9db0a58bb3167390eab32a44c`.
- License inventory: 95 dependency records, 0 unknown; SHA-256 `c45164c38fa7754cb940f94daa54b572ab3a75ce717f5bcec60a7d16ea0a08dd`.
- Native prebuild manifest SHA-256: `2bd61d602e433e5a826f476fb6f33791ffe8ca9d9da78513f674651343920b1e`.
- Bundled source manifests: `better-sqlite3` SHA-256 `5adeec8e325f9c76f70e107a4b69c43965da4c51ea6f982567fc0c6a196f5bee`; `node-addon-api` SHA-256 `b2b0ab050585230c1609c563c8170c196c884c201780b3af628587d2aa4d171c`.
- `npm outdated` reported available development-only updates for `@types/node` and Vitest; no production dependency was reported outdated.
- The package contains only its declared public export and reviewed allowlist. It excludes tests, docs, workflows, and native hardware experiments.

## Architecture and documentation

The three current architecture views were inspected against `31aac732…`, updated to that basis, and kept at one Mermaid block each. Their boundaries match the combined implementation. Product-text reconciliation still fails because [`docs/faq.md`](../../faq.md) says unsupported runtimes fail before vault creation, while the Node 22 artifact probe created a vault. The old `0.2.0-beta.1` release notes also cannot identify KC-Q01 as a new prerelease.

See [architecture-verification.md](./architecture-verification.md).

## Remaining gates

- Correct the two source failures without weakening their assertions, freeze a new revision and prerelease version, and repeat both clean builds.
- Fix Linux wrapper-signal shutdown, add a regression that proves bounded completion and no surviving descendant, then repeat all eight supported Linux cells on clean native hosts.
- Reject unsupported Node releases before vault creation or narrow the documented contract and qualification requirement through an explicit product decision.
- Run exact-host macOS x64 and Windows fail-closed checks.
- Complete the physical macOS and Linux checklist against one replacement candidate.
- Obtain Developer ID signing/notarization if the intended distribution is general third-party use.
- Commission independent external assurance after the replacement candidate is frozen.
- Obtain separate authorization for Git delivery, publication, installation, real-vault migration, credential rotation, or rollout.

Gates A-D remain open. The `2026-09-05` general-production denial remains in force.
