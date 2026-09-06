# Post-KC-Q01 blocker remediation

Status: **implemented at `e6e2de43b7d6a4168ab7a16278487fe20eb3b100` and locally verified; not a replacement candidate or qualification receipt.**

The working tree is based on frozen KC-Q01 source `31aac732317e40597eeee02695b019a2045228ad`. The preserved KC-Q01 tarball and its failed [receipt](./KC-Q01-receipt.md) remain unchanged.

## Changes

- Source acceptance: updated the helper metadata to the merged source, made its clean-build check require the recorded revision to remain an ancestor of the current source, and restored the status contract that values are not inspected.
- Linux signal supervision: detect whether a Linux process group contains a live member instead of waiting forever on zombie-only entries left for the container's init process to reap.
- Unsupported Node releases: reject versions outside Node 24 and 26 in both the package install hook and the stateful CLI before vault creation.

## Evidence

- Complete source suite, one uninterrupted run: 32 files passed; 554 tests passed; 5 platform cases skipped.
- Focused source run: platform, lock CLI, integration, run, and biometric coverage passed 146 tests with 4 platform skips.
- Helper verification: two clean unsigned builds were byte-identical; the packaged helper and metadata matched.
- Final diagnostic package SHA-256: `0be5b7b445bd1c0d933aafcaeca4a914ae6d03085ceb2d0d76e3722a374ae421`.
- Linux diagnostic matrix: Node 24.20.0 and 26.8.1 on arm64 and x64, through both reviewed prebuild and forced source-build paths, passed all eight cells. The x64 cells used local emulation.
- Node 22.23.2: normal installation failed in the Node-version guard. After a forced scripts-disabled installation, `init --machine-only` failed in the runtime guard and did not create the vault directory.

Only synthetic temporary vaults and values were used.

## Remaining qualification work

Select the reviewed release revision and a new prerelease version, produce two clean reproducible builds, and repeat the affected gates against the preserved replacement artifact. KC-Q01 remains not qualified. Physical authorization, native unsupported-host checks, independent assurance, signing, CI, publication, installation, real-vault migration, and rollout remain unexecuted.
