# KC-Q01 build and provenance receipt

## Frozen inputs

| Input | Frozen value |
| --- | --- |
| Git source | `31aac732317e40597eeee02695b019a2045228ad` |
| Git tree | `33319e06779a6147815fbd23876404fbd4c657d5` |
| Commit time | `2026-09-06T01:15:38+02:00`; epoch `1788650138` |
| Lockfile SHA-256 | `14a8ae1f9227d8a634752797e1a6d37cae8d08ce24b8d51241f92efb5b057f5f` |
| Host | macOS 27.0 build `26A5425a`, arm64 |
| Node/npm | Node `26.8.1`; npm `11.19.0` |
| Locale/time controls | `LANG=C`, `LC_ALL=C`, `TZ=UTC`, `SOURCE_DATE_EPOCH=1788650138` |
| Caches/config | Separate empty npm cache per build; `npm_config_userconfig=/dev/null` |
| Compiler | Apple clang `21.0.0 (clang-2100.3.33.1)` |
| Linker | `ld-27037.1` |
| SDK | macOS SDK `27.0`, build `26A5419a` |
| Codesign | `codesign-135.0.6`; ad hoc; timestamp disabled; hardened runtime; no entitlements |
| Helper target | arm64; deployment target 13.0; flags and frameworks in [`evidence/macos-helper-candidate.json`](./evidence/macos-helper-candidate.json) |
| Package allowlist | Frozen `package.json` `files`, `exports`, OS/CPU, Node engines, dependency, and bundled-dependency fields |
| Workflow actions | checkout `d23441a48e516b6c34aea4fa41551a30e30af803`; setup-node `249970729cb0ef3589644e2896645e5dc5ba9c38`; upload-artifact `330a01c490aca151604b8cf639adc76d48f6c5d4`; download-artifact `018cc2cf5baa6db3ef3c5f8a56943fffe632ef53` |

Full Xcode was unavailable; only Command Line Tools were active. No Developer ID identity, notarization credential, network signing service, or remote attestation was used.

## Build method

Two temporary source directories were independently populated from `git archive 31aac732…`. Each had a separate npm cache. A read-only worktree Git pointer was copied only so generated helper metadata could identify the frozen revision; it did not add package files.

Each build then performed the same steps:

1. Install the lockfile with lifecycle scripts disabled.
2. Verify the bundled native source and selected prebuild.
3. Compile TypeScript.
4. Build two unsigned helpers with the declared toolchain, require byte equality, ad hoc sign one helper, and replace only the temporary build output.
5. Regenerate dependency, native, helper, SBOM, and license metadata in the temporary tree.
6. Compile TypeScript again and pack with lifecycle scripts disabled.

Temporary build root: `/tmp/keyclasp-kc-q01-builds.6xXVEy`. This path is diagnostic workspace, not the preserved candidate.

## Reproducibility result

| Output | Build 1 | Build 2 | Result |
| --- | --- | --- | --- |
| Unsigned helper SHA-256 | `c9aaafcc933ec880c2afc313fa64cba7f5f30471b89b604ad49d3648e40a7ddd` | same | Passed |
| Signed helper executable SHA-256 | `f0e8ecfea105db34fce8e812e2cda05763c644f55403d501de4be927b1337a65` | same | Passed |
| npm tarball SHA-256 | `7fdf6c4fbd09a4e2d0e2d7203227ffa11f080658d58e379480f3761878042323` | same | Passed |

Each build's internal comparison of its two unsigned helper builds passed, and both builds recorded the same unsigned-helper hash. `cmp` reported byte equality for the signed helper executables and the two package files. The preserved candidate is a mode-`0600` copy of build 1. It was not published or globally installed.

This is local provenance, not a hosted or SLSA attestation. A source or package-input change requires a new candidate ID, hash, and complete affected-gate rerun.
