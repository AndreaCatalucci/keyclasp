# Releasing a beta

From a clean, committed `main` checkout on macOS arm64 with Node.js 24 or 26 and the helper's declared Xcode toolchain:

```bash
npm run release:beta
```

Run `npm ci --ignore-scripts` after pulling dependency changes. Sign in with `npm login` if needed. Release-it handles npm authentication checks and asks before committing, tagging, publishing, and pushing to `origin`.

The command increments the beta number, updates the lockfile and inventories, runs the source tests, packs once, and tests that exact package. It records the package manifest, licenses, SBOM, release notes, and SHA-256, then publishes the verified tarball under `beta`. It also commits and tags the release. It leaves `latest` unchanged.

Users install or update with `npm install -g keyclasp@beta`. Published versions cannot be overwritten; the next fix gets the next beta number.

## Preview or retry

`npm run release:beta -- --dry-run` previews the release. It does not run the build or tests and is not verification evidence.

If preparation fails, nothing is published. The version and generated files may already have changed. Fix the failure, then run `npm run release:prepare` to rebuild and verify that version. Inspect and commit the changes, then use `npm run release:beta -- --no-increment` to finish the same version. Check `npm view keyclasp versions` first if publication returned an uncertain result; never assume a failed response means npm rejected the package.

Do not publish an older tarball after changing the source. The prepared versioned tarball and a fixed `keyclasp.tgz` publication copy live in ignored `release-artifacts/`. A hash check immediately before publication rejects a replaced package or missing success receipt.

## Broader qualification

The manual software-beta workflow checks the current version against its recorded package manifest across the supported matrix. Normal PR CI remains source-only. A local release does not establish physical authorization checks, every platform combination, independent security review, or production rollout. Historical release receipts remain unchanged.
