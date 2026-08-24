# Publishing Keyclasp to npm

This historical concept is superseded by the `0.2.0-beta.1` exact-artifact release process. Publication remains a protected checkpoint.

## Current contract

- Prepare and review one prerelease tarball from the frozen source state.
- Record its SHA-256, npm integrity, package contents, source revision, lockfile hash, SBOM, licenses, platform receipts, and accepted limitations.
- Publish that exact `.tgz` with `npm publish /absolute/path/keyclasp-0.2.0-beta.1.tgz --tag beta`. Publishing from the working tree is prohibited because npm would rebuild and repack different bytes.
- Download the registry tarball without installing it, verify its npm integrity and SHA-256 against the receipt, then run one narrow registry-install named-run/status smoke test.
- Stop on any mismatch. Rebuilding under the same candidate identity is not allowed.

## Protected commands

These commands require explicit publication authorization and are not part of local candidate preparation:

```bash
git commit
git push
git tag v0.2.0-beta.1
npm publish /absolute/path/keyclasp-0.2.0-beta.1.tgz --tag beta
gh release create v0.2.0-beta.1 /absolute/path/keyclasp-0.2.0-beta.1.tgz
```

The beta package supports macOS `arm64` and glibc Linux `arm64` or `x64` on Node.js 24 or 26. macOS `x64` and Windows installation and stateful use fail closed.
