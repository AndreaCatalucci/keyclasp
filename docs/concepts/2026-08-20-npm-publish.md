# Publishing keyclasp to npm

## Brief

Get `keyclasp` onto the npm registry so `npm install -g keyclasp` works, replacing the current `npm install -g github:AndreaCatalucci/keyclasp` install path in README.md.

## Facts checked

- `package.json` is already publish-shaped: `name: keyclasp`, `bin.keyclasp -> dist/cli.js`, `main`, `files` (dist, native, install-codex-skill.sh, skills, NOTICE), `prepublishOnly: npm run build`, MIT license, repo/homepage/bugs URLs. No changes needed here.
- Name check: `npm view keyclasp` → 404, name is free on the public registry.
- Auth: `npm whoami` → `ENEEDAUTH`, this machine has no npm login/token yet.
- `native/` holds one plain JS file (`macos-biometric.js`), not a compiled addon. No prebuild/cross-compile problem. The only native dependency is `better-sqlite3`, which ships its own prebuilds and is resolved normally by npm on install.
- Cross-platform already handled in source: `src/vault.ts` and `src/biometric.ts` branch on `darwin`/`win32`/other; README already states macOS/Linux/Windows support with Touch ID as a macOS-only enhancement. Nothing npm-specific to fix here.
- No `.github/workflows/` exist yet. There is no CI release pipeline today, so "set up CI publish" is a real build step, not a rename of something existing.
- `dist/` is current and matches source (checked file listing); `prepublishOnly` rebuilds it anyway on publish.

## Decision tree

1. **Auth path**: manual (`npm login` + `npm publish` from this machine) vs. CI-driven (GitHub Actions workflow, npm automation token as repo secret, triggered by a version tag or GitHub Release).
2. **Initial version**: publish as `1.0.0` (current `package.json` value) vs. drop to `0.1.0` to signal first public release.
3. **Package scope**: unscoped `keyclasp` (name confirmed free) vs. scoped `@andreacatalucci/keyclasp`.

These are independent of each other (no prerequisite ordering), so asked together as round 1.

## Decisions

- Auth path: manual `npm login` + `npm publish` from this machine. CI publish deferred.
- Initial version: `0.1.0`, not `1.0.0`, to signal first public release. Requires editing `package.json`.
- Scope: unscoped `keyclasp`.

## Leading concept

Manual `npm login` + `npm publish` first, to get the package live now; CI publish (with `--provenance`) as a fast-follow once the manual path is proven. Unscoped name, version dropped to `0.1.0` for first public release.

## Remaining uncertainty

- Whether 2FA is enabled on the npm account (affects whether `npm publish` needs an OTP prompt or an automation token even for the manual path).
- Whether `NOTICE` / contributor attribution (Keyblind origin) needs any adjustment for a public registry listing (not checked, likely fine as-is).
- Long-term: once CI publish exists, whether releases are cut manually (tag push) or via a release-please-style automated versioning bot. Out of scope until the manual path is validated.
