---
title: Upgrading Keyblind to Node 26 compatibility
date: 2026-07-08
category: tooling-decisions
module: node-runtime
problem_type: tooling_decision
component: tooling
severity: medium
tags:
  - node-26
  - better-sqlite3
  - v8-compatibility
  - native-modules
  - dependency-upgrade
  - node-runtime
applies_when:
  - Upgrading a Node.js TypeScript project across a major Node version whose V8 release removes C++ addon APIs
  - A native addon that depends on removed V8 APIs fails to compile and must be upgraded to a version with prebuilds for the new Node target
---

# Upgrading Keyblind to Node 26 compatibility

## Problem

Keyblind (a TypeScript MCP secrets vault using AES-256-GCM encrypted SQLite) failed to run on Node 26 because its native database binding, `better-sqlite3@11.10.0`, could not compile against the V8 14.6 / NODE_MODULE_VERSION 147 ABI shipped with Node 26 — the addon's C++ sources referenced V8 APIs that Node 26 has removed.

## Symptoms

`npm install` / `npm rebuild better-sqlite3` aborted during the C++ compilation phase of the native addon build. The compiler emitted undefined-reference errors against removed V8 symbols rather than fetching a prebuilt binary:

```
../src/objects/database.cc: error: 'class v8::Object' has no member named 'GetPrototype'
../src/objects/statement.cc: error: 'class v8::Context' has no member named 'GetIsolate'
../src/objects/statement.cc: error: 'class v8::PropertyCallbackInfo<T>' has no member named 'This'
../src/objects/database.cc: warning: 'static v8::Local<v8::External> v8::External::New(...)' is deprecated

gyp ERR! build error
make: *** [Release/obj.target/better_sqlite3.node] Error 1
```

No prebuilt binary was downloaded — the install fell through to a from-source build that then failed against the new V8 headers.

## What Didn't Work

1. **`npm rebuild better-sqlite3`** — re-ran the same 11.10.0 source against the same Node 26 headers and failed identically. Rebuilding does not change the addon source, and 11.10.0 ships no Node 26 prebuild, so the broken from-source path is the only one available.
2. **`npm install better-sqlite3@11.10.0 --build-from-source`** — same V8 API removals; the C++ in 11.10.0 predates the V8 14.6 cleanup and cannot be compiled as-is.
3. **Patching the V8 calls in-tree** — the removed APIs (`v8::Object::GetPrototype()`, `v8::Context::GetIsolate()`, `v8::PropertyCallbackInfo<T>::This()`, deprecated `v8::External::New(isolate, value)`) are pervasive across the addon's object wrappers and the correct replacements are non-trivial. Forking/maintaining a patched copy is the wrong fix when an upstream release already targets Node 26.

The root cause is not a build-environment issue but a **version gap**: 11.10.0 was released before Node 26's V8 API surface and has no prebuilt binary for NODE_MODULE_VERSION 147.

## Solution

Upgrade the native addon to a release that ships Node 26 prebuilds, then update every place that declares the supported Node version.

### 1. Upgrade better-sqlite3

```diff
// package.json
- "better-sqlite3": "^11.10.0"
+ "better-sqlite3": "^12.11.1"
```

```bash
npm install better-sqlite3@latest   # resolves to 12.11.1
```

Verified in `package-lock.json`:
```json
"node_modules/better-sqlite3": {
  "version": "12.11.1",
  "resolved": "https://registry.npmjs.org/better-sqlite3/-/better-sqlite3-12.11.1.tgz",
  "engines": {
    "node": "20.x || 22.x || 23.x || 24.x || 25.x || 26.x"
  }
}
```

12.11.1 explicitly lists `26.x` in its `engines` and ships a prebuilt binary for NODE_MODULE_VERSION 147, so `prebuild-install` fetches the binary and no compilation occurs.

### 2. Declare the supported Node floor

```diff
// package.json
+ "engines": {
+   "node": ">=24"
+ }
```

```diff
// manifest.json (MCP server manifest)
- "node": ">=20.0.0"
+ "node": ">=24.0.0"
```

### 3. Move CI to the Node 26 era

```diff
// .github/workflows/test.yml
   strategy:
     matrix:
       os: [ubuntu-latest, windows-latest, macos-latest]
-      node-version: [20, 22, 24]
+      node-version: [24, 26]
```

### 4. Bump the container base image

```diff
// Dockerfile
- FROM node:22-alpine AS builder
+ FROM node:26-alpine AS builder
```

### Verification

Node 26.4.0: `npm ci` pulls the prebuilt `.node` binary (no compile), and all 78 tests pass.

## Why This Works

V8 14.6 (the engine in Node 26) completed the removal of long-deprecated C++ APIs that `better-sqlite3` 11.x still called — `GetPrototype`, `Context::GetIsolate`, `PropertyCallbackInfo::This`, and the isolate-explicit `External::New`. These were previously behind deprecation warnings; in 14.6 they are gone, so any source that calls them fails to compile. Additionally, Node 26's native module ABI is NODE_MODULE_VERSION 147, for which 11.10.0 has no prebuilt artifact, forcing the doomed from-source fallback.

`better-sqlite3` 12.x is the first major line rebuilt against the modern V8 API surface. It replaces the removed calls with their current equivalents and publishes prebuilt binaries that explicitly target `node 26.x` (NODE_MODULE_VERSION 147). With `prebuild-install` as a dependency, `npm install` detects the matching prebuild and skips compilation entirely, sidestepping both the V8 API removals and the ABI mismatch.

## Prevention

- **Pin native addons and track their Node-version support.** `better-sqlite3` declares its supported Node versions in `engines`; before bumping Node, confirm the pinned version lists the target. `npm` will still install on a mismatch by default, so treat the `engines` list as a release gate, not an enforcement.
- **Use the `engines` field in your own `package.json` to block installs on unsupported Node** (`"node": ">=24"`). Pair with `engine-strict=true` (`.npmrc`) if you want npm to hard-fail instead of warn.
- **Test against Node `current` during development**, not only LTS. The CI matrix now runs `[24, 26]` so an addon that silently drops Node 26 support is caught at PR time, not in production.
- **Prefer prebuilds over from-source.** A native dep that compiles cleanly is a bonus; the supported path is a prebuilt binary matching your ABI. If an install ever falls through to `node-gyp`, treat it as a signal that the pin is behind the runtime.

### Known non-blocking warning

`@renovatebot/pep440` (a transitive dependency of the Vercel CLI) declares `"engines": { "node": "^20.9.0 || ^22.11.0 || ^24" }` and emits `EBADENGINE` on Node 26.4.0. It is a development-time tool, does not affect Keyblind's runtime or tests, and can be ignored until upstream widens the constraint.