#!/bin/sh

set -eu

artifact=${1:?Usage: verify-unsupported-unix-fail-closed.sh exact-tarball target}
target=${2:?Usage: verify-unsupported-unix-fail-closed.sh exact-tarball target}
case "$target" in
  musl) runtime_message="unsupported on musl Linux" ;;
  macos-x64) runtime_message="unsupported on darwin-x64" ;;
  *) echo "Unknown unsupported target: $target" >&2; exit 1 ;;
esac

if ! printf '%s' "${EXPECTED_SHA256:-}" | grep -Eq '^[a-f0-9]{64}$'; then
  echo "EXPECTED_SHA256 must name the reviewed candidate." >&2
  exit 1
fi
if command -v sha256sum >/dev/null 2>&1; then
  actual_sha256=$(sha256sum "$artifact" | cut -d ' ' -f 1)
else
  actual_sha256=$(shasum -a 256 "$artifact" | cut -d ' ' -f 1)
fi
if [ "$actual_sha256" != "$EXPECTED_SHA256" ]; then
  echo "Artifact SHA-256 mismatch: expected $EXPECTED_SHA256, received $actual_sha256." >&2
  exit 1
fi

qualification_root=$(mktemp -d)
install_root="$qualification_root/install"
vault_root="$qualification_root/vault"
mkdir -p "$install_root"

if npm install --no-audit --no-fund --prefix "$install_root" "$artifact" >"$qualification_root/normal.out" 2>&1; then
  echo "$target installation unexpectedly succeeded." >&2
  exit 1
fi
if ! grep -q "no reviewed native binding for this OS, libc, and architecture" "$qualification_root/normal.out"; then
  cat "$qualification_root/normal.out" >&2
  echo "$target installation did not return the reviewed native-binding rejection." >&2
  exit 1
fi

npm install --force --ignore-scripts --no-audit --no-fund --prefix "$install_root" "$artifact"
cli="$install_root/node_modules/keyclasp/dist/cli.js"
if KEYCLASP_HOME="$vault_root" node "$cli" init >"$qualification_root/runtime.out" 2>&1; then
  echo "$target initialization unexpectedly succeeded after a forced diagnostic install." >&2
  exit 1
fi
if ! grep -q "$runtime_message" "$qualification_root/runtime.out"; then
  cat "$qualification_root/runtime.out" >&2
  echo "$target runtime did not return the fail-closed platform message." >&2
  exit 1
fi
if [ -e "$vault_root" ]; then
  echo "$target runtime created vault state before rejecting the platform." >&2
  exit 1
fi

echo "PASS: $target install and runtime fail closed before vault creation."
