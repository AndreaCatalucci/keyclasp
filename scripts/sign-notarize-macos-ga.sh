#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    printf '%s\n' "Usage: sign-notarize-macos-ga.sh <bundle-directory> <tag> <output-dmg>" >&2
    exit 2
fi

bundle_dir=$1
tag=$2
output_dmg=$3
: "${KEYCLASP_CODESIGN_IDENTITY:?KEYCLASP_CODESIGN_IDENTITY is required}"
: "${KEYCLASP_NOTARY_KEY:?KEYCLASP_NOTARY_KEY is required}"
: "${KEYCLASP_NOTARY_KEY_ID:?KEYCLASP_NOTARY_KEY_ID is required}"
: "${KEYCLASP_NOTARY_ISSUER:?KEYCLASP_NOTARY_ISSUER is required}"

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
output_parent=$(dirname -- "$output_dmg")
output_name=$(basename -- "$output_dmg")
mkdir -p "$output_parent"
lock_dir="$output_parent/.${output_name}.lock"
if ! mkdir "$lock_dir" 2>/dev/null; then
    printf '%s\n' "Another release process owns the output lock: $lock_dir" >&2
    exit 1
fi
published_checksum="$output_dmg.sha256"
candidate_dir=
checksum_published=false
cleanup() {
    if [ -n "$candidate_dir" ]; then
        rm -rf "$candidate_dir"
    fi
    if [ "$checksum_published" = true ] && [ ! -e "$output_dmg" ]; then
        rm -f "$published_checksum"
    fi
    rmdir "$lock_dir" 2>/dev/null || true
}
on_signal() {
    trap - EXIT HUP INT TERM
    cleanup
    exit 1
}
trap cleanup EXIT
trap on_signal HUP INT TERM

if [ -e "$output_dmg" ] || [ -e "$published_checksum" ]; then
    printf '%s\n' "Output or checksum path already exists: $output_dmg" >&2
    exit 1
fi
"$script_dir/assert-macos-release-ready.mjs" ga
candidate_dir=$(mktemp -d "$output_parent/.keyclasp-ga.XXXXXX")
candidate_bundle="$candidate_dir/bundle"
/usr/bin/ditto "$bundle_dir" "$candidate_bundle"
core="$candidate_bundle/keyclasp-core"
candidate_dmg="$candidate_dir/$output_name"
notary_json="$candidate_dir/notary.json"

if [ -n "${KEYCLASP_SIGNING_KEYCHAIN:-}" ]; then
    /usr/bin/codesign --force --options runtime --timestamp \
        --identifier dev.keyclasp.core --keychain "$KEYCLASP_SIGNING_KEYCHAIN" \
        --sign "$KEYCLASP_CODESIGN_IDENTITY" "$core"
else
    /usr/bin/codesign --force --options runtime --timestamp \
        --identifier dev.keyclasp.core \
        --sign "$KEYCLASP_CODESIGN_IDENTITY" "$core"
fi
/usr/bin/codesign --verify --strict --verbose=2 "$core"
/usr/bin/codesign --verify --strict --verbose=2 \
    --test-requirement='=anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists' \
    "$core"
/usr/bin/codesign --display --requirements - --verbose=4 "$core"
"$script_dir/assert-native-release-capability.sh" "$core" ga-signed

/usr/bin/hdiutil create -fs HFS+ -srcfolder "$candidate_bundle" -volname "Keyclasp $tag" "$candidate_dmg"
if [ -n "${KEYCLASP_SIGNING_KEYCHAIN:-}" ]; then
    /usr/bin/codesign --force --timestamp --keychain "$KEYCLASP_SIGNING_KEYCHAIN" \
        --sign "$KEYCLASP_CODESIGN_IDENTITY" "$candidate_dmg"
else
    /usr/bin/codesign --force --timestamp \
        --sign "$KEYCLASP_CODESIGN_IDENTITY" "$candidate_dmg"
fi
/usr/bin/codesign --verify --strict --verbose=2 "$candidate_dmg"

/usr/bin/xcrun notarytool submit "$candidate_dmg" \
    --key "$KEYCLASP_NOTARY_KEY" \
    --key-id "$KEYCLASP_NOTARY_KEY_ID" \
    --issuer "$KEYCLASP_NOTARY_ISSUER" \
    --wait --timeout 30m --output-format json > "$notary_json"
node -e '
  const fs = require("node:fs");
  const result = JSON.parse(fs.readFileSync(process.argv[1], "utf8"));
  if (result.status !== "Accepted") {
    console.error(`Notarization was not accepted: ${result.status ?? "missing status"}`);
    process.exit(1);
  }
' "$notary_json"
/usr/bin/xcrun stapler staple "$candidate_dmg"
/usr/bin/xcrun stapler validate "$candidate_dmg"
/usr/sbin/spctl --assess --type open --verbose=4 "$candidate_dmg"
checksum=$(/usr/bin/shasum -a 256 "$candidate_dmg" | /usr/bin/awk '{ print $1 }')
printf '%s  %s\n' "$checksum" "$output_name" > "$candidate_dir/checksum"
if [ -e "$output_dmg" ] || [ -e "$published_checksum" ]; then
    printf '%s\n' "Output or checksum path appeared while signing: $output_dmg" >&2
    exit 1
fi
mv "$candidate_dir/checksum" "$published_checksum"
checksum_published=true
mv "$candidate_dmg" "$output_dmg"
