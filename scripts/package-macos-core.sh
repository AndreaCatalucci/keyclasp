#!/bin/sh
set -eu

if [ "$#" -ne 3 ]; then
    printf '%s\n' "Usage: package-macos-core.sh <qualification|beta> <tag> <output-directory>" >&2
    exit 2
fi

channel=$1
tag=$2
output_dir=$3
case "$channel" in
    qualification|beta) ;;
    *) printf '%s\n' "Channel must be qualification or beta." >&2; exit 2 ;;
esac

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH= cd -- "$script_dir/.." && pwd)

output_parent=$(dirname -- "$output_dir")
output_name=$(basename -- "$output_dir")
mkdir -p "$output_parent"
lock_dir="$output_parent/.${output_name}.lock"
if ! mkdir "$lock_dir" 2>/dev/null; then
    printf '%s\n' "Another release process owns the output lock: $lock_dir" >&2
    exit 1
fi
staging=
output_candidate=
cleanup() {
    if [ -n "$staging" ]; then
        rm -rf "$staging"
    fi
    if [ -n "$output_candidate" ]; then
        rm -rf "$output_candidate"
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

if [ -e "$output_dir" ]; then
    printf '%s\n' "Output path already exists: $output_dir" >&2
    exit 1
fi
(
    cd "$root"
    "$script_dir/assert-exact-release-source.sh" "$tag"
)
commit=$(git -C "$root" rev-parse HEAD)
source_epoch=$(git -C "$root" show -s --format=%ct "$commit")

staging=$(mktemp -d "${TMPDIR:-/tmp}/keyclasp-macos-package.XXXXXX")
output_candidate=$(mktemp -d "$output_parent/.${output_name}.XXXXXX")

source_root="$staging/source"
mkdir -m 0755 "$source_root"
git -C "$root" archive "$commit" | /usr/bin/tar -x -C "$source_root"
source_script_dir="$source_root/scripts"
core_dir="$source_root/native/keyclasp-core"
if [ "$channel" = beta ]; then
    node "$source_script_dir/assert-macos-release-ready.mjs" beta
fi

core="$staging/keyclasp-core-candidate"
"$core_dir/scripts/build-adhoc.sh" "$core" "$channel"

bundle="$staging/keyclasp-macos-$tag"
mkdir -m 0755 "$bundle"
install -m 0755 "$core" "$bundle/keyclasp-core"
if [ "$channel" = qualification ]; then
    printf '%s\n' \
        "STATUS-ONLY QUALIFICATION ARTIFACT" \
        "This artifact cannot enroll, open a vault, handle secrets, or launch a child." \
        > "$bundle/NOT-A-RELEASE.txt"
else
    install -m 0644 "$source_root/docs/macos-beta-install.md" "$bundle/README.txt"
fi
node "$source_script_dir/generate-macos-release-metadata.mjs" \
    "$bundle/keyclasp-core" "$bundle" "$channel" "$tag" "$commit" "$source_epoch"

archive="$output_candidate/keyclasp-macos-$tag.zip"
/usr/bin/ditto -c -k --keepParent "$bundle" "$archive"
(cd "$output_candidate" && /usr/bin/shasum -a 256 "$(basename "$archive")") > "$archive.sha256"
install -m 0644 "$bundle/manifest.json" "$output_candidate/keyclasp-macos-$tag.manifest.json"
install -m 0644 "$bundle/sbom.spdx.json" "$output_candidate/keyclasp-macos-$tag.sbom.spdx.json"
if [ -e "$output_dir" ]; then
    printf '%s\n' "Output path appeared while packaging: $output_dir" >&2
    exit 1
fi
mv "$output_candidate" "$output_dir"
output_candidate=
printf '%s\n' "$output_dir/keyclasp-macos-$tag.zip"
