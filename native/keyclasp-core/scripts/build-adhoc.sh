#!/bin/sh
set -eu

if [ "$#" -gt 2 ]; then
    printf '%s\n' "Usage: build-adhoc.sh [output-path [qualification|beta]]" >&2
    exit 2
fi

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
crate_dir=$(CDPATH= cd -- "$script_dir/.." && pwd)
dist_dir="$crate_dir/dist"
staged=${1:-"$dist_dir/keyclasp-core-spike"}
profile=${2:-qualification}
staged_dir=$(dirname -- "$staged")

mkdir -p "$staged_dir"
build_dir=$(mktemp -d "${TMPDIR:-/tmp}/keyclasp-adhoc-build.XXXXXX")
candidate=$(mktemp "$staged_dir/.keyclasp-core-spike.XXXXXX")
cleanup() {
    rm -f "$candidate"
    rm -rf "$build_dir"
}
on_signal() {
    trap - EXIT HUP INT TERM
    cleanup
    exit 1
}
trap cleanup EXIT
trap on_signal HUP INT TERM

host_target=$(rustc -vV | sed -n 's/^host: //p')
case "$host_target" in
    *-apple-darwin) ;;
    *)
        printf '%s\n' "The ad-hoc build requires a macOS Rust host target." >&2
        exit 1
        ;;
esac

KEYCLASP_BUILD_IDENTITY=ad_hoc cargo build \
    --manifest-path "$crate_dir/Cargo.toml" \
    --release \
    --locked \
    --target "$host_target" \
    --target-dir "$build_dir"
artifact="$build_dir/$host_target/release/keyclasp-core-spike"
install -m 0755 "$artifact" "$candidate"
/usr/bin/codesign --remove-signature "$candidate"
/usr/bin/codesign --force --sign - "$candidate"
/usr/bin/codesign --verify --strict --verbose=2 "$candidate"

abi_symbols=$(/usr/bin/nm -gjU "$candidate" | /usr/bin/awk '/^_keyclasp_/ { print }' | LC_ALL=C /usr/bin/sort)
expected_abi_symbols=$(printf '%s\n' \
    _keyclasp_code_signing_facts \
    _keyclasp_current_set_policy_available \
    _keyclasp_hardware_presence \
    _keyclasp_touch_id_available)
if [ "$abi_symbols" != "$expected_abi_symbols" ]; then
    printf '%s\n' "Ad-hoc artifact exported an unexpected Keyclasp C ABI:" >&2
    printf '%s\n' "$abi_symbols" >&2
    exit 1
fi

undefined_symbols=$(/usr/bin/nm -gu "$candidate")
for forbidden_symbol in \
    _SecItemAdd \
    _SecItemCopyMatching \
    _SecItemDelete \
    _SecItemUpdate \
    _SecKeyCreateRandomKey
do
    case "$undefined_symbols" in
        *"$forbidden_symbol"*)
            printf '%s\n' "Ad-hoc artifact imports forbidden API: $forbidden_symbol" >&2
            exit 1
            ;;
    esac
done

"$crate_dir/../../scripts/assert-native-release-capability.sh" "$candidate" "$profile"
mv -f "$candidate" "$staged"

printf '%s\n' "Built and verified the ad-hoc-signed spike: $staged"
