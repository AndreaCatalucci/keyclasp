#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    printf '%s\n' "Usage: assert-native-release-capability.sh <native-core> <qualification|beta|ga-unsigned|ga-signed>" >&2
    exit 2
fi

core=$1
mode=$2
case "$mode" in
    qualification) expected_identity=ad_hoc; expected_lifecycle=disabled ;;
    beta) expected_identity=ad_hoc; expected_lifecycle=enabled ;;
    ga-unsigned) expected_identity=development; expected_lifecycle=enabled ;;
    ga-signed) expected_identity=developer_id; expected_lifecycle=enabled ;;
    *) printf '%s\n' "Unknown native release mode: $mode" >&2; exit 2 ;;
esac
if [ ! -x "$core" ]; then
    printf '%s\n' "Native core is missing or not executable: $core" >&2
    exit 1
fi

status_output=$("$core" status)
require_exactly_once() {
    field=$1
    expected=$2
    result=$(printf '%s\n' "$status_output" | /usr/bin/awk -F= -v field="$field" -v expected="$expected" '
        $1 == field { total += 1 }
        $1 == field && $2 == expected { exact += 1 }
        END { printf "%d:%d", total, exact }
    ')
    if [ "$result" != "1:1" ]; then
        printf '%s\n' "Native core is not release-capable: expected $field=$expected exactly once." >&2
        exit 1
    fi
}

require_exactly_once protocol_version 1
require_exactly_once adapter keyclasp_macos_v1
require_exactly_once reported_backend secure_enclave
require_exactly_once required_access_policy biometric_current_set
require_exactly_once current_set_policy_available true
require_exactly_once lifecycle_operations "$expected_lifecycle"
require_exactly_once enrollment_state unavailable
require_exactly_once code_identity "$expected_identity"

# CI builders may not expose Secure Enclave or Touch ID hardware. Require the
# fields to be typed exactly, while clean-Mac evidence gates own availability.
require_boolean_once() {
    field=$1
    result=$(printf '%s\n' "$status_output" | /usr/bin/awk -F= -v field="$field" '
        $1 == field { total += 1 }
        $1 == field && ($2 == "true" || $2 == "false") { valid += 1 }
        END { printf "%d:%d", total, valid }
    ')
    if [ "$result" != "1:1" ]; then
        printf '%s\n' "Native core is not release-capable: expected one boolean $field field." >&2
        exit 1
    fi
}
require_boolean_once hardware_presence_available
require_boolean_once touch_id_available
