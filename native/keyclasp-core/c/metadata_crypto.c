#include <CommonCrypto/CommonHMAC.h>
#include <CommonCrypto/CommonRandom.h>
#include <stdint.h>
#include <string.h>

enum { KEYCLASP_HMAC_SHA256_LENGTH = 32 };

__attribute__((visibility("hidden")))
int32_t keyclasp_random_bytes(uint8_t *output, size_t output_length) {
    if (output == NULL || output_length == 0) {
        return 0;
    }
    return CCRandomGenerateBytes(output, output_length) == kCCSuccess;
}

__attribute__((visibility("hidden")))
int32_t keyclasp_hmac_sha256(
    const uint8_t *key,
    size_t key_length,
    const uint8_t *data,
    size_t data_length,
    uint8_t *output,
    size_t output_length
) {
    if (key == NULL || key_length == 0 || data == NULL || data_length == 0
        || output == NULL || output_length != KEYCLASP_HMAC_SHA256_LENGTH) {
        return 0;
    }
    CCHmac(kCCHmacAlgSHA256, key, key_length, data, data_length, output);
    return 1;
}

__attribute__((visibility("hidden")))
int32_t keyclasp_hmac_sha256_verify(
    const uint8_t *key,
    size_t key_length,
    const uint8_t *data,
    size_t data_length,
    const uint8_t *expected,
    size_t expected_length
) {
    if (expected == NULL || expected_length != KEYCLASP_HMAC_SHA256_LENGTH) {
        return 0;
    }
    uint8_t actual[KEYCLASP_HMAC_SHA256_LENGTH];
    if (keyclasp_hmac_sha256(
            key,
            key_length,
            data,
            data_length,
            actual,
            sizeof(actual)
        ) != 1) {
        return 0;
    }
    int32_t verified = timingsafe_bcmp(actual, expected, sizeof(actual)) == 0;
    (void)memset_s(actual, sizeof(actual), 0, sizeof(actual));
    return verified;
}

__attribute__((visibility("hidden")))
void keyclasp_explicit_bzero(uint8_t *bytes, size_t length) {
    if (bytes != NULL && length > 0) {
        (void)memset_s(bytes, length, 0, length);
    }
}
