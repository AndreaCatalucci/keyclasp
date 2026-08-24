#include <Security/Security.h>
#include <sys/resource.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum {
    KEYCLASP_KEY_OK = 0,
    KEYCLASP_KEY_ALREADY_EXISTS = 1,
    KEYCLASP_KEY_NOT_FOUND = 2,
    KEYCLASP_KEY_PERMISSION_DENIED = 3,
    KEYCLASP_KEY_UNSUPPORTED = 4,
    KEYCLASP_KEY_FAILED = 5,
    KEYCLASP_KEY_INCOMPLETE = 6,
    KEYCLASP_KEY_IDENTITY_MISMATCH = 7,
    KEYCLASP_KEY_POLICY_MISMATCH = 8,
    KEYCLASP_KEY_BACKEND_MISMATCH = 9,
    KEYCLASP_KEY_INVALID_PUBLIC_KEY = 10,
    KEYCLASP_KEY_CLEANUP_FAILED = 11,
};

/*
 * The Security framework returns decrypted bytes in a framework-owned CFData.
 * Apple's ownership contract permits CFRelease, but does not promise that the
 * allocator overwrites the released bytes. Keep that opaque copy inside this
 * bridge for only the copy into Rust-owned, explicitly-zeroized storage.
 *
 * Before any lifecycle path can hold a passphrase or call SecKey decrypt, turn
 * off traditional core-file generation for this short-lived process. This is
 * intentionally a containment measure, not a claim that CFRelease scrubs
 * memory or that an administrator-configured external crash collector is under
 * application control. The command-line executable remains status-only until
 * the remaining physical crash-reporting review is complete.
 */
__attribute__((visibility("hidden")))
int32_t keyclasp_prepare_secret_bearing_operation(void) {
    struct rlimit limit = { 0, 0 };
    if (setrlimit(RLIMIT_CORE, &limit) != 0) {
        return 0;
    }
    struct rlimit observed = { 0, 0 };
    return getrlimit(RLIMIT_CORE, &observed) == 0
        && observed.rlim_cur == 0 && observed.rlim_max == 0;
}

typedef int32_t (*keyclasp_key_validator)(
    void *context,
    const uint8_t *public_key,
    size_t public_key_length
);

static CFMutableDictionaryRef keyclasp_dictionary(void) {
    return CFDictionaryCreateMutable(
        kCFAllocatorDefault,
        0,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
}

static int32_t keyclasp_status_from_osstatus(OSStatus status) {
    switch (status) {
        case errSecSuccess:
            return KEYCLASP_KEY_OK;
        case errSecDuplicateItem:
            return KEYCLASP_KEY_ALREADY_EXISTS;
        case errSecItemNotFound:
            return KEYCLASP_KEY_NOT_FOUND;
        case errSecAuthFailed:
        case errSecInteractionNotAllowed:
        case errSecUserCanceled:
        case errSecMissingEntitlement:
            return KEYCLASP_KEY_PERMISSION_DENIED;
        case errSecNotAvailable:
        case errSecUnimplemented:
            return KEYCLASP_KEY_UNSUPPORTED;
        default:
            return KEYCLASP_KEY_FAILED;
    }
}

static int32_t keyclasp_status_from_error(CFErrorRef error) {
    if (error == NULL) {
        return KEYCLASP_KEY_FAILED;
    }
    return keyclasp_status_from_osstatus((OSStatus)CFErrorGetCode(error));
}

static int32_t keyclasp_count_keys(
    CFDataRef application_tag,
    CFIndex *count
) {
    CFMutableDictionaryRef query = keyclasp_dictionary();
    if (query == NULL || count == NULL) {
        if (query != NULL) {
            CFRelease(query);
        }
        return KEYCLASP_KEY_FAILED;
    }
    *count = 0;
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrApplicationTag, application_tag);
    CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (status == errSecItemNotFound) {
        return KEYCLASP_KEY_OK;
    }
    if (status != errSecSuccess) {
        if (result != NULL) {
            CFRelease(result);
        }
        return keyclasp_status_from_osstatus(status);
    }
    if (result == NULL || CFGetTypeID(result) != CFArrayGetTypeID()) {
        if (result != NULL) {
            CFRelease(result);
        }
        return KEYCLASP_KEY_INCOMPLETE;
    }
    *count = CFArrayGetCount((CFArrayRef)result);
    CFRelease(result);
    return KEYCLASP_KEY_OK;
}

static SecAccessControlRef keyclasp_copy_access_control(void) {
    CFErrorRef error = NULL;
    SecAccessControlRef access = SecAccessControlCreateWithFlags(
        kCFAllocatorDefault,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        kSecAccessControlBiometryCurrentSet | kSecAccessControlPrivateKeyUsage,
        &error
    );
    if (error != NULL) {
        CFRelease(error);
    }
    return access;
}

static bool keyclasp_number_equals(CFTypeRef value, int expected) {
    if (value == NULL || CFGetTypeID(value) != CFNumberGetTypeID()) {
        return false;
    }
    int actual = 0;
    return CFNumberGetValue((CFNumberRef)value, kCFNumberIntType, &actual)
        && actual == expected;
}

static bool keyclasp_dictionary_value_equals(
    CFDictionaryRef dictionary,
    CFTypeRef key,
    CFTypeRef expected
) {
    CFTypeRef actual = CFDictionaryGetValue(dictionary, key);
    return actual != NULL && expected != NULL && CFEqual(actual, expected);
}

static CFDictionaryRef keyclasp_copy_item_attributes(SecKeyRef private_key) {
    const void *item = private_key;
    CFArrayRef items = CFArrayCreate(
        kCFAllocatorDefault,
        &item,
        1,
        &kCFTypeArrayCallBacks
    );
    CFMutableDictionaryRef query = keyclasp_dictionary();
    if (items == NULL || query == NULL) {
        if (items != NULL) {
            CFRelease(items);
        }
        if (query != NULL) {
            CFRelease(query);
        }
        return NULL;
    }
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecMatchItemList, items);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitOne);

    CFTypeRef result = NULL;
    OSStatus status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    CFRelease(items);
    if (status != errSecSuccess || result == NULL
        || CFGetTypeID(result) != CFDictionaryGetTypeID()) {
        if (result != NULL) {
            CFRelease(result);
        }
        return NULL;
    }
    return (CFDictionaryRef)result;
}

static int32_t keyclasp_copy_public_key(
    SecKeyRef private_key,
    uint8_t *public_key,
    size_t public_key_capacity,
    size_t *public_key_length
) {
    SecKeyRef public = SecKeyCopyPublicKey(private_key);
    if (public == NULL) {
        return KEYCLASP_KEY_INCOMPLETE;
    }
    CFErrorRef error = NULL;
    CFDataRef representation = SecKeyCopyExternalRepresentation(public, &error);
    CFRelease(public);
    if (error != NULL) {
        CFRelease(error);
    }
    if (representation == NULL) {
        return KEYCLASP_KEY_INVALID_PUBLIC_KEY;
    }
    CFIndex length = CFDataGetLength(representation);
    if (length != 65 || public_key_capacity < (size_t)length) {
        CFRelease(representation);
        return KEYCLASP_KEY_INVALID_PUBLIC_KEY;
    }
    memcpy(public_key, CFDataGetBytePtr(representation), (size_t)length);
    *public_key_length = (size_t)length;
    CFRelease(representation);
    return KEYCLASP_KEY_OK;
}

static int32_t keyclasp_prove_private_key_use(SecKeyRef private_key) {
    const SecKeyAlgorithm algorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
    if (!SecKeyIsAlgorithmSupported(private_key, kSecKeyOperationTypeSign, algorithm)) {
        return KEYCLASP_KEY_UNSUPPORTED;
    }

    uint8_t challenge_bytes[32];
    if (SecRandomCopyBytes(
            kSecRandomDefault,
            sizeof(challenge_bytes),
            challenge_bytes
        ) != errSecSuccess) {
        return KEYCLASP_KEY_FAILED;
    }
    CFDataRef challenge = CFDataCreate(
        kCFAllocatorDefault,
        challenge_bytes,
        (CFIndex)sizeof(challenge_bytes)
    );
    SecKeyRef public_key = SecKeyCopyPublicKey(private_key);
    if (challenge == NULL || public_key == NULL) {
        if (challenge != NULL) {
            CFRelease(challenge);
        }
        if (public_key != NULL) {
            CFRelease(public_key);
        }
        return KEYCLASP_KEY_INCOMPLETE;
    }

    CFErrorRef error = NULL;
    CFDataRef signature = SecKeyCreateSignature(
        private_key,
        algorithm,
        challenge,
        &error
    );
    if (signature == NULL) {
        int32_t status = keyclasp_status_from_error(error);
        if (error != NULL) {
            CFRelease(error);
        }
        CFRelease(public_key);
        CFRelease(challenge);
        return status;
    }
    if (error != NULL) {
        CFRelease(error);
        error = NULL;
    }

    bool verified = SecKeyVerifySignature(
        public_key,
        algorithm,
        challenge,
        signature,
        &error
    );
    if (error != NULL) {
        CFRelease(error);
    }
    CFRelease(signature);
    CFRelease(public_key);
    CFRelease(challenge);
    return verified ? KEYCLASP_KEY_OK : KEYCLASP_KEY_INVALID_PUBLIC_KEY;
}

static int32_t keyclasp_validate_key(
    SecKeyRef private_key,
    CFDictionaryRef item_attributes,
    CFDataRef application_tag,
    CFStringRef label,
    const uint8_t *expected_public_key,
    size_t expected_public_key_length,
    uint8_t *public_key,
    size_t public_key_capacity,
    size_t *public_key_length,
    bool prove_private_use
) {
    CFDictionaryRef key_attributes = SecKeyCopyAttributes(private_key);
    if (key_attributes == NULL) {
        return KEYCLASP_KEY_INCOMPLETE;
    }
    bool backend_matches = keyclasp_dictionary_value_equals(
        key_attributes,
        kSecAttrTokenID,
        kSecAttrTokenIDSecureEnclave
    ) && keyclasp_dictionary_value_equals(
        key_attributes,
        kSecAttrKeyType,
        kSecAttrKeyTypeECSECPrimeRandom
    ) && keyclasp_dictionary_value_equals(
        key_attributes,
        kSecAttrKeyClass,
        kSecAttrKeyClassPrivate
    ) && keyclasp_number_equals(
        CFDictionaryGetValue(key_attributes, kSecAttrKeySizeInBits),
        256
    );
    CFRelease(key_attributes);
    if (!backend_matches) {
        return KEYCLASP_KEY_BACKEND_MISMATCH;
    }

    bool identity_matches = keyclasp_dictionary_value_equals(
        item_attributes,
        kSecAttrApplicationTag,
        application_tag
    ) && keyclasp_dictionary_value_equals(
        item_attributes,
        kSecAttrLabel,
        label
    );
    CFTypeRef stored_access = CFDictionaryGetValue(
        item_attributes,
        kSecAttrAccessControl
    );
    bool access_control_metadata_present = stored_access != NULL
        && CFGetTypeID(stored_access) == SecAccessControlGetTypeID()
        && keyclasp_dictionary_value_equals(
            item_attributes,
            kSecAttrAccessible,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        );
    if (!identity_matches) {
        return KEYCLASP_KEY_IDENTITY_MISMATCH;
    }
    if (!access_control_metadata_present) {
        return KEYCLASP_KEY_POLICY_MISMATCH;
    }
    int32_t status = keyclasp_copy_public_key(
        private_key,
        public_key,
        public_key_capacity,
        public_key_length
    );
    if (status != KEYCLASP_KEY_OK) {
        return status;
    }
    if (expected_public_key != NULL
        && (expected_public_key_length != *public_key_length
            || memcmp(
                public_key,
                expected_public_key,
                expected_public_key_length
            ) != 0)) {
        return KEYCLASP_KEY_IDENTITY_MISMATCH;
    }
    return prove_private_use
        ? keyclasp_prove_private_key_use(private_key)
        : KEYCLASP_KEY_OK;
}

static int32_t keyclasp_decrypt_data_key(
    SecKeyRef private_key,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_length
) {
    const SecKeyAlgorithm algorithm =
        kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM;
    if (ciphertext == NULL || ciphertext_length == 0 || plaintext == NULL
        || plaintext_capacity < 32 || plaintext_length == NULL) {
        return KEYCLASP_KEY_FAILED;
    }
    *plaintext_length = 0;
    (void)memset_s(plaintext, plaintext_capacity, 0, plaintext_capacity);
    if (!SecKeyIsAlgorithmSupported(
            private_key,
            kSecKeyOperationTypeDecrypt,
            algorithm
        )) {
        return KEYCLASP_KEY_UNSUPPORTED;
    }
    CFDataRef encrypted = CFDataCreateWithBytesNoCopy(
        kCFAllocatorDefault,
        ciphertext,
        (CFIndex)ciphertext_length,
        kCFAllocatorNull
    );
    if (encrypted == NULL) {
        return KEYCLASP_KEY_FAILED;
    }
    CFErrorRef error = NULL;
    CFDataRef decrypted = SecKeyCreateDecryptedData(
        private_key,
        algorithm,
        encrypted,
        &error
    );
    CFRelease(encrypted);
    if (decrypted == NULL) {
        int32_t status = keyclasp_status_from_error(error);
        if (error != NULL) {
            CFRelease(error);
        }
        return status;
    }
    if (error != NULL) {
        CFRelease(error);
    }
    CFIndex length = CFDataGetLength(decrypted);
    if (length != 32 || plaintext_capacity < (size_t)length) {
        CFRelease(decrypted);
        return KEYCLASP_KEY_INCOMPLETE;
    }
    // `decrypted` is framework-owned and cannot be safely cast mutable. Copy
    // it once into caller-owned zeroizable storage, then release it promptly.
    memcpy(plaintext, CFDataGetBytePtr(decrypted), (size_t)length);
    *plaintext_length = (size_t)length;
    CFRelease(decrypted);
    return KEYCLASP_KEY_OK;
}

static OSStatus keyclasp_delete_exact_key(SecKeyRef private_key) {
    const void *item = private_key;
    CFArrayRef items = CFArrayCreate(
        kCFAllocatorDefault,
        &item,
        1,
        &kCFTypeArrayCallBacks
    );
    CFMutableDictionaryRef query = keyclasp_dictionary();
    if (items == NULL || query == NULL) {
        if (items != NULL) {
            CFRelease(items);
        }
        if (query != NULL) {
            CFRelease(query);
        }
        return errSecAllocate;
    }
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecMatchItemList, items);
    OSStatus status = SecItemDelete(query);
    CFRelease(query);
    CFRelease(items);
    return status;
}

static int32_t keyclasp_copy_exact_validated_key(
    CFDataRef application_tag,
    CFStringRef label,
    const uint8_t *expected_public_key,
    size_t expected_public_key_length,
    uint8_t *public_key,
    size_t public_key_capacity,
    size_t *public_key_length,
    SecKeyRef *private_key
) {
    if (application_tag == NULL || label == NULL
        || expected_public_key == NULL || expected_public_key_length != 65
        || public_key == NULL || public_key_capacity < 65
        || public_key_length == NULL || private_key == NULL) {
        return KEYCLASP_KEY_FAILED;
    }
    *public_key_length = 0;
    *private_key = NULL;

    CFMutableDictionaryRef query = keyclasp_dictionary();
    if (query == NULL) {
        return KEYCLASP_KEY_FAILED;
    }
    CFDictionarySetValue(query, kSecClass, kSecClassKey);
    CFDictionarySetValue(query, kSecAttrApplicationTag, application_tag);
    CFDictionarySetValue(query, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFDictionarySetValue(query, kSecReturnAttributes, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecReturnRef, kCFBooleanTrue);
    CFDictionarySetValue(query, kSecMatchLimit, kSecMatchLimitAll);

    CFTypeRef result = NULL;
    OSStatus copy_status = SecItemCopyMatching(query, &result);
    CFRelease(query);
    if (copy_status != errSecSuccess) {
        if (result != NULL) CFRelease(result);
        return keyclasp_status_from_osstatus(copy_status);
    }
    if (result == NULL || CFGetTypeID(result) != CFArrayGetTypeID()) {
        if (result != NULL) CFRelease(result);
        return KEYCLASP_KEY_INCOMPLETE;
    }
    if (CFArrayGetCount((CFArrayRef)result) != 1) {
        CFRelease(result);
        return KEYCLASP_KEY_IDENTITY_MISMATCH;
    }
    CFTypeRef match = CFArrayGetValueAtIndex((CFArrayRef)result, 0);
    if (match == NULL || CFGetTypeID(match) != CFDictionaryGetTypeID()) {
        CFRelease(result);
        return KEYCLASP_KEY_INCOMPLETE;
    }
    CFDictionaryRef item = (CFDictionaryRef)match;
    CFTypeRef reference = CFDictionaryGetValue(item, kSecValueRef);
    if (reference == NULL || CFGetTypeID(reference) != SecKeyGetTypeID()) {
        CFRelease(result);
        return KEYCLASP_KEY_INCOMPLETE;
    }

    int32_t status = keyclasp_validate_key(
        (SecKeyRef)reference,
        item,
        application_tag,
        label,
        expected_public_key,
        expected_public_key_length,
        public_key,
        public_key_capacity,
        public_key_length,
        false
    );
    if (status == KEYCLASP_KEY_OK) {
        *private_key = (SecKeyRef)CFRetain(reference);
    }
    CFRelease(result);
    return status;
}

__attribute__((visibility("hidden")))
int32_t keyclasp_hardware_key_delete_exact(
    const uint8_t *application_tag_bytes,
    size_t application_tag_length,
    const uint8_t *label_bytes,
    size_t label_length,
    const uint8_t *expected_public_key,
    size_t expected_public_key_length
) {
    if (application_tag_bytes == NULL || application_tag_length == 0
        || label_bytes == NULL || label_length == 0
        || expected_public_key == NULL || expected_public_key_length != 65) {
        return KEYCLASP_KEY_FAILED;
    }
    CFDataRef application_tag = CFDataCreate(
        kCFAllocatorDefault,
        application_tag_bytes,
        (CFIndex)application_tag_length
    );
    CFStringRef label = CFStringCreateWithBytes(
        kCFAllocatorDefault,
        label_bytes,
        (CFIndex)label_length,
        kCFStringEncodingUTF8,
        false
    );
    if (application_tag == NULL || label == NULL) {
        if (application_tag != NULL) CFRelease(application_tag);
        if (label != NULL) CFRelease(label);
        return KEYCLASP_KEY_FAILED;
    }
    uint8_t public_key[65];
    size_t public_key_length = 0;
    SecKeyRef private_key = NULL;
    int32_t status = keyclasp_copy_exact_validated_key(
        application_tag,
        label,
        expected_public_key,
        expected_public_key_length,
        public_key,
        sizeof(public_key),
        &public_key_length,
        &private_key
    );
    (void)memset_s(public_key, sizeof(public_key), 0, sizeof(public_key));
    if (status == KEYCLASP_KEY_OK) {
        OSStatus deleted = keyclasp_delete_exact_key(private_key);
        status = deleted == errSecSuccess
            ? KEYCLASP_KEY_OK
            : keyclasp_status_from_osstatus(deleted);
    }
    if (private_key != NULL) CFRelease(private_key);
    CFRelease(label);
    CFRelease(application_tag);
    return status;
}

__attribute__((visibility("hidden")))
int32_t keyclasp_ecies_qualification(void) {
    const SecKeyAlgorithm algorithm =
        kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM;
    uint8_t cleartext_bytes[32] = {0};
    for (size_t index = 0; index < sizeof(cleartext_bytes); index++) {
        cleartext_bytes[index] = (uint8_t)index;
    }
    uint8_t private_key_bytes[97] = {
        0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42,
        0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63, 0xa4, 0x40,
        0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33,
        0xa0, 0xf4, 0xa1, 0x39, 0x45, 0xd8, 0x98, 0xc2,
        0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f,
        0x9b, 0x8e, 0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e,
        0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
        0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51,
        0xf5,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
    };
    int key_size = 256;
    CFNumberRef size = CFNumberCreate(kCFAllocatorDefault, kCFNumberIntType, &key_size);
    CFMutableDictionaryRef attributes = keyclasp_dictionary();
    CFDataRef private_representation = CFDataCreateWithBytesNoCopy(
        kCFAllocatorDefault,
        private_key_bytes,
        sizeof(private_key_bytes),
        kCFAllocatorNull
    );
    if (size == NULL || attributes == NULL || private_representation == NULL) {
        if (size != NULL) CFRelease(size);
        if (attributes != NULL) CFRelease(attributes);
        if (private_representation != NULL) CFRelease(private_representation);
        (void)memset_s(private_key_bytes, sizeof(private_key_bytes), 0, sizeof(private_key_bytes));
        (void)memset_s(cleartext_bytes, sizeof(cleartext_bytes), 0, sizeof(cleartext_bytes));
        return KEYCLASP_KEY_FAILED;
    }
    CFDictionarySetValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(attributes, kSecAttrKeySizeInBits, size);
    CFDictionarySetValue(attributes, kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    CFErrorRef error = NULL;
    SecKeyRef private_key = SecKeyCreateWithData(private_representation, attributes, &error);
    CFRelease(private_representation);
    CFRelease(attributes);
    CFRelease(size);
    if (private_key == NULL) {
        if (error != NULL) CFRelease(error);
        (void)memset_s(private_key_bytes, sizeof(private_key_bytes), 0, sizeof(private_key_bytes));
        (void)memset_s(cleartext_bytes, sizeof(cleartext_bytes), 0, sizeof(cleartext_bytes));
        return KEYCLASP_KEY_INCOMPLETE;
    }
    if (error != NULL) {
        CFRelease(error);
        error = NULL;
    }
    SecKeyRef public_key = SecKeyCopyPublicKey(private_key);
    CFDataRef cleartext = CFDataCreateWithBytesNoCopy(
        kCFAllocatorDefault, cleartext_bytes, sizeof(cleartext_bytes), kCFAllocatorNull
    );
    if (public_key == NULL || cleartext == NULL
        || !SecKeyIsAlgorithmSupported(public_key, kSecKeyOperationTypeEncrypt, algorithm)
        || !SecKeyIsAlgorithmSupported(private_key, kSecKeyOperationTypeDecrypt, algorithm)) {
        if (cleartext != NULL) CFRelease(cleartext);
        if (public_key != NULL) CFRelease(public_key);
        CFRelease(private_key);
        (void)memset_s(private_key_bytes, sizeof(private_key_bytes), 0, sizeof(private_key_bytes));
        (void)memset_s(cleartext_bytes, sizeof(cleartext_bytes), 0, sizeof(cleartext_bytes));
        return KEYCLASP_KEY_UNSUPPORTED;
    }
    CFDataRef ciphertext = SecKeyCreateEncryptedData(public_key, algorithm, cleartext, &error);
    CFRelease(cleartext);
    if (ciphertext == NULL) {
        if (error != NULL) CFRelease(error);
        CFRelease(public_key);
        CFRelease(private_key);
        (void)memset_s(private_key_bytes, sizeof(private_key_bytes), 0, sizeof(private_key_bytes));
        (void)memset_s(cleartext_bytes, sizeof(cleartext_bytes), 0, sizeof(cleartext_bytes));
        return KEYCLASP_KEY_BACKEND_MISMATCH;
    }
    if (error != NULL) {
        CFRelease(error);
        error = NULL;
    }
    CFDataRef decrypted = SecKeyCreateDecryptedData(private_key, algorithm, ciphertext, &error);
    bool round_trip = decrypted != NULL && CFDataGetLength(decrypted) == 32
        && memcmp(CFDataGetBytePtr(decrypted), cleartext_bytes, 32) == 0;
    if (decrypted != NULL) CFRelease(decrypted);
    if (error != NULL) {
        CFRelease(error);
        error = NULL;
    }
    CFMutableDataRef tampered = CFDataCreateMutableCopy(kCFAllocatorDefault, 0, ciphertext);
    bool rejected = false;
    if (tampered != NULL && CFDataGetLength(tampered) > 0) {
        uint8_t *bytes = CFDataGetMutableBytePtr(tampered);
        bytes[CFDataGetLength(tampered) - 1] ^= 0x01;
        CFDataRef rejected_output = SecKeyCreateDecryptedData(private_key, algorithm, tampered, &error);
        rejected = rejected_output == NULL;
        if (rejected_output != NULL) CFRelease(rejected_output);
        if (error != NULL) CFRelease(error);
    }
    if (tampered != NULL) CFRelease(tampered);
    CFRelease(ciphertext);
    CFRelease(public_key);
    CFRelease(private_key);
    (void)memset_s(private_key_bytes, sizeof(private_key_bytes), 0, sizeof(private_key_bytes));
    (void)memset_s(cleartext_bytes, sizeof(cleartext_bytes), 0, sizeof(cleartext_bytes));
    if (!round_trip) {
        return KEYCLASP_KEY_INCOMPLETE;
    }
    return rejected ? KEYCLASP_KEY_OK : KEYCLASP_KEY_IDENTITY_MISMATCH;
}

static int32_t keyclasp_rollback(
    SecKeyRef private_key,
    int32_t original_error
) {
    OSStatus cleanup = keyclasp_delete_exact_key(private_key);
    return cleanup == errSecSuccess ? original_error : KEYCLASP_KEY_CLEANUP_FAILED;
}

__attribute__((visibility("hidden")))
int32_t keyclasp_hardware_key_wrap(
    const uint8_t *public_key_bytes,
    size_t public_key_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_capacity,
    size_t *ciphertext_length
);

__attribute__((visibility("hidden")))
int32_t keyclasp_hardware_key_create(
    const uint8_t *application_tag_bytes,
    size_t application_tag_length,
    const uint8_t *label_bytes,
    size_t label_length,
    keyclasp_key_validator validator,
    void *validator_context,
    const uint8_t *data_key,
    size_t data_key_length,
    uint8_t *hardware_ciphertext,
    size_t hardware_ciphertext_capacity,
    size_t *hardware_ciphertext_length,
    uint8_t *public_key,
    size_t public_key_capacity,
    size_t *public_key_length
) {
    if (application_tag_bytes == NULL || application_tag_length == 0
        || label_bytes == NULL || label_length == 0 || validator == NULL
        || data_key == NULL || data_key_length != 32
        || hardware_ciphertext == NULL || hardware_ciphertext_capacity == 0
        || hardware_ciphertext_length == NULL
        || public_key == NULL || public_key_capacity < 65
        || public_key_length == NULL) {
        return KEYCLASP_KEY_FAILED;
    }
    *public_key_length = 0;
    *hardware_ciphertext_length = 0;
    CFDataRef application_tag = CFDataCreate(
        kCFAllocatorDefault,
        application_tag_bytes,
        (CFIndex)application_tag_length
    );
    CFStringRef label = CFStringCreateWithBytes(
        kCFAllocatorDefault,
        label_bytes,
        (CFIndex)label_length,
        kCFStringEncodingUTF8,
        false
    );
    SecAccessControlRef access = keyclasp_copy_access_control();
    CFMutableDictionaryRef private_attributes = keyclasp_dictionary();
    CFMutableDictionaryRef attributes = keyclasp_dictionary();
    if (application_tag == NULL || label == NULL || access == NULL
        || private_attributes == NULL || attributes == NULL) {
        if (application_tag != NULL) {
            CFRelease(application_tag);
        }
        if (label != NULL) {
            CFRelease(label);
        }
        if (access != NULL) {
            CFRelease(access);
        }
        if (private_attributes != NULL) {
            CFRelease(private_attributes);
        }
        if (attributes != NULL) {
            CFRelease(attributes);
        }
        return KEYCLASP_KEY_FAILED;
    }

    CFIndex existing_count = 0;
    int32_t status = keyclasp_count_keys(application_tag, &existing_count);
    if (status != KEYCLASP_KEY_OK || existing_count != 0) {
        CFRelease(attributes);
        CFRelease(private_attributes);
        CFRelease(access);
        CFRelease(label);
        CFRelease(application_tag);
        return status == KEYCLASP_KEY_OK ? KEYCLASP_KEY_ALREADY_EXISTS : status;
    }

    int key_size = 256;
    CFNumberRef size = CFNumberCreate(
        kCFAllocatorDefault,
        kCFNumberIntType,
        &key_size
    );
    if (size == NULL) {
        CFRelease(attributes);
        CFRelease(private_attributes);
        CFRelease(access);
        CFRelease(label);
        CFRelease(application_tag);
        return KEYCLASP_KEY_FAILED;
    }

    CFDictionarySetValue(private_attributes, kSecAttrIsPermanent, kCFBooleanTrue);
    CFDictionarySetValue(private_attributes, kSecAttrApplicationTag, application_tag);
    CFDictionarySetValue(private_attributes, kSecAttrLabel, label);
    CFDictionarySetValue(private_attributes, kSecAttrAccessControl, access);
    CFDictionarySetValue(attributes, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave);
    CFDictionarySetValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(attributes, kSecAttrKeySizeInBits, size);
    CFDictionarySetValue(attributes, kSecPrivateKeyAttrs, private_attributes);

    CFErrorRef error = NULL;
    SecKeyRef private_key = SecKeyCreateRandomKey(attributes, &error);
    CFRelease(size);
    CFRelease(attributes);
    CFRelease(private_attributes);
    if (private_key == NULL) {
        status = keyclasp_status_from_error(error);
        if (error != NULL) {
            CFRelease(error);
        }
        CFRelease(access);
        CFRelease(label);
        CFRelease(application_tag);
        return status;
    }
    if (error != NULL) {
        CFRelease(error);
    }

    CFDictionaryRef item_attributes = keyclasp_copy_item_attributes(private_key);
    if (item_attributes == NULL) {
        status = KEYCLASP_KEY_INCOMPLETE;
    } else {
        status = keyclasp_validate_key(
            private_key,
            item_attributes,
            application_tag,
            label,
            NULL,
            0,
            public_key,
            public_key_capacity,
            public_key_length,
            true
        );
        CFRelease(item_attributes);
    }
    if (status == KEYCLASP_KEY_OK) {
        CFIndex created_count = 0;
        status = keyclasp_count_keys(application_tag, &created_count);
        if (status == KEYCLASP_KEY_OK && created_count != 1) {
            status = created_count > 1
                ? KEYCLASP_KEY_ALREADY_EXISTS
                : KEYCLASP_KEY_INCOMPLETE;
        }
    }
    if (status == KEYCLASP_KEY_OK) {
        status = validator(
            validator_context,
            public_key,
            *public_key_length
        );
    }
    if (status == KEYCLASP_KEY_OK) {
        status = keyclasp_hardware_key_wrap(
            public_key,
            *public_key_length,
            data_key,
            data_key_length,
            hardware_ciphertext,
            hardware_ciphertext_capacity,
            hardware_ciphertext_length
        );
    }
    if (status != KEYCLASP_KEY_OK) {
        status = keyclasp_rollback(private_key, status);
    }

    CFRelease(private_key);
    CFRelease(access);
    CFRelease(label);
    CFRelease(application_tag);
    return status;
}

__attribute__((visibility("hidden")))
int32_t keyclasp_hardware_key_open(
    const uint8_t *application_tag_bytes,
    size_t application_tag_length,
    const uint8_t *label_bytes,
    size_t label_length,
    const uint8_t *expected_public_key,
    size_t expected_public_key_length,
    const uint8_t *ciphertext,
    size_t ciphertext_length,
    uint8_t *public_key,
    size_t public_key_capacity,
    size_t *public_key_length,
    uint8_t *plaintext,
    size_t plaintext_capacity,
    size_t *plaintext_length
) {
    if (application_tag_bytes == NULL || application_tag_length == 0
        || label_bytes == NULL || label_length == 0
        || expected_public_key == NULL || expected_public_key_length != 65
        || ciphertext == NULL || ciphertext_length == 0
        || public_key == NULL
        || public_key_capacity < 65 || public_key_length == NULL
        || plaintext == NULL || plaintext_capacity < 32
        || plaintext_length == NULL) {
        return KEYCLASP_KEY_FAILED;
    }
    *public_key_length = 0;
    *plaintext_length = 0;
    CFDataRef application_tag = CFDataCreate(
        kCFAllocatorDefault,
        application_tag_bytes,
        (CFIndex)application_tag_length
    );
    CFStringRef label = CFStringCreateWithBytes(
        kCFAllocatorDefault,
        label_bytes,
        (CFIndex)label_length,
        kCFStringEncodingUTF8,
        false
    );
    if (application_tag == NULL || label == NULL) {
        if (application_tag != NULL) {
            CFRelease(application_tag);
        }
        if (label != NULL) {
            CFRelease(label);
        }
        return KEYCLASP_KEY_FAILED;
    }

    SecKeyRef private_key = NULL;
    int32_t status = keyclasp_copy_exact_validated_key(
        application_tag,
        label,
        expected_public_key,
        expected_public_key_length,
        public_key,
        public_key_capacity,
        public_key_length,
        &private_key
    );
    if (status == KEYCLASP_KEY_OK) {
        status = keyclasp_decrypt_data_key(
            private_key,
            ciphertext,
            ciphertext_length,
            plaintext,
            plaintext_capacity,
            plaintext_length
        );
    }
    if (private_key != NULL) CFRelease(private_key);
    CFRelease(label);
    CFRelease(application_tag);
    return status;
}

__attribute__((visibility("hidden")))
int32_t keyclasp_hardware_key_wrap(
    const uint8_t *public_key_bytes,
    size_t public_key_length,
    const uint8_t *plaintext,
    size_t plaintext_length,
    uint8_t *ciphertext,
    size_t ciphertext_capacity,
    size_t *ciphertext_length
) {
    const SecKeyAlgorithm algorithm =
        kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM;
    if (public_key_bytes == NULL || public_key_length != 65
        || plaintext == NULL || plaintext_length != 32 || ciphertext == NULL
        || ciphertext_capacity == 0 || ciphertext_length == NULL) {
        return KEYCLASP_KEY_FAILED;
    }
    *ciphertext_length = 0;
    CFDataRef representation = CFDataCreateWithBytesNoCopy(
        kCFAllocatorDefault,
        public_key_bytes,
        (CFIndex)public_key_length,
        kCFAllocatorNull
    );
    CFMutableDictionaryRef attributes = keyclasp_dictionary();
    int key_size = 256;
    CFNumberRef size = CFNumberCreate(
        kCFAllocatorDefault,
        kCFNumberIntType,
        &key_size
    );
    if (representation == NULL || attributes == NULL || size == NULL) {
        if (representation != NULL) {
            CFRelease(representation);
        }
        if (attributes != NULL) {
            CFRelease(attributes);
        }
        if (size != NULL) {
            CFRelease(size);
        }
        return KEYCLASP_KEY_FAILED;
    }
    CFDictionarySetValue(attributes, kSecAttrKeyType, kSecAttrKeyTypeECSECPrimeRandom);
    CFDictionarySetValue(attributes, kSecAttrKeyClass, kSecAttrKeyClassPublic);
    CFDictionarySetValue(attributes, kSecAttrKeySizeInBits, size);
    CFErrorRef error = NULL;
    SecKeyRef public_key = SecKeyCreateWithData(representation, attributes, &error);
    CFRelease(size);
    CFRelease(attributes);
    CFRelease(representation);
    if (public_key == NULL) {
        int32_t status = keyclasp_status_from_error(error);
        if (error != NULL) {
            CFRelease(error);
        }
        return status;
    }
    if (error != NULL) {
        CFRelease(error);
        error = NULL;
    }
    if (!SecKeyIsAlgorithmSupported(
            public_key,
            kSecKeyOperationTypeEncrypt,
            algorithm
        )) {
        CFRelease(public_key);
        return KEYCLASP_KEY_UNSUPPORTED;
    }
    CFDataRef cleartext = CFDataCreateWithBytesNoCopy(
        kCFAllocatorDefault,
        plaintext,
        (CFIndex)plaintext_length,
        kCFAllocatorNull
    );
    if (cleartext == NULL) {
        CFRelease(public_key);
        return KEYCLASP_KEY_FAILED;
    }
    CFDataRef encrypted = SecKeyCreateEncryptedData(
        public_key,
        algorithm,
        cleartext,
        &error
    );
    CFRelease(cleartext);
    CFRelease(public_key);
    if (encrypted == NULL) {
        int32_t status = keyclasp_status_from_error(error);
        if (error != NULL) {
            CFRelease(error);
        }
        return status;
    }
    if (error != NULL) {
        CFRelease(error);
    }
    CFIndex length = CFDataGetLength(encrypted);
    if (length <= 0 || ciphertext_capacity < (size_t)length) {
        CFRelease(encrypted);
        return KEYCLASP_KEY_INCOMPLETE;
    }
    memcpy(ciphertext, CFDataGetBytePtr(encrypted), (size_t)length);
    *ciphertext_length = (size_t)length;
    CFRelease(encrypted);
    return KEYCLASP_KEY_OK;
}
