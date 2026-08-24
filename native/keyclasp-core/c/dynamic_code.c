#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/acl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <Security/Security.h>

// macOS exports csops from libSystem but omits its user-space declaration.
extern int csops(pid_t pid, unsigned int operations, void *address, size_t size);

enum { KEYCLASP_CS_OPS_STATUS = 0 };

__attribute__((visibility("hidden")))
int32_t keyclasp_dynamic_code_status(uint32_t *status) {
    if (status == NULL) {
        return -1;
    }
    int32_t result = csops(getpid(), KEYCLASP_CS_OPS_STATUS, status, sizeof(*status));
    if (result == 0) {
        *status = ntohl(*status);
    }
    return result;
}

__attribute__((visibility("hidden")))
uint32_t keyclasp_effective_user_id(void) {
    return (uint32_t)geteuid();
}

__attribute__((visibility("hidden")))
int32_t keyclasp_user_lock_directory(
    uint8_t *buffer,
    size_t capacity,
    size_t *length
) {
    if (buffer == NULL || length == NULL) {
        return 0;
    }
    struct passwd password;
    struct passwd *result = NULL;
    char storage[16384];
    if (getpwuid_r(geteuid(), &password, storage, sizeof(storage), &result) != 0
        || result == NULL || result->pw_dir == NULL) {
        return 0;
    }

    const char suffix[] = "/.keyclasp-hardware-locks";
    size_t home_length = strlen(result->pw_dir);
    size_t suffix_length = sizeof(suffix) - 1;
    if (home_length == 0 || home_length + suffix_length > capacity) {
        return 0;
    }
    memcpy(buffer, result->pw_dir, home_length);
    memcpy(buffer + home_length, suffix, suffix_length);
    *length = home_length + suffix_length;
    return 1;
}

__attribute__((visibility("hidden")))
int32_t keyclasp_p256_public_key_valid(const uint8_t *bytes, size_t length) {
    if (bytes == NULL || length != 65 || bytes[0] != 0x04) {
        return 0;
    }

    CFDataRef data = CFDataCreate(kCFAllocatorDefault, bytes, (CFIndex)length);
    int key_size = 256;
    CFNumberRef size = CFNumberCreate(
        kCFAllocatorDefault,
        kCFNumberIntType,
        &key_size
    );
    if (data == NULL || size == NULL) {
        if (data != NULL) {
            CFRelease(data);
        }
        if (size != NULL) {
            CFRelease(size);
        }
        return 0;
    }

    const void *keys[] = {
        kSecAttrKeyType,
        kSecAttrKeyClass,
        kSecAttrKeySizeInBits,
    };
    const void *values[] = {
        kSecAttrKeyTypeECSECPrimeRandom,
        kSecAttrKeyClassPublic,
        size,
    };
    CFDictionaryRef attributes = CFDictionaryCreate(
        kCFAllocatorDefault,
        keys,
        values,
        3,
        &kCFTypeDictionaryKeyCallBacks,
        &kCFTypeDictionaryValueCallBacks
    );
    CFErrorRef error = NULL;
    SecKeyRef key = attributes == NULL
        ? NULL
        : SecKeyCreateWithData(data, attributes, &error);

    if (error != NULL) {
        CFRelease(error);
    }
    if (attributes != NULL) {
        CFRelease(attributes);
    }
    CFRelease(size);
    CFRelease(data);
    if (key == NULL) {
        return 0;
    }
    CFRelease(key);
    return 1;
}

enum {
    KEYCLASP_LOCK_OK = 0,
    KEYCLASP_LOCK_BUSY = 1,
    KEYCLASP_LOCK_INVALID = 2,
    KEYCLASP_LOCK_INSECURE = 3,
    KEYCLASP_LOCK_SYSTEM = 4,
};

static int32_t keyclasp_fd_has_extended_acl(int descriptor) {
    errno = 0;
    acl_t acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED);
    if (acl == NULL) {
        return errno == ENOENT ? 0 : -1;
    }
    acl_free(acl);
    return 1;
}

__attribute__((visibility("hidden")))
int32_t keyclasp_file_descriptor_secure(int32_t descriptor) {
    if (descriptor < 0) {
        return 0;
    }
    struct stat attributes;
    return fstat(descriptor, &attributes) == 0
        && S_ISREG(attributes.st_mode)
        && attributes.st_nlink == 1
        && attributes.st_uid == geteuid()
        && (attributes.st_mode & (S_IRWXG | S_IRWXO | S_IXUSR)) == 0
        && (attributes.st_mode & (S_ISUID | S_ISGID | S_ISVTX)) == 0
        && (attributes.st_mode & (S_IRUSR | S_IWUSR)) == (S_IRUSR | S_IWUSR)
        && keyclasp_fd_has_extended_acl(descriptor) == 0;
}

__attribute__((visibility("hidden")))
int32_t keyclasp_directory_secure(const uint8_t *path, size_t length) {
    if (path == NULL || length == 0 || memchr(path, '\0', length) != NULL) {
        return 0;
    }
    char *terminated = malloc(length + 1);
    if (terminated == NULL) {
        return 0;
    }
    memcpy(terminated, path, length);
    terminated[length] = '\0';
    int descriptor = open(
        terminated,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    free(terminated);
    if (descriptor < 0) {
        return 0;
    }

    struct stat attributes;
    int32_t secure = fstat(descriptor, &attributes) == 0
        && S_ISDIR(attributes.st_mode)
        && attributes.st_uid == geteuid()
        && (attributes.st_mode & (S_IRWXU | S_IRWXG | S_IRWXO)) == S_IRWXU
        && (attributes.st_mode & (S_ISUID | S_ISGID | S_ISVTX)) == 0
        && keyclasp_fd_has_extended_acl(descriptor) == 0;
    close(descriptor);
    return secure;
}

__attribute__((visibility("hidden")))
int32_t keyclasp_lock_acquire(
    const uint8_t *path,
    size_t length,
    int32_t *descriptor
) {
    if (path == NULL || length == 0 || descriptor == NULL
        || memchr(path, '\0', length) != NULL) {
        return KEYCLASP_LOCK_INVALID;
    }

    char *terminated = malloc(length + 1);
    if (terminated == NULL) {
        return KEYCLASP_LOCK_SYSTEM;
    }
    memcpy(terminated, path, length);
    terminated[length] = '\0';

    char *separator = strrchr(terminated, '/');
    if (separator == NULL || separator == terminated || separator[1] == '\0') {
        free(terminated);
        return KEYCLASP_LOCK_INVALID;
    }
    *separator = '\0';
    const char *file_name = separator + 1;

    if (mkdir(terminated, S_IRWXU) != 0 && errno != EEXIST) {
        free(terminated);
        return KEYCLASP_LOCK_SYSTEM;
    }

    int directory_fd = open(
        terminated,
        O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW
    );
    if (directory_fd < 0) {
        free(terminated);
        return errno == ELOOP ? KEYCLASP_LOCK_INSECURE : KEYCLASP_LOCK_SYSTEM;
    }

    struct stat directory_attributes;
    if (fstat(directory_fd, &directory_attributes) != 0) {
        close(directory_fd);
        free(terminated);
        return KEYCLASP_LOCK_SYSTEM;
    }
    if (!S_ISDIR(directory_attributes.st_mode)
        || directory_attributes.st_uid != geteuid()
        || (directory_attributes.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        close(directory_fd);
        free(terminated);
        return KEYCLASP_LOCK_INSECURE;
    }
    int32_t directory_acl = keyclasp_fd_has_extended_acl(directory_fd);
    if (directory_acl != 0) {
        close(directory_fd);
        free(terminated);
        return directory_acl > 0 ? KEYCLASP_LOCK_INSECURE : KEYCLASP_LOCK_SYSTEM;
    }

    int fd = openat(
        directory_fd,
        file_name,
        O_CREAT | O_RDWR | O_CLOEXEC | O_NOFOLLOW,
        S_IRUSR | S_IWUSR
    );
    int open_error = errno;
    close(directory_fd);
    free(terminated);
    if (fd < 0) {
        return open_error == ELOOP ? KEYCLASP_LOCK_INSECURE : KEYCLASP_LOCK_SYSTEM;
    }

    struct stat attributes;
    if (fstat(fd, &attributes) != 0) {
        close(fd);
        return KEYCLASP_LOCK_SYSTEM;
    }
    if (!S_ISREG(attributes.st_mode)
        || attributes.st_uid != geteuid()
        || (attributes.st_mode & (S_IRWXG | S_IRWXO)) != 0) {
        close(fd);
        return KEYCLASP_LOCK_INSECURE;
    }
    int32_t file_acl = keyclasp_fd_has_extended_acl(fd);
    if (file_acl != 0) {
        close(fd);
        return file_acl > 0 ? KEYCLASP_LOCK_INSECURE : KEYCLASP_LOCK_SYSTEM;
    }

    if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
        int lock_error = errno;
        close(fd);
        return lock_error == EWOULDBLOCK
            ? KEYCLASP_LOCK_BUSY
            : KEYCLASP_LOCK_SYSTEM;
    }

    *descriptor = fd;
    return KEYCLASP_LOCK_OK;
}

__attribute__((visibility("hidden")))
void keyclasp_lock_release(int32_t descriptor) {
    if (descriptor >= 0) {
        flock(descriptor, LOCK_UN);
        close(descriptor);
    }
}
