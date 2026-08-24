use std::fmt;
use std::path::Path;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CodeIdentity {
    Development,
    Unsigned,
    AdHoc,
    DeveloperId,
    Unknown,
}

impl CodeIdentity {
    #[cfg(target_os = "macos")]
    fn from_signing_facts(facts: i32) -> Self {
        Self::from_signing_facts_with_build_identity(facts, option_env!("KEYCLASP_BUILD_IDENTITY"))
    }

    #[cfg(target_os = "macos")]
    fn from_signing_facts_with_build_identity(facts: i32, build_identity: Option<&str>) -> Self {
        const VALID: i32 = 1 << 0;
        const UNSIGNED: i32 = 1 << 1;
        const AD_HOC: i32 = 1 << 2;
        const DEVELOPER_ID: i32 = 1 << 3;

        if facts & VALID != 0 && facts & DEVELOPER_ID != 0 {
            Self::DeveloperId
        } else if facts & VALID != 0 && facts & AD_HOC != 0 {
            if build_identity == Some("ad_hoc") {
                Self::AdHoc
            } else {
                Self::Development
            }
        } else if facts & UNSIGNED != 0 {
            Self::Unsigned
        } else {
            Self::Unknown
        }
    }
}

impl fmt::Display for CodeIdentity {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let value = match self {
            Self::Development => "development",
            Self::Unsigned => "unsigned",
            Self::AdHoc => "ad_hoc",
            Self::DeveloperId => "developer_id",
            Self::Unknown => "unknown",
        };
        formatter.write_str(value)
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct Capabilities {
    pub backend: &'static str,
    pub hardware_presence: bool,
    pub touch_id_available: bool,
    pub code_identity: CodeIdentity,
    pub current_set_policy_available: bool,
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod macos {
    use super::{HardwareKeyBridgeError, InterprocessLock, LockError};
    use std::ffi::c_void;
    use std::os::unix::ffi::OsStrExt;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::path::Path;

    unsafe extern "C" {
        fn keyclasp_hardware_presence() -> i32;
        fn keyclasp_touch_id_available() -> i32;
        fn keyclasp_current_set_policy_available() -> i32;
        fn keyclasp_code_signing_facts() -> i32;
        fn keyclasp_effective_user_id() -> u32;
        fn keyclasp_user_lock_directory(
            buffer: *mut u8,
            capacity: usize,
            length: *mut usize,
        ) -> i32;
        fn keyclasp_p256_public_key_valid(bytes: *const u8, length: usize) -> i32;
        fn keyclasp_directory_secure(path: *const u8, length: usize) -> i32;
        fn keyclasp_file_descriptor_secure(descriptor: i32) -> i32;
        fn keyclasp_hmac_sha256(
            key: *const u8,
            key_length: usize,
            data: *const u8,
            data_length: usize,
            output: *mut u8,
            output_length: usize,
        ) -> i32;
        fn keyclasp_hmac_sha256_verify(
            key: *const u8,
            key_length: usize,
            data: *const u8,
            data_length: usize,
            expected: *const u8,
            expected_length: usize,
        ) -> i32;
        fn keyclasp_random_bytes(output: *mut u8, output_length: usize) -> i32;
        fn keyclasp_aes_gcm_seal(
            key: *const u8,
            key_length: isize,
            nonce: *const u8,
            nonce_length: isize,
            authenticated_data: *const u8,
            authenticated_data_length: isize,
            plaintext: *const u8,
            plaintext_length: isize,
            ciphertext: *mut u8,
            ciphertext_capacity: isize,
            tag: *mut u8,
            tag_capacity: isize,
        ) -> i32;
        fn keyclasp_aes_gcm_open(
            key: *const u8,
            key_length: isize,
            nonce: *const u8,
            nonce_length: isize,
            authenticated_data: *const u8,
            authenticated_data_length: isize,
            ciphertext: *const u8,
            ciphertext_length: isize,
            tag: *const u8,
            tag_length: isize,
            plaintext: *mut u8,
            plaintext_capacity: isize,
        ) -> i32;
        fn keyclasp_explicit_bzero(bytes: *mut u8, length: usize);
        fn keyclasp_prepare_secret_bearing_operation() -> i32;
        fn keyclasp_lock_acquire(path: *const u8, length: usize, descriptor: *mut i32) -> i32;
        fn keyclasp_lock_release(descriptor: i32);
        fn keyclasp_hardware_key_create(
            application_tag: *const u8,
            application_tag_length: usize,
            label: *const u8,
            label_length: usize,
            validator: Option<unsafe extern "C" fn(*mut c_void, *const u8, usize) -> i32>,
            validator_context: *mut c_void,
            data_key: *const u8,
            data_key_length: usize,
            hardware_ciphertext: *mut u8,
            hardware_ciphertext_capacity: usize,
            hardware_ciphertext_length: *mut usize,
            public_key: *mut u8,
            public_key_capacity: usize,
            public_key_length: *mut usize,
        ) -> i32;
        fn keyclasp_hardware_key_open(
            application_tag: *const u8,
            application_tag_length: usize,
            label: *const u8,
            label_length: usize,
            expected_public_key: *const u8,
            expected_public_key_length: usize,
            ciphertext: *const u8,
            ciphertext_length: usize,
            public_key: *mut u8,
            public_key_capacity: usize,
            public_key_length: *mut usize,
            plaintext: *mut u8,
            plaintext_capacity: usize,
            plaintext_length: *mut usize,
        ) -> i32;
        fn keyclasp_hardware_key_delete_exact(
            application_tag: *const u8,
            application_tag_length: usize,
            label: *const u8,
            label_length: usize,
            expected_public_key: *const u8,
            expected_public_key_length: usize,
        ) -> i32;
        fn keyclasp_ecies_qualification() -> i32;
    }

    pub fn hardware_presence() -> bool {
        // SAFETY: the Swift bridge defines this zero-argument function and returns an Int32.
        unsafe { keyclasp_hardware_presence() == 1 }
    }

    pub fn touch_id_available() -> bool {
        // SAFETY: the Swift bridge defines this zero-argument function and returns an Int32.
        unsafe { keyclasp_touch_id_available() == 1 }
    }

    pub fn current_set_policy_available() -> bool {
        // SAFETY: the Swift bridge defines this zero-argument function and returns an Int32.
        unsafe { keyclasp_current_set_policy_available() == 1 }
    }

    pub fn code_signing_facts() -> i32 {
        // SAFETY: the Swift bridge defines this zero-argument function and returns an Int32.
        unsafe { keyclasp_code_signing_facts() }
    }

    pub fn effective_user_id() -> u32 {
        // SAFETY: the C bridge defines this zero-argument function and returns uid_t as uint32_t.
        unsafe { keyclasp_effective_user_id() }
    }

    pub fn user_lock_directory() -> Option<std::path::PathBuf> {
        use std::ffi::OsString;
        use std::os::unix::ffi::OsStringExt;

        let mut buffer = vec![0; 4096];
        let mut length = 0;
        // SAFETY: the C helper writes at most `buffer.len()` bytes, reports the
        // initialized length, and does not retain either pointer.
        let status =
            unsafe { keyclasp_user_lock_directory(buffer.as_mut_ptr(), buffer.len(), &mut length) };
        if status != 1 || length > buffer.len() {
            return None;
        }
        buffer.truncate(length);
        Some(std::path::PathBuf::from(OsString::from_vec(buffer)))
    }

    pub fn p256_public_key_valid(bytes: &[u8]) -> bool {
        // SAFETY: the C helper reads exactly `bytes.len()` bytes during the call
        // and does not retain the pointer.
        unsafe { keyclasp_p256_public_key_valid(bytes.as_ptr(), bytes.len()) == 1 }
    }

    pub fn directory_secure(path: &Path) -> bool {
        let bytes = path.as_os_str().as_bytes();
        // SAFETY: the C helper copies the path during the call and does not
        // retain the pointer.
        unsafe { keyclasp_directory_secure(bytes.as_ptr(), bytes.len()) == 1 }
    }

    pub fn file_descriptor_secure(descriptor: i32) -> bool {
        // SAFETY: the C helper inspects but does not retain the live descriptor.
        unsafe { keyclasp_file_descriptor_secure(descriptor) == 1 }
    }

    pub fn hmac_sha256_into(key: &[u8], data: &[u8], output: &mut [u8; 32]) -> bool {
        // SAFETY: every slice remains live for the call, and the helper writes
        // exactly `output.len()` bytes on success without retaining pointers.
        let status = unsafe {
            keyclasp_hmac_sha256(
                key.as_ptr(),
                key.len(),
                data.as_ptr(),
                data.len(),
                output.as_mut_ptr(),
                output.len(),
            )
        };
        status == 1
    }

    pub fn hmac_sha256_verify(key: &[u8], data: &[u8], expected: &[u8; 32]) -> bool {
        // SAFETY: all inputs remain live for the call. The helper compares a
        // stack-local MAC with `timingsafe_bcmp` and retains no pointers.
        unsafe {
            keyclasp_hmac_sha256_verify(
                key.as_ptr(),
                key.len(),
                data.as_ptr(),
                data.len(),
                expected.as_ptr(),
                expected.len(),
            ) == 1
        }
    }

    pub fn random_bytes(output: &mut [u8]) -> bool {
        // SAFETY: the helper initializes exactly `output.len()` bytes and
        // retains no pointer.
        unsafe { keyclasp_random_bytes(output.as_mut_ptr(), output.len()) == 1 }
    }

    pub fn aes_gcm_seal(
        key: &[u8; 32],
        nonce: &[u8; 12],
        authenticated_data: &[u8],
        plaintext: &[u8; 32],
    ) -> Option<([u8; 32], [u8; 16])> {
        let mut ciphertext = [0; 32];
        let mut tag = [0; 16];
        // SAFETY: all inputs and outputs remain live for the synchronous Swift
        // call, whose fixed-size guards match these arrays.
        let status = unsafe {
            keyclasp_aes_gcm_seal(
                key.as_ptr(),
                key.len() as isize,
                nonce.as_ptr(),
                nonce.len() as isize,
                authenticated_data.as_ptr(),
                authenticated_data.len() as isize,
                plaintext.as_ptr(),
                plaintext.len() as isize,
                ciphertext.as_mut_ptr(),
                ciphertext.len() as isize,
                tag.as_mut_ptr(),
                tag.len() as isize,
            )
        };
        (status == 1).then_some((ciphertext, tag))
    }

    pub fn aes_gcm_open(
        key: &[u8; 32],
        nonce: &[u8; 12],
        authenticated_data: &[u8],
        ciphertext: &[u8; 32],
        tag: &[u8; 16],
        plaintext: &mut [u8; 32],
    ) -> bool {
        // SAFETY: all inputs and the output remain live for the synchronous
        // Swift call, whose fixed-size guards match these arrays.
        unsafe {
            keyclasp_aes_gcm_open(
                key.as_ptr(),
                key.len() as isize,
                nonce.as_ptr(),
                nonce.len() as isize,
                authenticated_data.as_ptr(),
                authenticated_data.len() as isize,
                ciphertext.as_ptr(),
                ciphertext.len() as isize,
                tag.as_ptr(),
                tag.len() as isize,
                plaintext.as_mut_ptr(),
                plaintext.len() as isize,
            ) == 1
        }
    }

    pub fn zeroize(bytes: &mut [u8]) {
        // SAFETY: the helper overwrites exactly this live mutable slice and
        // retains no pointer.
        unsafe { keyclasp_explicit_bzero(bytes.as_mut_ptr(), bytes.len()) };
    }

    pub fn prepare_secret_bearing_operation() -> bool {
        // SAFETY: the C bridge changes only this process's core-dump resource
        // limit and reports whether the zero limit was installed and read back.
        unsafe { keyclasp_prepare_secret_bearing_operation() == 1 }
    }

    pub fn acquire_lock(path: &Path) -> Result<InterprocessLock, LockError> {
        let bytes = path.as_os_str().as_bytes();
        let mut descriptor = -1;
        // SAFETY: the C helper copies `bytes` before returning and initializes
        // `descriptor` only on success. The slice remains alive for the call.
        let status = unsafe { keyclasp_lock_acquire(bytes.as_ptr(), bytes.len(), &mut descriptor) };
        match status {
            0 => Ok(InterprocessLock { descriptor }),
            1 => Err(LockError::Busy),
            _ => Err(LockError::Failed),
        }
    }

    pub fn release_lock(descriptor: i32) {
        // SAFETY: successful acquisition transfers one live descriptor to the
        // guard, and Drop releases it exactly once.
        unsafe { keyclasp_lock_release(descriptor) };
    }

    struct ValidatorContext<'a> {
        validator: &'a mut dyn FnMut(&[u8]) -> Result<(), HardwareKeyBridgeError>,
    }

    unsafe extern "C" fn validate_public_key(
        context: *mut c_void,
        public_key: *const u8,
        public_key_length: usize,
    ) -> i32 {
        if context.is_null() || public_key.is_null() {
            return HardwareKeyBridgeError::Failed.code();
        }
        // SAFETY: `create_hardware_key` passes a live stack context and the C
        // bridge keeps both pointers only for this callback.
        let context = unsafe { &mut *context.cast::<ValidatorContext<'_>>() };
        // SAFETY: the C bridge owns a buffer of `public_key_length` bytes for
        // the duration of this callback.
        let bytes = unsafe { std::slice::from_raw_parts(public_key, public_key_length) };
        match catch_unwind(AssertUnwindSafe(|| (context.validator)(bytes))) {
            Ok(Ok(())) => 0,
            Ok(Err(error)) => error.code(),
            Err(_) => HardwareKeyBridgeError::Failed.code(),
        }
    }

    pub fn create_hardware_key(
        application_tag: &[u8],
        label: &str,
        data_key: &[u8; 32],
        validator: &mut dyn FnMut(&[u8]) -> Result<(), HardwareKeyBridgeError>,
    ) -> Result<(Vec<u8>, Vec<u8>), HardwareKeyBridgeError> {
        let mut public_key = vec![0; 65];
        let mut public_key_length = 0;
        let mut hardware_ciphertext = vec![0; 512];
        let mut hardware_ciphertext_length = 0;
        let mut context = ValidatorContext { validator };
        // SAFETY: all slices and output storage remain live for the call. The
        // C bridge invokes the callback synchronously and retains no pointers.
        let status = unsafe {
            keyclasp_hardware_key_create(
                application_tag.as_ptr(),
                application_tag.len(),
                label.as_ptr(),
                label.len(),
                Some(validate_public_key),
                (&mut context as *mut ValidatorContext<'_>).cast(),
                data_key.as_ptr(),
                data_key.len(),
                hardware_ciphertext.as_mut_ptr(),
                hardware_ciphertext.len(),
                &mut hardware_ciphertext_length,
                public_key.as_mut_ptr(),
                public_key.len(),
                &mut public_key_length,
            )
        };
        HardwareKeyBridgeError::result(status)?;
        if public_key_length != public_key.len() {
            return Err(HardwareKeyBridgeError::InvalidPublicKey);
        }
        if hardware_ciphertext_length == 0 || hardware_ciphertext_length > hardware_ciphertext.len()
        {
            return Err(HardwareKeyBridgeError::Incomplete);
        }
        hardware_ciphertext.truncate(hardware_ciphertext_length);
        Ok((public_key, hardware_ciphertext))
    }

    pub fn open_hardware_key(
        application_tag: &[u8],
        label: &str,
        expected_public_key: &[u8],
        ciphertext: &[u8],
        plaintext: &mut [u8; 32],
    ) -> Result<Vec<u8>, HardwareKeyBridgeError> {
        let mut public_key = vec![0; 65];
        let mut public_key_length = 0;
        let mut plaintext_length = 0;
        // SAFETY: all slices and output storage remain live for the call, and
        // the C bridge retains no pointers.
        let status = unsafe {
            keyclasp_hardware_key_open(
                application_tag.as_ptr(),
                application_tag.len(),
                label.as_ptr(),
                label.len(),
                expected_public_key.as_ptr(),
                expected_public_key.len(),
                ciphertext.as_ptr(),
                ciphertext.len(),
                public_key.as_mut_ptr(),
                public_key.len(),
                &mut public_key_length,
                plaintext.as_mut_ptr(),
                plaintext.len(),
                &mut plaintext_length,
            )
        };
        HardwareKeyBridgeError::result(status)?;
        if public_key_length != public_key.len() {
            zeroize(plaintext);
            return Err(HardwareKeyBridgeError::InvalidPublicKey);
        }
        if plaintext_length != plaintext.len() {
            zeroize(plaintext);
            return Err(HardwareKeyBridgeError::Incomplete);
        }
        Ok(public_key)
    }

    pub fn delete_exact_hardware_key(
        application_tag: &[u8],
        label: &str,
        expected_public_key: &[u8],
    ) -> Result<(), HardwareKeyBridgeError> {
        let status = unsafe {
            keyclasp_hardware_key_delete_exact(
                application_tag.as_ptr(),
                application_tag.len(),
                label.as_ptr(),
                label.len(),
                expected_public_key.as_ptr(),
                expected_public_key.len(),
            )
        };
        HardwareKeyBridgeError::result(status)
    }

    pub fn ecies_qualification() -> Result<(), HardwareKeyBridgeError> {
        HardwareKeyBridgeError::result(unsafe { keyclasp_ecies_qualification() })
    }
}

#[cfg(target_os = "macos")]
pub(crate) fn effective_user_id() -> u32 {
    macos::effective_user_id()
}

pub(crate) fn user_lock_directory() -> Option<std::path::PathBuf> {
    #[cfg(target_os = "macos")]
    {
        macos::user_lock_directory()
    }

    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

pub(crate) fn p256_public_key_valid(bytes: &[u8]) -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::p256_public_key_valid(bytes)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = bytes;
        false
    }
}

pub(crate) fn directory_secure(path: &Path) -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::directory_secure(path)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        false
    }
}

pub(crate) fn file_descriptor_secure(descriptor: i32) -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::file_descriptor_secure(descriptor)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = descriptor;
        false
    }
}

pub(crate) fn hmac_sha256_into(key: &[u8], data: &[u8], output: &mut [u8; 32]) -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::hmac_sha256_into(key, data, output)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (key, data, output);
        false
    }
}

pub(crate) fn hmac_sha256_verify(key: &[u8], data: &[u8], expected: &[u8; 32]) -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::hmac_sha256_verify(key, data, expected)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (key, data, expected);
        false
    }
}

pub(crate) fn random_bytes(output: &mut [u8]) -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::random_bytes(output)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = output;
        false
    }
}

pub(crate) fn aes_gcm_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    authenticated_data: &[u8],
    plaintext: &[u8; 32],
) -> Option<([u8; 32], [u8; 16])> {
    #[cfg(target_os = "macos")]
    {
        macos::aes_gcm_seal(key, nonce, authenticated_data, plaintext)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (key, nonce, authenticated_data, plaintext);
        None
    }
}

pub(crate) fn aes_gcm_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    authenticated_data: &[u8],
    ciphertext: &[u8; 32],
    tag: &[u8; 16],
    plaintext: &mut [u8; 32],
) -> bool {
    #[cfg(target_os = "macos")]
    {
        macos::aes_gcm_open(key, nonce, authenticated_data, ciphertext, tag, plaintext)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (key, nonce, authenticated_data, ciphertext, tag, plaintext);
        false
    }
}

pub(crate) fn zeroize(bytes: &mut [u8]) {
    #[cfg(target_os = "macos")]
    macos::zeroize(bytes);

    #[cfg(not(target_os = "macos"))]
    bytes.fill(0);
}

/// Prevent OS core files before the private lifecycle can receive a recovery
/// passphrase or request a hardware unwrap. This is deliberately process-wide
/// and irreversible for the short-lived native core.
///
/// This does not claim to wipe Security.framework's opaque `CFData` allocation
/// or to control externally configured macOS crash reporting. The executable
/// remains status-only until those physical and release controls are reviewed.
pub(crate) struct SecretCaptureGuard(());

pub(crate) fn prepare_secret_bearing_operation(
) -> Result<SecretCaptureGuard, crate::transaction::LifecycleError> {
    #[cfg(target_os = "macos")]
    {
        macos::prepare_secret_bearing_operation()
            .then_some(SecretCaptureGuard(()))
            .ok_or(crate::transaction::LifecycleError::SecretCaptureUnsafe)
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err(crate::transaction::LifecycleError::SecretCaptureUnsafe)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum HardwareKeyBridgeError {
    AlreadyExists,
    NotFound,
    PermissionDenied,
    Unsupported,
    Failed,
    Incomplete,
    IdentityMismatch,
    PolicyMismatch,
    BackendMismatch,
    InvalidPublicKey,
    CleanupFailed,
}

impl HardwareKeyBridgeError {
    fn code(self) -> i32 {
        match self {
            Self::AlreadyExists => 1,
            Self::NotFound => 2,
            Self::PermissionDenied => 3,
            Self::Unsupported => 4,
            Self::Failed => 5,
            Self::Incomplete => 6,
            Self::IdentityMismatch => 7,
            Self::PolicyMismatch => 8,
            Self::BackendMismatch => 9,
            Self::InvalidPublicKey => 10,
            Self::CleanupFailed => 11,
        }
    }

    fn result(status: i32) -> Result<(), Self> {
        match status {
            0 => Ok(()),
            1 => Err(Self::AlreadyExists),
            2 => Err(Self::NotFound),
            3 => Err(Self::PermissionDenied),
            4 => Err(Self::Unsupported),
            6 => Err(Self::Incomplete),
            7 => Err(Self::IdentityMismatch),
            8 => Err(Self::PolicyMismatch),
            9 => Err(Self::BackendMismatch),
            10 => Err(Self::InvalidPublicKey),
            11 => Err(Self::CleanupFailed),
            _ => Err(Self::Failed),
        }
    }
}

pub(crate) fn create_hardware_key(
    application_tag: &[u8],
    label: &str,
    data_key: &[u8; 32],
    validator: &mut dyn FnMut(&[u8]) -> Result<(), HardwareKeyBridgeError>,
) -> Result<(Vec<u8>, Vec<u8>), HardwareKeyBridgeError> {
    #[cfg(target_os = "macos")]
    {
        macos::create_hardware_key(application_tag, label, data_key, validator)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (application_tag, label, data_key, validator);
        Err(HardwareKeyBridgeError::Unsupported)
    }
}

pub(crate) fn delete_exact_hardware_key(
    application_tag: &[u8],
    label: &str,
    expected_public_key: &[u8],
) -> Result<(), HardwareKeyBridgeError> {
    #[cfg(target_os = "macos")]
    {
        macos::delete_exact_hardware_key(application_tag, label, expected_public_key)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (application_tag, label, expected_public_key);
        Err(HardwareKeyBridgeError::Unsupported)
    }
}

/// Compile and execute an ephemeral ECIES round-trip/tamper check. It has no
/// parameters and returns no cryptographic material; the status executable
/// never calls it.
pub(crate) fn ecies_qualification() -> Result<(), HardwareKeyBridgeError> {
    #[cfg(target_os = "macos")]
    {
        macos::ecies_qualification()
    }

    #[cfg(not(target_os = "macos"))]
    {
        Err(HardwareKeyBridgeError::Unsupported)
    }
}

pub(crate) fn open_hardware_key(
    application_tag: &[u8],
    label: &str,
    expected_public_key: &[u8],
    ciphertext: &[u8],
    plaintext: &mut [u8; 32],
) -> Result<Vec<u8>, HardwareKeyBridgeError> {
    #[cfg(target_os = "macos")]
    {
        macos::open_hardware_key(
            application_tag,
            label,
            expected_public_key,
            ciphertext,
            plaintext,
        )
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (
            application_tag,
            label,
            expected_public_key,
            ciphertext,
            plaintext,
        );
        Err(HardwareKeyBridgeError::Unsupported)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LockError {
    Busy,
    Failed,
    #[cfg(not(target_os = "macos"))]
    Unsupported,
}

pub(crate) struct InterprocessLock {
    #[cfg(target_os = "macos")]
    descriptor: i32,
}

pub(crate) fn acquire_interprocess_lock(path: &Path) -> Result<InterprocessLock, LockError> {
    #[cfg(target_os = "macos")]
    {
        macos::acquire_lock(path)
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = path;
        Err(LockError::Unsupported)
    }
}

impl Drop for InterprocessLock {
    fn drop(&mut self) {
        #[cfg(target_os = "macos")]
        macos::release_lock(self.descriptor);
    }
}

pub fn capabilities() -> Capabilities {
    #[cfg(target_os = "macos")]
    {
        Capabilities {
            backend: "secure_enclave",
            hardware_presence: macos::hardware_presence(),
            touch_id_available: macos::touch_id_available(),
            code_identity: CodeIdentity::from_signing_facts(macos::code_signing_facts()),
            current_set_policy_available: macos::current_set_policy_available(),
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        Capabilities {
            backend: "unsupported",
            hardware_presence: false,
            touch_id_available: false,
            code_identity: CodeIdentity::Unknown,
            current_set_policy_available: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(target_os = "macos")]
    const SWIFT_BRIDGE: &str = include_str!("../swift/macos_adapter.swift");
    #[cfg(target_os = "macos")]
    const C_BRIDGE: &str = include_str!("../c/dynamic_code.c");
    #[cfg(target_os = "macos")]
    const SECURITY_BACKEND: &str = include_str!("../c/security_backend.c");
    const TRANSACTION: &str = include_str!("transaction.rs");
    #[cfg(target_os = "macos")]
    const METADATA_CRYPTO: &str = include_str!("../c/metadata_crypto.c");
    #[cfg(target_os = "macos")]
    const RECOVERY_CRYPTO: &str = include_str!("../swift/recovery_crypto.swift");

    #[test]
    fn identity_values_are_stable() {
        assert_eq!(CodeIdentity::Development.to_string(), "development");
        assert_eq!(CodeIdentity::Unsigned.to_string(), "unsigned");
        assert_eq!(CodeIdentity::AdHoc.to_string(), "ad_hoc");
        assert_eq!(CodeIdentity::DeveloperId.to_string(), "developer_id");
        assert_eq!(CodeIdentity::Unknown.to_string(), "unknown");
    }

    #[test]
    fn hardware_bridge_error_codes_round_trip() {
        for error in [
            HardwareKeyBridgeError::AlreadyExists,
            HardwareKeyBridgeError::NotFound,
            HardwareKeyBridgeError::PermissionDenied,
            HardwareKeyBridgeError::Unsupported,
            HardwareKeyBridgeError::Failed,
            HardwareKeyBridgeError::Incomplete,
            HardwareKeyBridgeError::IdentityMismatch,
            HardwareKeyBridgeError::PolicyMismatch,
            HardwareKeyBridgeError::BackendMismatch,
            HardwareKeyBridgeError::InvalidPublicKey,
            HardwareKeyBridgeError::CleanupFailed,
        ] {
            assert_eq!(HardwareKeyBridgeError::result(error.code()), Err(error));
        }
        assert_eq!(HardwareKeyBridgeError::result(0), Ok(()));
        assert_eq!(
            HardwareKeyBridgeError::result(i32::MAX),
            Err(HardwareKeyBridgeError::Failed)
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bridge_exposes_current_set_policy() {
        let report = capabilities();
        assert_eq!(report.backend, "secure_enclave");
        assert!(report.current_set_policy_available);
        assert_eq!(report.code_identity, CodeIdentity::Development);
        assert_eq!(CodeIdentity::from_signing_facts(0), CodeIdentity::Unknown);
        assert_eq!(
            CodeIdentity::from_signing_facts(1 << 1),
            CodeIdentity::Unsigned
        );
        assert_eq!(
            CodeIdentity::from_signing_facts((1 << 0) | (1 << 2)),
            CodeIdentity::Development
        );
        assert_eq!(
            CodeIdentity::from_signing_facts_with_build_identity(
                (1 << 0) | (1 << 2),
                Some("ad_hoc")
            ),
            CodeIdentity::AdHoc
        );
        assert_eq!(
            CodeIdentity::from_signing_facts((1 << 0) | (1 << 3)),
            CodeIdentity::DeveloperId
        );
        assert_eq!(
            CodeIdentity::from_signing_facts(1 << 0),
            CodeIdentity::Unknown
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn status_bridge_remains_current_set_and_non_mutating() {
        assert!(SWIFT_BRIDGE.contains("[.privateKeyUsage, .biometryCurrentSet]"));
        assert!(SWIFT_BRIDGE.contains("certificate leaf[field.1.2.840.113635.100.6.1.13] exists"));
        assert_eq!(SWIFT_BRIDGE.matches("@_cdecl(").count(), 4);
        for required_export in [
            "@_cdecl(\"keyclasp_hardware_presence\")",
            "@_cdecl(\"keyclasp_touch_id_available\")",
            "@_cdecl(\"keyclasp_current_set_policy_available\")",
            "@_cdecl(\"keyclasp_code_signing_facts\")",
        ] {
            assert!(SWIFT_BRIDGE.contains(required_export));
        }
        for forbidden in [
            ".biometryAny",
            ".userPresence",
            "SecItemAdd",
            "SecItemUpdate",
            "SecItemDelete",
            "SecItemCopyMatching",
            "SecKeyCreateRandomKey",
            "SecureEnclave.P256",
        ] {
            assert!(
                !SWIFT_BRIDGE.contains(forbidden) && !C_BRIDGE.contains(forbidden),
                "status adapter contains forbidden mutating or weaker API: {forbidden}"
            );
        }
        assert!(C_BRIDGE.contains("__attribute__((visibility(\"hidden\")))"));
        assert!(C_BRIDGE.contains("csops(getpid(), KEYCLASP_CS_OPS_STATUS"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn security_backend_creation_and_rollback_source_contract() {
        for required in [
            "kSecAttrTokenIDSecureEnclave",
            "kSecAccessControlBiometryCurrentSet | kSecAccessControlPrivateKeyUsage",
            "kSecAttrAccessibleWhenUnlockedThisDeviceOnly",
            "SecKeyCreateRandomKey(",
            "SecKeyCreateSignature(",
            "SecKeyVerifySignature(",
            "SecItemCopyMatching(",
            "SecItemDelete(",
            "kSecMatchItemList",
            "kSecMatchLimitAll",
        ] {
            assert!(SECURITY_BACKEND.contains(required), "missing {required}");
        }

        let create = SECURITY_BACKEND
            .split("int32_t keyclasp_hardware_key_create(")
            .nth(1)
            .expect("create function")
            .split("int32_t keyclasp_hardware_key_open(")
            .next()
            .expect("create body");
        let preflight = create.find("keyclasp_count_keys(").expect("preflight");
        let creation = create
            .find("SecKeyCreateRandomKey(")
            .expect("permanent creation");
        let inspection = create
            .find("keyclasp_validate_key(")
            .expect("platform inspection");
        let postcondition = create[inspection + 1..]
            .find("keyclasp_count_keys(")
            .map(|index| index + inspection + 1)
            .expect("singleton postcondition");
        let validation = create.find("status = validator(").expect("Rust validation");
        let wrapping = create
            .find("status = keyclasp_hardware_key_wrap(")
            .expect("hardware wrapping");
        let rollback = create.find("keyclasp_rollback(").expect("exact rollback");
        assert!(preflight < creation);
        assert!(creation < inspection);
        assert!(inspection < postcondition);
        assert!(postcondition < validation);
        assert!(validation < wrapping);
        assert!(wrapping < rollback);

        let exact_delete = SECURITY_BACKEND
            .split("static OSStatus keyclasp_delete_exact_key(")
            .nth(1)
            .expect("exact delete helper")
            .split("static int32_t keyclasp_copy_exact_validated_key(")
            .next()
            .expect("exact delete body");
        assert!(exact_delete.contains("kSecMatchItemList"));
        assert!(!exact_delete.contains("kSecAttrApplicationTag"));
        assert!(!exact_delete.contains("kSecAttrLabel"));

        let validated_lookup = SECURITY_BACKEND
            .split("static int32_t keyclasp_copy_exact_validated_key(")
            .nth(1)
            .expect("validated exact lookup")
            .split("int32_t keyclasp_hardware_key_delete_exact(")
            .next()
            .expect("validated exact lookup body");
        assert!(validated_lookup.contains("SecItemCopyMatching("));
        assert!(validated_lookup.contains("keyclasp_validate_key("));
        assert!(validated_lookup.contains("CFRetain(reference)"));
        assert!(validated_lookup.contains("CFArrayGetCount((CFArrayRef)result) != 1"));
        let lookup = validated_lookup
            .find("SecItemCopyMatching(")
            .expect("exact key lookup");
        let singleton = validated_lookup
            .find("CFArrayGetCount((CFArrayRef)result) != 1")
            .expect("singleton exact key check");
        let validated = validated_lookup
            .find("keyclasp_validate_key(")
            .expect("exact key validation");
        let retained = validated_lookup
            .find("CFRetain(reference)")
            .expect("validated key retain");
        assert!(lookup < singleton);
        assert!(singleton < validated);
        assert!(validated < retained);

        let post_backend_delete = SECURITY_BACKEND
            .split("int32_t keyclasp_hardware_key_delete_exact(")
            .nth(1)
            .expect("post-backend delete")
            .split("int32_t keyclasp_ecies_qualification(void)")
            .next()
            .expect("post-backend delete body");
        assert!(post_backend_delete.contains("keyclasp_copy_exact_validated_key("));
        assert!(post_backend_delete.contains("keyclasp_delete_exact_key(private_key)"));
        assert!(
            post_backend_delete
                .find("keyclasp_copy_exact_validated_key(")
                .expect("validated delete lookup")
                < post_backend_delete
                    .find("keyclasp_delete_exact_key(private_key)")
                    .expect("delete validated key")
        );

        let rollback_body = SECURITY_BACKEND
            .split("static int32_t keyclasp_rollback(")
            .nth(1)
            .expect("rollback helper")
            .split("int32_t keyclasp_hardware_key_create(")
            .next()
            .expect("rollback body");
        assert!(rollback_body.contains("keyclasp_delete_exact_key(private_key)"));
        for forbidden in [
            "kSecAccessControlBiometryAny",
            "kSecAccessControlUserPresence",
            "SecItemAdd(",
            "SecItemUpdate(",
        ] {
            assert!(
                !SECURITY_BACKEND.contains(forbidden),
                "backend contains forbidden API or weaker policy: {forbidden}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn metadata_crypto_uses_sha256_hmac_and_constant_time_verification() {
        for required in [
            "CCHmac(kCCHmacAlgSHA256",
            "timingsafe_bcmp(actual, expected",
            "memset_s(actual",
            "memset_s(bytes",
        ] {
            assert!(METADATA_CRYPTO.contains(required), "missing {required}");
        }
        assert!(!METADATA_CRYPTO.contains("memcmp(actual"));
        assert!(!METADATA_CRYPTO.contains("strcmp("));
        assert!(C_BRIDGE.contains("attributes.st_nlink == 1"));
        assert!(C_BRIDGE.contains("keyclasp_fd_has_extended_acl(descriptor) == 0"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn recovery_crypto_uses_secure_randomness_and_aes_gcm() {
        let random_bytes = METADATA_CRYPTO
            .split("int32_t keyclasp_random_bytes(")
            .nth(1)
            .expect("random-bytes function")
            .split("int32_t keyclasp_hmac_sha256(")
            .next()
            .expect("random-bytes function body");
        assert!(
            random_bytes.contains("CCRandomGenerateBytes(output, output_length)"),
            "random-bytes function does not call CCRandomGenerateBytes"
        );
        for removed in ["CCKeyDerivationPBKDF(", "kCCPBKDF2", "kCCPRFHmacAlgSHA256"] {
            assert!(!METADATA_CRYPTO.contains(removed), "obsolete {removed}");
        }
        for required in [
            "AES.GCM.seal(",
            "AES.GCM.open(",
            "AES.GCM.SealedBox(",
            "recoveryNonceLength = 12",
            "recoveryTagLength = 16",
            "keyData.resetBytes(",
            "plaintextData.resetBytes(",
            "opened.resetBytes(",
        ] {
            assert!(RECOVERY_CRYPTO.contains(required), "missing {required}");
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn security_backend_open_is_one_snapshot_and_read_only() {
        let open = SECURITY_BACKEND
            .split("int32_t keyclasp_hardware_key_open(")
            .nth(1)
            .expect("open function");
        let validated_lookup = SECURITY_BACKEND
            .split("static int32_t keyclasp_copy_exact_validated_key(")
            .nth(1)
            .expect("validated exact lookup")
            .split("int32_t keyclasp_hardware_key_delete_exact(")
            .next()
            .expect("validated exact lookup body");
        assert_eq!(validated_lookup.matches("SecItemCopyMatching(").count(), 1);
        assert_eq!(
            open.matches("keyclasp_copy_exact_validated_key(").count(),
            1
        );
        assert!(!open.contains("SecItemCopyMatching("));
        assert!(open.contains("keyclasp_decrypt_data_key("));
        let private_use_proof = SECURITY_BACKEND
            .split("static int32_t keyclasp_prove_private_key_use(")
            .nth(1)
            .expect("private-key use proof")
            .split("static int32_t keyclasp_validate_key(")
            .next()
            .expect("private-key use proof body");
        assert!(private_use_proof.contains("SecRandomCopyBytes("));
        assert!(private_use_proof.contains("SecKeyCreateSignature("));
        assert!(private_use_proof.contains("SecKeyVerifySignature("));
        let key_validation = SECURITY_BACKEND
            .split("static int32_t keyclasp_validate_key(")
            .nth(1)
            .expect("key validation")
            .split("static int32_t keyclasp_decrypt_data_key(")
            .next()
            .expect("key validation body");
        let public_key_copy = key_validation
            .find("keyclasp_copy_public_key(")
            .expect("public-key extraction");
        let enrollment_match = key_validation
            .find("memcmp(")
            .expect("authenticated enrollment match");
        let authorized_use = key_validation
            .find("? keyclasp_prove_private_key_use(private_key)")
            .expect("private-key use proof call");
        assert!(public_key_copy < enrollment_match);
        assert!(enrollment_match < authorized_use);
        let validation = open
            .find("keyclasp_copy_exact_validated_key(")
            .expect("exact validated lookup");
        let decrypt = open
            .find("keyclasp_decrypt_data_key(")
            .expect("authorized decrypt");
        assert!(validation < decrypt);
        let decrypt_body = SECURITY_BACKEND
            .split("static int32_t keyclasp_decrypt_data_key(")
            .nth(1)
            .expect("decrypt helper")
            .split("static OSStatus keyclasp_delete_exact_key(")
            .next()
            .expect("decrypt helper body");
        assert!(decrypt_body.contains("kSecKeyOperationTypeDecrypt"));
        assert!(decrypt_body.contains("SecKeyCreateDecryptedData("));
        assert!(decrypt_body.contains("memset_s(plaintext"));
        assert!(decrypt_body.contains("framework-owned and cannot be safely cast mutable"));
        assert!(decrypt_body.contains("CFRelease(decrypted)"));
        let capture_guard = SECURITY_BACKEND
            .split("int32_t keyclasp_prepare_secret_bearing_operation(void)")
            .nth(1)
            .expect("secret-capture guard")
            .split("static CFMutableDictionaryRef")
            .next()
            .expect("secret-capture guard body");
        assert!(capture_guard.contains("setrlimit(RLIMIT_CORE"));
        assert!(capture_guard.contains("getrlimit(RLIMIT_CORE"));
        assert!(capture_guard.contains("struct rlimit limit = { 0, 0 };"));
        assert!(capture_guard.contains("observed.rlim_cur == 0"));
        assert!(capture_guard.contains("observed.rlim_max == 0"));
        assert!(
            capture_guard
                .find("setrlimit(RLIMIT_CORE")
                .expect("set core limit")
                < capture_guard
                    .find("getrlimit(RLIMIT_CORE")
                    .expect("read core limit")
        );
        for (entrypoint, terminator, protected_call) in [
            (
                "pub fn create_new(&mut self, recovery:",
                "pub fn create_new_from_recovery_descriptor(",
                "self.create_new_locked(recovery, &capture_guard)",
            ),
            (
                "pub fn create_new_from_recovery_descriptor(",
                "fn create_new_locked(",
                "RecoveryPassphrase::read_from_descriptor(descriptor, &capture_guard)?",
            ),
            (
                "pub fn open_existing(\n",
                "pub fn open_existing_from_recovery_descriptor(",
                "self.open_existing_locked(recovery, &capture_guard)",
            ),
            (
                "pub fn open_existing_from_recovery_descriptor(",
                "fn open_existing_locked(",
                "RecoveryPassphrase::read_from_descriptor(descriptor, &capture_guard)?",
            ),
        ] {
            let operation = TRANSACTION
                .split(entrypoint)
                .nth(1)
                .expect("secret-bearing entrypoint")
                .split(terminator)
                .next()
                .expect("bounded secret-bearing entrypoint");
            let guard = operation
                .find("prepare_secret_bearing_operation()?")
                .expect("capture guard");
            let protected = operation
                .find(protected_call)
                .expect("guarded secret-bearing call");
            assert!(guard < protected);
        }
        let open_with_descriptor = TRANSACTION
            .split("pub fn open_existing_from_recovery_descriptor(")
            .nth(1)
            .expect("owned open entrypoint")
            .split("fn open_existing_locked(")
            .next()
            .expect("owned open body");
        assert!(open_with_descriptor
            .contains("RecoveryPassphrase::read_from_descriptor(descriptor, &capture_guard)?"));
        let wrap = SECURITY_BACKEND
            .split("int32_t keyclasp_hardware_key_wrap(")
            .nth(2)
            .expect("hardware wrapping function");
        assert!(wrap.contains("kSecKeyOperationTypeEncrypt"));
        assert!(wrap.contains("SecKeyCreateEncryptedData("));
        assert!(wrap.contains("kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM"));
        assert!(!open.contains("keyclasp_copy_item_attributes("));
        for forbidden in [
            "SecKeyCreateRandomKey(",
            "SecItemAdd(",
            "SecItemUpdate(",
            "SecItemDelete(",
            "keyclasp_delete_exact_key(",
            "keyclasp_rollback(",
        ] {
            assert!(
                !open.contains(forbidden),
                "open contains mutating API or helper: {forbidden}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn ecies_qualification_round_trip_and_tamper_rejection_compile_and_run() {
        assert_eq!(ecies_qualification(), Ok(()));
        let qualification = SECURITY_BACKEND
            .split("int32_t keyclasp_ecies_qualification(void)")
            .nth(1)
            .expect("ECIES qualification")
            .split("static int32_t keyclasp_rollback(")
            .next()
            .expect("ECIES qualification body");
        for required in [
            "SecKeyCreateWithData(",
            "SecKeyCreateEncryptedData(",
            "SecKeyCreateDecryptedData(",
            "CFDataCreateMutableCopy(",
            "kSecKeyAlgorithmECIESEncryptionStandardVariableIVX963SHA256AESGCM",
        ] {
            assert!(qualification.contains(required), "missing {required}");
        }
        for forbidden in [
            "SecKeyCreateRandomKey(",
            "kSecAttrIsPermanent",
            "kSecAttrTokenIDSecureEnclave",
            "SecItemCopyMatching(",
            "SecItemDelete(",
        ] {
            assert!(!qualification.contains(forbidden), "forbidden {forbidden}");
        }
    }
}
