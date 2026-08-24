use crate::platform::{acquire_interprocess_lock, LockError};
use crate::recovery::{RecoveryError, RecoveryPassphrase, RecoveryStore, VerifiedRecovery};
use crate::vault_key::{VaultKeyError, VaultKeyStore};
use std::error::Error;
use std::fmt;
use std::fs;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

const APPLICATION_TAG_PREFIX: &[u8] = b"com.keyclasp.hardware-root.v1\0";
const KEY_LABEL: &str = "Keyclasp hardware root v1";
const P256_PUBLIC_KEY_LENGTH: usize = 65;
const UNCOMPRESSED_POINT_PREFIX: u8 = 0x04;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessPolicy {
    BiometricCurrentSet,
    BiometricAny,
    UserPresence,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum KeyBackendKind {
    SecureEnclave,
    Software,
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CanonicalKeyIdentity {
    vault_home: PathBuf,
    application_tag: Vec<u8>,
    label: &'static str,
    lock_path: PathBuf,
}

impl CanonicalKeyIdentity {
    pub fn for_vault_home(vault_home: &Path) -> Result<Self, LifecycleError> {
        let canonical_home =
            fs::canonicalize(vault_home).map_err(|error| LifecycleError::InvalidVaultHome {
                path: vault_home.to_path_buf(),
                detail: error.to_string(),
            })?;
        let metadata =
            fs::metadata(&canonical_home).map_err(|error| LifecycleError::InvalidVaultHome {
                path: canonical_home.clone(),
                detail: error.to_string(),
            })?;
        if !metadata.is_dir() {
            return Err(LifecycleError::InvalidVaultHome {
                path: canonical_home,
                detail: "vault home is not a directory".to_owned(),
            });
        }

        #[cfg(target_os = "macos")]
        {
            use std::os::unix::fs::MetadataExt;

            if !vault_home_is_secure(
                metadata.uid(),
                metadata.mode(),
                crate::platform::effective_user_id(),
            ) || !crate::platform::directory_secure(&canonical_home)
            {
                return Err(LifecycleError::InvalidVaultHome {
                    path: canonical_home,
                    detail: "vault home must be owned by the current user, mode 0700, and have no extended ACL"
                        .to_owned(),
                });
            }
        }

        #[cfg(unix)]
        let path_bytes = {
            use std::os::unix::ffi::OsStrExt;
            canonical_home.as_os_str().as_bytes()
        };
        #[cfg(not(unix))]
        let path_bytes = canonical_home.to_string_lossy().as_bytes();

        let mut application_tag =
            Vec::with_capacity(APPLICATION_TAG_PREFIX.len() + path_bytes.len());
        application_tag.extend_from_slice(APPLICATION_TAG_PREFIX);
        application_tag.extend_from_slice(path_bytes);

        let lock_path =
            lock_path_for(&canonical_home, &application_tag).ok_or(LifecycleError::LockFailed)?;

        Ok(Self {
            vault_home: canonical_home,
            application_tag,
            label: KEY_LABEL,
            lock_path,
        })
    }

    pub fn application_tag(&self) -> &[u8] {
        &self.application_tag
    }

    pub fn vault_home(&self) -> &Path {
        &self.vault_home
    }

    pub fn label(&self) -> &'static str {
        self.label
    }

    pub fn lock_path(&self) -> &Path {
        &self.lock_path
    }
}

fn lock_path_for(_canonical_home: &Path, application_tag: &[u8]) -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let hash = application_tag
            .iter()
            .fold(0xcbf29ce484222325_u64, |hash, byte| {
                (hash ^ u64::from(*byte)).wrapping_mul(0x100000001b3)
            });
        #[cfg(not(test))]
        let lock_directory = crate::platform::user_lock_directory()?;
        #[cfg(test)]
        let lock_directory = std::env::temp_dir().join(format!(
            "keyclasp-hardware-lock-tests-{}",
            std::process::id()
        ));
        Some(lock_directory.join(format!("hardware-root-v1-{hash:016x}.lock")))
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = application_tag;
        Some(_canonical_home.join(".hardware-root-v1.lock"))
    }
}

#[cfg(target_os = "macos")]
fn vault_home_is_secure(owner: u32, mode: u32, effective_user: u32) -> bool {
    owner == effective_user && mode & 0o7777 == 0o700
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct KeyRecord {
    pub application_tag: Vec<u8>,
    pub label: String,
    pub backend: KeyBackendKind,
    pub required_policy: AccessPolicy,
    pub public_key: Vec<u8>,
}

/// Enrollment metadata whose integrity was verified before hardware-key access.
///
/// The private vault-key store constructs this value only after recovery has
/// authenticated the persisted policy, public key, and both key wrappers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedEnrollment {
    required_policy: AccessPolicy,
    public_key: Vec<u8>,
}

impl AuthenticatedEnrollment {
    pub fn required_policy(&self) -> AccessPolicy {
        self.required_policy
    }

    pub fn public_key(&self) -> &[u8] {
        &self.public_key
    }

    pub(crate) fn from_authenticated_metadata(
        required_policy: AccessPolicy,
        public_key: Vec<u8>,
    ) -> Self {
        Self {
            required_policy,
            public_key,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RecordError {
    IncompleteState(&'static str),
    IdentityMismatch,
    PolicyMismatch,
    BackendMismatch,
    InvalidPublicKey,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackendError {
    AlreadyExists,
    NotFound,
    PermissionDenied,
    Unsupported,
    Failed,
    InvalidRecord(RecordError),
    CleanupFailed,
}

/// Atomic hardware-key operations implemented by one platform boundary.
///
/// `create_new` may use a platform API that persists the key as part of one
/// atomic creation call. While the transaction lock is held, it may perform an
/// exact read-only identity preflight and must prove that exactly one matching
/// key exists after creation. It must call `validate` before returning success
/// and wrap the supplied disposable data key before returning. It must delete
/// that exact new key when validation or wrapping fails. A failed rollback
/// returns `BackendError::CleanupFailed` rather than hiding the partial state.
/// Successful create and open operations include an authorized private-key use.
/// `open_existing` must compare the Keychain public key with the authenticated
/// enrollment before decrypting the wrapped vault key. It performs lookup only:
/// it cannot create, update, migrate, delete, repair, or cache persistent state.
pub trait HardwareKeyBackend {
    fn create_new(
        &mut self,
        identity: &CanonicalKeyIdentity,
        policy: AccessPolicy,
        data_key: &[u8; 32],
        validate: &dyn Fn(&KeyRecord) -> Result<(), RecordError>,
    ) -> Result<(KeyRecord, Vec<u8>), BackendError>;

    fn open_existing(
        &mut self,
        identity: &CanonicalKeyIdentity,
        enrollment: &AuthenticatedEnrollment,
        hardware_ciphertext: &[u8],
        data_key: &mut [u8; 32],
    ) -> Result<KeyRecord, BackendError>;

    /// Delete only the key created by this transaction after a later Rust-side
    /// validation or durable-metadata failure. The backend uses its trusted
    /// creation token, never the record that failed Rust validation. The caller
    /// still holds the transaction lock and must surface cleanup failure.
    fn rollback_created(&mut self) -> Result<(), BackendError>;
}

#[derive(Debug, Eq, PartialEq)]
pub enum LifecycleError {
    AlreadyExists,
    NotFound,
    PermissionDenied,
    Unsupported,
    BackendFailed,
    LockBusy,
    LockFailed,
    IncompleteState(&'static str),
    IdentityMismatch,
    PolicyMismatch,
    BackendMismatch,
    InvalidPublicKey,
    CleanupFailed,
    SecretCaptureUnsafe,
    RecoveryRequired,
    RecoveryAuthenticationFailed,
    RecoveryMetadataInsecure,
    RecoveryMetadataFailed,
    VaultKeyMetadataDamaged,
    VaultKeyMetadataInsecure,
    VaultKeyMetadataFailed,
    VaultKeyActivationIndeterminate,
    VaultKeyMismatch,
    InvalidVaultHome { path: PathBuf, detail: String },
}

impl fmt::Display for LifecycleError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::AlreadyExists => formatter.write_str("hardware key already exists"),
            Self::NotFound => formatter.write_str("hardware key was not found"),
            Self::PermissionDenied => formatter.write_str("hardware key access was denied"),
            Self::Unsupported => formatter.write_str("hardware key operation is unsupported"),
            Self::BackendFailed => formatter.write_str("hardware key backend failed"),
            Self::LockBusy => formatter.write_str("hardware key transaction is already running"),
            Self::LockFailed => formatter.write_str("hardware key transaction lock failed"),
            Self::IncompleteState(field) => {
                write!(formatter, "hardware key state is missing {field}")
            }
            Self::IdentityMismatch => formatter.write_str("hardware key identity does not match"),
            Self::PolicyMismatch => formatter.write_str("hardware key policy does not match"),
            Self::BackendMismatch => formatter.write_str("hardware key backend does not match"),
            Self::InvalidPublicKey => {
                formatter.write_str("hardware key public key is not canonical P-256")
            }
            Self::CleanupFailed => formatter.write_str("hardware key rollback left partial state"),
            Self::SecretCaptureUnsafe => formatter.write_str(
                "secret-bearing operation requires core-dump suppression",
            ),
            Self::RecoveryRequired => formatter.write_str(
                "hardware enrollment requires verified recovery before it can continue",
            ),
            Self::RecoveryAuthenticationFailed => {
                formatter.write_str("hardware recovery authentication failed")
            }
            Self::RecoveryMetadataInsecure => formatter
                .write_str("hardware recovery metadata must be an owner-only regular file"),
            Self::RecoveryMetadataFailed => {
                formatter.write_str("hardware recovery metadata could not be persisted")
            }
            Self::VaultKeyMetadataDamaged => {
                formatter.write_str("wrapped vault-key metadata is damaged")
            }
            Self::VaultKeyMetadataInsecure => formatter
                .write_str("wrapped vault-key metadata must be an owner-only regular file"),
            Self::VaultKeyMetadataFailed => {
                formatter.write_str("wrapped vault-key metadata could not be persisted")
            }
            Self::VaultKeyActivationIndeterminate => formatter.write_str(
                "wrapped vault-key activation may have committed; recovery is required before retry",
            ),
            Self::VaultKeyMismatch => {
                formatter.write_str("hardware and recovery vault-key copies do not match")
            }
            Self::InvalidVaultHome { path, detail } => {
                write!(formatter, "invalid vault home {}: {detail}", path.display())
            }
        }
    }
}

impl Error for LifecycleError {}

impl From<BackendError> for LifecycleError {
    fn from(error: BackendError) -> Self {
        match error {
            BackendError::AlreadyExists => Self::AlreadyExists,
            BackendError::NotFound => Self::NotFound,
            BackendError::PermissionDenied => Self::PermissionDenied,
            BackendError::Unsupported => Self::Unsupported,
            BackendError::Failed => Self::BackendFailed,
            BackendError::InvalidRecord(error) => error.into(),
            BackendError::CleanupFailed => Self::CleanupFailed,
        }
    }
}

impl From<RecordError> for LifecycleError {
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::IncompleteState(field) => Self::IncompleteState(field),
            RecordError::IdentityMismatch => Self::IdentityMismatch,
            RecordError::PolicyMismatch => Self::PolicyMismatch,
            RecordError::BackendMismatch => Self::BackendMismatch,
            RecordError::InvalidPublicKey => Self::InvalidPublicKey,
        }
    }
}

impl From<RecoveryError> for LifecycleError {
    fn from(error: RecoveryError) -> Self {
        match error {
            RecoveryError::AlreadyExists
            | RecoveryError::NotFound
            | RecoveryError::RecoveryRequired => Self::RecoveryRequired,
            RecoveryError::AuthenticationFailed => Self::RecoveryAuthenticationFailed,
            RecoveryError::Insecure => Self::RecoveryMetadataInsecure,
            RecoveryError::Failed => Self::RecoveryMetadataFailed,
        }
    }
}

impl From<VaultKeyError> for LifecycleError {
    fn from(error: VaultKeyError) -> Self {
        match error {
            VaultKeyError::AlreadyActive => Self::AlreadyExists,
            VaultKeyError::NotFound => Self::NotFound,
            VaultKeyError::RecoveryRequired => Self::RecoveryRequired,
            VaultKeyError::AuthenticationFailed => Self::RecoveryAuthenticationFailed,
            VaultKeyError::Damaged => Self::VaultKeyMetadataDamaged,
            VaultKeyError::Insecure => Self::VaultKeyMetadataInsecure,
            VaultKeyError::Failed => Self::VaultKeyMetadataFailed,
            VaultKeyError::ActivationIndeterminate => Self::VaultKeyActivationIndeterminate,
        }
    }
}

pub struct KeyTransaction<B> {
    backend: B,
    identity: CanonicalKeyIdentity,
}

impl<B: HardwareKeyBackend> KeyTransaction<B> {
    pub fn new(backend: B, vault_home: &Path) -> Result<Self, LifecycleError> {
        Ok(Self {
            backend,
            identity: CanonicalKeyIdentity::for_vault_home(vault_home)?,
        })
    }

    pub fn create_new(&mut self, recovery: &VerifiedRecovery) -> Result<KeyRecord, LifecycleError> {
        let capture_guard = crate::platform::prepare_secret_bearing_operation()?;
        let _lock = acquire_interprocess_lock(self.identity.lock_path()).map_err(map_lock_error)?;
        self.create_new_locked(recovery, &capture_guard)
    }

    pub fn create_new_from_recovery_descriptor(
        &mut self,
        descriptor: OwnedFd,
    ) -> Result<KeyRecord, LifecycleError> {
        let capture_guard = crate::platform::prepare_secret_bearing_operation()?;
        let passphrase = RecoveryPassphrase::read_from_descriptor(descriptor, &capture_guard)?;
        let _lock = acquire_interprocess_lock(self.identity.lock_path()).map_err(map_lock_error)?;
        let recovery =
            RecoveryStore::new(self.identity.vault_home()).initialize_or_restore(passphrase)?;
        self.create_new_locked(&recovery, &capture_guard)
    }

    fn create_new_locked(
        &mut self,
        recovery: &VerifiedRecovery,
        _capture_guard: &crate::platform::SecretCaptureGuard,
    ) -> Result<KeyRecord, LifecycleError> {
        let vault_key =
            VaultKeyStore::new(self.identity.vault_home(), self.identity.application_tag());
        let data_key = vault_key.begin(recovery)?;
        let validate = |record: &KeyRecord| validate_record(&self.identity, record);
        let (record, hardware_ciphertext) = self.backend.create_new(
            &self.identity,
            AccessPolicy::BiometricCurrentSet,
            data_key.as_bytes(),
            &validate,
        )?;
        let result = validate(&record)
            .map_err(LifecycleError::from)
            .and_then(|()| {
                vault_key
                    .activate(recovery, &data_key, &record, &hardware_ciphertext)
                    .map_err(LifecycleError::from)
            });
        if let Err(error) = result {
            if error == LifecycleError::VaultKeyActivationIndeterminate {
                return Err(error);
            }
            return match self.backend.rollback_created() {
                Ok(()) => Err(error),
                Err(_) => Err(LifecycleError::CleanupFailed),
            };
        }
        Ok(record)
    }

    pub fn open_existing(
        &mut self,
        recovery: &VerifiedRecovery,
    ) -> Result<KeyRecord, LifecycleError> {
        let capture_guard = crate::platform::prepare_secret_bearing_operation()?;
        let _lock = acquire_interprocess_lock(self.identity.lock_path()).map_err(map_lock_error)?;
        self.open_existing_locked(recovery, &capture_guard)
    }

    pub fn open_existing_from_recovery_descriptor(
        &mut self,
        descriptor: OwnedFd,
    ) -> Result<KeyRecord, LifecycleError> {
        let capture_guard = crate::platform::prepare_secret_bearing_operation()?;
        let passphrase = RecoveryPassphrase::read_from_descriptor(descriptor, &capture_guard)?;
        let _lock = acquire_interprocess_lock(self.identity.lock_path()).map_err(map_lock_error)?;
        let recovery = RecoveryStore::new(self.identity.vault_home()).restore_owned(passphrase)?;
        self.open_existing_locked(&recovery, &capture_guard)
    }

    fn open_existing_locked(
        &mut self,
        recovery: &VerifiedRecovery,
        _capture_guard: &crate::platform::SecretCaptureGuard,
    ) -> Result<KeyRecord, LifecycleError> {
        let active_key =
            VaultKeyStore::new(self.identity.vault_home(), self.identity.application_tag())
                .load_active(recovery)?;
        let enrollment = active_key.authenticated_enrollment();
        validate_enrollment(&enrollment).map_err(LifecycleError::from)?;
        let mut hardware_data_key = Zeroizing::new([0; 32]);
        let record = self.backend.open_existing(
            &self.identity,
            &enrollment,
            &active_key.hardware_ciphertext,
            &mut hardware_data_key,
        )?;
        if let Err(error) = validate_record(&self.identity, &record) {
            return Err(error.into());
        }
        if record.public_key != enrollment.public_key {
            return Err(LifecycleError::IdentityMismatch);
        }
        let matches = active_key.data_key.matches(&hardware_data_key);
        if !matches {
            return Err(LifecycleError::VaultKeyMismatch);
        }
        Ok(record)
    }
}

fn validate_enrollment(enrollment: &AuthenticatedEnrollment) -> Result<(), RecordError> {
    if enrollment.required_policy != AccessPolicy::BiometricCurrentSet {
        return Err(RecordError::PolicyMismatch);
    }
    validate_public_key(&enrollment.public_key)
}

fn validate_record(identity: &CanonicalKeyIdentity, record: &KeyRecord) -> Result<(), RecordError> {
    if record.application_tag != identity.application_tag || record.label != identity.label {
        return Err(RecordError::IdentityMismatch);
    }
    if record.backend != KeyBackendKind::SecureEnclave {
        return Err(RecordError::BackendMismatch);
    }
    if record.required_policy != AccessPolicy::BiometricCurrentSet {
        return Err(RecordError::PolicyMismatch);
    }
    if record.public_key.is_empty() {
        return Err(RecordError::IncompleteState("public key"));
    }
    validate_public_key(&record.public_key)
}

fn validate_public_key(public_key: &[u8]) -> Result<(), RecordError> {
    if public_key.len() != P256_PUBLIC_KEY_LENGTH
        || public_key[0] != UNCOMPRESSED_POINT_PREFIX
        || !crate::platform::p256_public_key_valid(public_key)
    {
        return Err(RecordError::InvalidPublicKey);
    }
    Ok(())
}

fn map_lock_error(error: LockError) -> LifecycleError {
    match error {
        LockError::Busy => LifecycleError::LockBusy,
        LockError::Failed => LifecycleError::LockFailed,
        #[cfg(not(target_os = "macos"))]
        LockError::Unsupported => LifecycleError::Unsupported,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::owner_file::{take_sync_events, SyncEvent};
    use std::env;
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);
    const RECOVERY_TEST_PASSPHRASE: &[u8] = b"hardware recovery passphrase";

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Operation {
        Create,
        Open,
        Rollback,
    }

    struct RecordingBackend {
        existing: Option<KeyRecord>,
        trace: Vec<Operation>,
        writes: usize,
        next_error: Option<BackendError>,
        rollback_error: Option<BackendError>,
        required_pending_path: Option<PathBuf>,
        unwrap_mask: u8,
    }

    impl RecordingBackend {
        fn empty() -> Self {
            Self {
                existing: None,
                trace: Vec::new(),
                writes: 0,
                next_error: None,
                rollback_error: None,
                required_pending_path: None,
                unwrap_mask: 0xa5,
            }
        }

        fn complete(identity: &CanonicalKeyIdentity) -> Self {
            Self {
                existing: Some(complete_record(identity)),
                trace: Vec::new(),
                writes: 0,
                next_error: None,
                rollback_error: None,
                required_pending_path: None,
                unwrap_mask: 0xa5,
            }
        }

        fn requiring_pending(mut self, path: PathBuf) -> Self {
            self.required_pending_path = Some(path);
            self
        }

        fn with_unwrap_mask(mut self, mask: u8) -> Self {
            self.unwrap_mask = mask;
            self
        }

        fn with_rollback_error(mut self, error: BackendError) -> Self {
            self.rollback_error = Some(error);
            self
        }
    }

    impl HardwareKeyBackend for RecordingBackend {
        fn create_new(
            &mut self,
            identity: &CanonicalKeyIdentity,
            policy: AccessPolicy,
            data_key: &[u8; 32],
            validate: &dyn Fn(&KeyRecord) -> Result<(), RecordError>,
        ) -> Result<(KeyRecord, Vec<u8>), BackendError> {
            if let Some(path) = &self.required_pending_path {
                assert!(
                    path.is_file(),
                    "recovery-wrapped vault key must predate hardware-key creation"
                );
                let events = take_sync_events();
                let expected_temp_name = format!("{}.tmp", crate::vault_key::FILE_NAME);
                let file_sync = events
                    .iter()
                    .position(|event| match event {
                        SyncEvent::File(event_path) => {
                            event_path.file_name().and_then(|name| name.to_str())
                                == Some(expected_temp_name.as_str())
                        }
                        SyncEvent::Directory(_) => false,
                    })
                    .expect("vault-key temporary file sync before hardware creation");
                let expected_parent = fs::canonicalize(path.parent().expect("vault-key parent"))
                    .expect("canonical vault-key parent");
                let directory_sync = events
                    .iter()
                    .rposition(|event| event == &SyncEvent::Directory(expected_parent.clone()))
                    .expect("vault directory sync before hardware creation");
                assert!(file_sync < directory_sync);
            }
            self.trace.push(Operation::Create);
            if let Some(error) = self.next_error.take() {
                return Err(error);
            }
            if self.existing.is_some() {
                return Err(BackendError::AlreadyExists);
            }
            let mut record = complete_record(identity);
            record.required_policy = policy;
            validate(&record).map_err(BackendError::InvalidRecord)?;
            self.existing = Some(record.clone());
            self.writes += 1;
            let hardware_ciphertext = data_key.iter().map(|byte| *byte ^ 0xa5).collect();
            Ok((record, hardware_ciphertext))
        }

        fn open_existing(
            &mut self,
            _identity: &CanonicalKeyIdentity,
            enrollment: &AuthenticatedEnrollment,
            hardware_ciphertext: &[u8],
            data_key: &mut [u8; 32],
        ) -> Result<KeyRecord, BackendError> {
            self.trace.push(Operation::Open);
            if let Some(error) = self.next_error.take() {
                return Err(error);
            }
            let _ = enrollment;
            if hardware_ciphertext.len() != data_key.len() {
                return Err(BackendError::Failed);
            }
            for (output, encrypted) in data_key.iter_mut().zip(hardware_ciphertext) {
                *output = *encrypted ^ self.unwrap_mask;
            }
            self.existing.clone().ok_or(BackendError::NotFound)
        }

        fn rollback_created(&mut self) -> Result<(), BackendError> {
            self.trace.push(Operation::Rollback);
            if let Some(error) = self.rollback_error.take() {
                return Err(error);
            }
            if self.existing.take().is_some() {
                Ok(())
            } else {
                Err(BackendError::CleanupFailed)
            }
        }
    }

    fn complete_record(identity: &CanonicalKeyIdentity) -> KeyRecord {
        KeyRecord {
            application_tag: identity.application_tag().to_vec(),
            label: identity.label().to_owned(),
            backend: KeyBackendKind::SecureEnclave,
            required_policy: AccessPolicy::BiometricCurrentSet,
            public_key: valid_p256_public_key(),
        }
    }

    fn valid_p256_public_key() -> Vec<u8> {
        vec![
            0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
            0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
            0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
        ]
    }

    fn different_valid_p256_public_key() -> Vec<u8> {
        vec![
            0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
            0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
            0x45, 0xd8, 0x98, 0xc2, 0x96, 0xb0, 0x1c, 0xbd, 0x1c, 0x01, 0xe5, 0x80, 0x65, 0x71,
            0x18, 0x14, 0xb5, 0x83, 0xf0, 0x61, 0xe9, 0xd4, 0x31, 0xcc, 0xa9, 0x94, 0xce, 0xa1,
            0x31, 0x34, 0x49, 0xbf, 0x97, 0xc8, 0x40, 0xae, 0x0a,
        ]
    }

    fn recovery() -> VerifiedRecovery {
        VerifiedRecovery::for_test(0xa5)
    }

    fn recovery_descriptor(directory: &Path, bytes: &[u8]) -> OwnedFd {
        let path = directory.join(format!(
            "recovery-input-{}",
            NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, bytes).expect("write recovery input");
        std::fs::File::open(path)
            .expect("open recovery input")
            .into()
    }

    fn activate_lifecycle(
        _directory: &TestDirectory,
        identity: &CanonicalKeyIdentity,
        record: &KeyRecord,
        recovery: &VerifiedRecovery,
    ) {
        let vault_store = VaultKeyStore::new(identity.vault_home(), identity.application_tag());
        let data_key = vault_store
            .begin(recovery)
            .expect("begin vault-key metadata");
        let hardware_ciphertext = data_key
            .as_bytes()
            .iter()
            .map(|byte| *byte ^ 0xa5)
            .collect::<Vec<_>>();
        vault_store
            .activate(recovery, &data_key, record, &hardware_ciphertext)
            .expect("activate vault-key metadata");
    }

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = env::temp_dir().join(format!(
                "keyclasp-transaction-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create transaction test directory");
            #[cfg(target_os = "macos")]
            {
                use std::os::unix::fs::PermissionsExt;
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                    .expect("set owner-only transaction test directory mode");
            }
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove transaction test directory");
        }
    }

    #[test]
    fn identity_binds_application_tag_and_lock_to_canonical_vault_home() {
        let directory = TestDirectory::new();
        let canonical_home = fs::canonicalize(&directory.0).expect("canonical test directory");
        let identity = CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
        assert!(identity
            .application_tag()
            .starts_with(APPLICATION_TAG_PREFIX));
        assert!(identity
            .application_tag()
            .ends_with(canonical_home.as_os_str().as_encoded_bytes()));
        assert_eq!(
            identity.lock_path(),
            lock_path_for(&canonical_home, identity.application_tag())
                .expect("resolve expected lock path")
        );
        assert!(!crate::platform::user_lock_directory()
            .expect("resolve production lock directory")
            .starts_with("/private/tmp"));
    }

    #[test]
    fn create_persists_recovery_copy_before_hardware_creation() {
        let directory = TestDirectory::new();
        let identity = CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
        let backend = RecordingBackend::empty()
            .requiring_pending(directory.0.join(crate::vault_key::FILE_NAME));
        let mut transaction = KeyTransaction::new(backend, &directory.0).expect("transaction");
        let recovery = recovery();

        let record = transaction.create_new(&recovery).expect("create new");
        assert_eq!(record.required_policy, AccessPolicy::BiometricCurrentSet);
        let enrollment = VaultKeyStore::new(identity.vault_home(), identity.application_tag())
            .load_active(&recovery)
            .expect("load committed enrollment");
        assert_eq!(enrollment.public_key, record.public_key);

        let backend = transaction.backend;
        assert_eq!(backend.trace, vec![Operation::Create]);
        assert_eq!(backend.writes, 1);
    }

    #[test]
    fn passphrase_recovery_restores_lifecycle_after_process_restart() {
        let directory = TestDirectory::new();
        let identity = CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
        let passphrase = RECOVERY_TEST_PASSPHRASE;
        let original = {
            let mut transaction = KeyTransaction::new(RecordingBackend::empty(), &directory.0)
                .expect("create transaction");
            transaction
                .create_new_from_recovery_descriptor(recovery_descriptor(&directory.0, passphrase))
                .expect("create with recovery passphrase")
        };

        let mut restarted =
            KeyTransaction::new(RecordingBackend::complete(&identity), &directory.0)
                .expect("restarted transaction");
        assert_eq!(
            restarted.open_existing_from_recovery_descriptor(recovery_descriptor(
                &directory.0,
                b"wrong recovery passphrase"
            )),
            Err(LifecycleError::RecoveryAuthenticationFailed)
        );
        assert!(restarted.backend.trace.is_empty());
        assert_eq!(
            restarted.open_existing_from_recovery_descriptor(recovery_descriptor(
                &directory.0,
                passphrase
            )),
            Ok(original)
        );
        assert_eq!(restarted.backend.trace, vec![Operation::Open]);

        let status = Command::new(env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "transaction::tests::passphrase_recovery_probe_child",
                "--nocapture",
            ])
            .env("KEYCLASP_RECOVERY_PROBE_HOME", &directory.0)
            .status()
            .expect("run recovery child");
        assert!(status.success());
    }

    #[test]
    fn create_resumes_after_recovery_envelope_commits_before_lifecycle_state() {
        let directory = TestDirectory::new();
        let identity = CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
        let passphrase = RECOVERY_TEST_PASSPHRASE;
        RecoveryStore::new(identity.vault_home())
            .initialize_for_test(passphrase)
            .expect("commit recovery envelope");

        let mut restarted = KeyTransaction::new(RecordingBackend::empty(), &directory.0)
            .expect("restarted transaction");
        assert!(restarted
            .create_new_from_recovery_descriptor(recovery_descriptor(&directory.0, passphrase))
            .is_ok());
        assert_eq!(restarted.backend.trace, vec![Operation::Create]);
        assert_eq!(restarted.backend.writes, 1);
    }

    #[test]
    fn unreadable_just_committed_recovery_blocks_backend_creation() {
        let directory = TestDirectory::new();
        let passphrase = RECOVERY_TEST_PASSPHRASE;
        let recovery_path = directory.0.join(crate::recovery::FILE_NAME);
        crate::recovery::truncate_after_create();

        let mut transaction = KeyTransaction::new(RecordingBackend::empty(), &directory.0)
            .expect("create transaction");
        assert_eq!(
            transaction
                .create_new_from_recovery_descriptor(recovery_descriptor(&directory.0, passphrase)),
            Err(LifecycleError::RecoveryAuthenticationFailed)
        );
        assert!(transaction.backend.trace.is_empty());
        assert_eq!(transaction.backend.writes, 0);
        assert_eq!(
            fs::metadata(recovery_path)
                .expect("recovery metadata")
                .len(),
            0
        );
        assert!(!directory.0.join(crate::vault_key::FILE_NAME).exists());
    }

    #[test]
    fn duplicate_create_fails_without_replacement() {
        let directory = TestDirectory::new();
        let identity = CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
        let original = complete_record(&identity);
        let backend = RecordingBackend::complete(&identity);
        let mut transaction = KeyTransaction::new(backend, &directory.0).expect("transaction");
        let recovery = recovery();

        assert_eq!(
            transaction.create_new(&recovery),
            Err(LifecycleError::AlreadyExists)
        );

        let backend = transaction.backend;
        assert_eq!(backend.existing, Some(original));
        assert_eq!(backend.trace, vec![Operation::Create]);
        assert_eq!(backend.writes, 0);
    }

    #[test]
    fn open_existing_is_read_only() {
        let directory = TestDirectory::new();
        let identity = CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
        let original = complete_record(&identity);
        let recovery = recovery();
        activate_lifecycle(&directory, &identity, &original, &recovery);
        let backend = RecordingBackend::complete(&identity);
        let mut transaction = KeyTransaction::new(backend, &directory.0).expect("transaction");

        assert_eq!(transaction.open_existing(&recovery), Ok(original.clone()));

        let backend = transaction.backend;
        assert_eq!(backend.existing, Some(original));
        assert_eq!(backend.trace, vec![Operation::Open]);
        assert_eq!(backend.writes, 0);
    }

    #[test]
    fn open_rejects_a_hardware_copy_that_differs_from_recovery() {
        let directory = TestDirectory::new();
        let identity = CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
        let original = complete_record(&identity);
        let recovery = recovery();
        activate_lifecycle(&directory, &identity, &original, &recovery);
        let backend = RecordingBackend::complete(&identity).with_unwrap_mask(0x5a);
        let mut transaction = KeyTransaction::new(backend, &directory.0).expect("transaction");

        assert_eq!(
            transaction.open_existing(&recovery),
            Err(LifecycleError::VaultKeyMismatch)
        );
        assert_eq!(transaction.backend.trace, vec![Operation::Open]);
        assert_eq!(transaction.backend.writes, 0);
    }

    #[test]
    fn open_rejects_wrong_recovery_before_backend_access() {
        let directory = TestDirectory::new();
        let identity = CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
        let correct_recovery = recovery();
        activate_lifecycle(
            &directory,
            &identity,
            &complete_record(&identity),
            &correct_recovery,
        );
        let backend = RecordingBackend::complete(&identity);
        let mut transaction = KeyTransaction::new(backend, &directory.0).expect("transaction");

        assert_eq!(
            transaction.open_existing(&VerifiedRecovery::for_test(0x5a)),
            Err(LifecycleError::RecoveryAuthenticationFailed)
        );
        assert!(transaction.backend.trace.is_empty());
        assert_eq!(transaction.backend.writes, 0);
    }

    #[test]
    fn strict_results_reject_incomplete_or_mismatched_records() {
        let directory = TestDirectory::new();
        let identity = CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
        let recovery = recovery();
        activate_lifecycle(
            &directory,
            &identity,
            &complete_record(&identity),
            &recovery,
        );

        let mut cases = Vec::new();
        let mut incomplete = complete_record(&identity);
        incomplete.public_key.clear();
        cases.push((incomplete, LifecycleError::IncompleteState("public key")));
        let mut truncated = complete_record(&identity);
        truncated.public_key.pop();
        cases.push((truncated, LifecycleError::InvalidPublicKey));
        let mut compressed = complete_record(&identity);
        compressed.public_key[0] = 0x02;
        cases.push((compressed, LifecycleError::InvalidPublicKey));
        let mut off_curve = complete_record(&identity);
        off_curve.public_key.fill(0);
        off_curve.public_key[0] = UNCOMPRESSED_POINT_PREFIX;
        cases.push((off_curve, LifecycleError::InvalidPublicKey));
        let mut wrong_tag = complete_record(&identity);
        wrong_tag.application_tag.push(0);
        cases.push((wrong_tag, LifecycleError::IdentityMismatch));
        let mut wrong_policy = complete_record(&identity);
        wrong_policy.required_policy = AccessPolicy::BiometricAny;
        cases.push((wrong_policy, LifecycleError::PolicyMismatch));
        let mut wrong_backend = complete_record(&identity);
        wrong_backend.backend = KeyBackendKind::Software;
        cases.push((wrong_backend, LifecycleError::BackendMismatch));
        let mut different_key = complete_record(&identity);
        different_key.public_key = different_valid_p256_public_key();
        cases.push((different_key, LifecycleError::IdentityMismatch));

        for (record, expected) in cases {
            let backend = RecordingBackend {
                existing: Some(record),
                trace: Vec::new(),
                writes: 0,
                next_error: None,
                rollback_error: None,
                required_pending_path: None,
                unwrap_mask: 0xa5,
            };
            let mut transaction = KeyTransaction::new(backend, &directory.0).expect("transaction");
            assert_eq!(transaction.open_existing(&recovery), Err(expected));
            let backend = transaction.backend;
            assert_eq!(backend.trace, vec![Operation::Open]);
            assert_eq!(backend.writes, 0);
        }
    }

    #[test]
    fn post_backend_validation_failure_rolls_back_the_exact_created_key() {
        struct PostReturnInvalidBackend {
            created: Option<KeyRecord>,
            returned: KeyRecord,
            trace: Vec<Operation>,
        }

        impl HardwareKeyBackend for PostReturnInvalidBackend {
            fn create_new(
                &mut self,
                identity: &CanonicalKeyIdentity,
                _policy: AccessPolicy,
                _data_key: &[u8; 32],
                validate: &dyn Fn(&KeyRecord) -> Result<(), RecordError>,
            ) -> Result<(KeyRecord, Vec<u8>), BackendError> {
                self.trace.push(Operation::Create);
                let created = complete_record(identity);
                validate(&created).map_err(BackendError::InvalidRecord)?;
                self.created = Some(created);
                Ok((self.returned.clone(), vec![0; 32]))
            }

            fn open_existing(
                &mut self,
                _identity: &CanonicalKeyIdentity,
                _enrollment: &AuthenticatedEnrollment,
                _hardware_ciphertext: &[u8],
                _data_key: &mut [u8; 32],
            ) -> Result<KeyRecord, BackendError> {
                Err(BackendError::NotFound)
            }

            fn rollback_created(&mut self) -> Result<(), BackendError> {
                self.trace.push(Operation::Rollback);
                if self.created.take().is_some() {
                    Ok(())
                } else {
                    Err(BackendError::CleanupFailed)
                }
            }
        }

        let directory = TestDirectory::new();
        let identity = CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
        let mut record = complete_record(&identity);
        record.public_key.pop();
        let backend = PostReturnInvalidBackend {
            created: None,
            returned: record,
            trace: Vec::new(),
        };
        let mut transaction = KeyTransaction::new(backend, &directory.0).expect("transaction");
        let recovery = recovery();

        assert_eq!(
            transaction.create_new(&recovery),
            Err(LifecycleError::InvalidPublicKey)
        );
        assert_eq!(
            transaction.backend.trace,
            vec![Operation::Create, Operation::Rollback]
        );
        assert!(transaction.backend.created.is_none());
    }

    #[test]
    fn backend_failures_remain_typed_through_create_and_open() {
        for (backend_error, lifecycle_error) in [
            (BackendError::AlreadyExists, LifecycleError::AlreadyExists),
            (BackendError::NotFound, LifecycleError::NotFound),
            (
                BackendError::PermissionDenied,
                LifecycleError::PermissionDenied,
            ),
            (BackendError::Unsupported, LifecycleError::Unsupported),
            (BackendError::Failed, LifecycleError::BackendFailed),
            (BackendError::CleanupFailed, LifecycleError::CleanupFailed),
        ] {
            for operation in [Operation::Create, Operation::Open] {
                let directory = TestDirectory::new();
                let mut backend = RecordingBackend::empty();
                backend.next_error = Some(backend_error);
                let recovery = recovery();
                if operation == Operation::Open {
                    let identity =
                        CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
                    activate_lifecycle(
                        &directory,
                        &identity,
                        &complete_record(&identity),
                        &recovery,
                    );
                }
                let mut transaction =
                    KeyTransaction::new(backend, &directory.0).expect("transaction");

                let result = match operation {
                    Operation::Create => transaction.create_new(&recovery),
                    Operation::Open => transaction.open_existing(&recovery),
                    Operation::Rollback => unreachable!("rollback is not an entrypoint"),
                };
                assert_eq!(result.as_ref().err(), Some(&lifecycle_error));
                assert_eq!(transaction.backend.trace, vec![operation]);
                assert_eq!(transaction.backend.writes, 0);
            }
        }
    }

    #[test]
    fn recovery_failures_remain_typed() {
        for (source, expected) in [
            (
                RecoveryError::AlreadyExists,
                LifecycleError::RecoveryRequired,
            ),
            (RecoveryError::NotFound, LifecycleError::RecoveryRequired),
            (
                RecoveryError::RecoveryRequired,
                LifecycleError::RecoveryRequired,
            ),
            (
                RecoveryError::AuthenticationFailed,
                LifecycleError::RecoveryAuthenticationFailed,
            ),
            (
                RecoveryError::Insecure,
                LifecycleError::RecoveryMetadataInsecure,
            ),
            (
                RecoveryError::Failed,
                LifecycleError::RecoveryMetadataFailed,
            ),
        ] {
            assert_eq!(LifecycleError::from(source), expected);
        }
    }

    #[test]
    fn failed_passphrase_create_restores_recovery_and_blocks_duplicate_backend_work() {
        let directory = TestDirectory::new();
        let passphrase = RECOVERY_TEST_PASSPHRASE;
        let mut backend = RecordingBackend::empty();
        backend.next_error = Some(BackendError::Failed);
        let mut transaction =
            KeyTransaction::new(backend, &directory.0).expect("create transaction");
        assert_eq!(
            transaction
                .create_new_from_recovery_descriptor(recovery_descriptor(&directory.0, passphrase)),
            Err(LifecycleError::BackendFailed)
        );
        assert_eq!(transaction.backend.trace, vec![Operation::Create]);
        assert!(directory.0.join(crate::recovery::FILE_NAME).is_file());
        assert!(directory.0.join(crate::vault_key::FILE_NAME).is_file());

        let mut restarted = KeyTransaction::new(RecordingBackend::empty(), &directory.0)
            .expect("restarted transaction");
        assert_eq!(
            restarted
                .create_new_from_recovery_descriptor(recovery_descriptor(&directory.0, passphrase)),
            Err(LifecycleError::RecoveryRequired)
        );
        assert!(restarted.backend.trace.is_empty());
    }

    #[test]
    fn failed_create_leaves_authenticated_pending_state_and_blocks_retry() {
        let directory = TestDirectory::new();
        let recovery = recovery();
        let mut backend = RecordingBackend::empty();
        backend.next_error = Some(BackendError::Failed);
        let mut transaction = KeyTransaction::new(backend, &directory.0).expect("transaction");

        assert_eq!(
            transaction.create_new(&recovery),
            Err(LifecycleError::BackendFailed)
        );
        assert_eq!(transaction.backend.trace, vec![Operation::Create]);

        let backend = RecordingBackend::empty();
        let mut retry = KeyTransaction::new(backend, &directory.0).expect("retry transaction");
        assert_eq!(
            retry.create_new(&recovery),
            Err(LifecycleError::RecoveryRequired)
        );
        assert!(retry.backend.trace.is_empty());
        assert_eq!(retry.backend.writes, 0);
    }

    #[test]
    fn activation_failure_rolls_back_the_exact_created_key() {
        let directory = TestDirectory::new();
        let recovery = recovery();
        crate::vault_key::fail_next_activate();
        let mut transaction =
            KeyTransaction::new(RecordingBackend::empty(), &directory.0).expect("transaction");

        assert_eq!(
            transaction.create_new(&recovery),
            Err(LifecycleError::VaultKeyMetadataFailed)
        );
        assert_eq!(
            transaction.backend.trace,
            vec![Operation::Create, Operation::Rollback]
        );
        assert!(transaction.backend.existing.is_none());
    }

    #[test]
    fn rollback_failure_after_activation_failure_surfaces_cleanup_failed() {
        let directory = TestDirectory::new();
        let recovery = recovery();
        crate::vault_key::fail_next_activate();
        let backend = RecordingBackend::empty().with_rollback_error(BackendError::Failed);
        let mut transaction = KeyTransaction::new(backend, &directory.0).expect("transaction");

        assert_eq!(
            transaction.create_new(&recovery),
            Err(LifecycleError::CleanupFailed)
        );
        assert_eq!(
            transaction.backend.trace,
            vec![Operation::Create, Operation::Rollback]
        );
        assert!(transaction.backend.existing.is_some());
    }

    #[test]
    fn post_rename_activation_failure_keeps_the_created_key_for_recovery() {
        let directory = TestDirectory::new();
        let recovery = recovery();
        crate::owner_file::fail_next_post_rename_sync();
        let mut transaction =
            KeyTransaction::new(RecordingBackend::empty(), &directory.0).expect("transaction");

        assert_eq!(
            transaction.create_new(&recovery),
            Err(LifecycleError::VaultKeyActivationIndeterminate)
        );
        assert_eq!(transaction.backend.trace, vec![Operation::Create]);
        assert!(transaction.backend.existing.is_some());

        let mut retry = KeyTransaction::new(RecordingBackend::empty(), &directory.0)
            .expect("retry transaction");
        assert_eq!(
            retry.create_new(&recovery),
            Err(LifecycleError::AlreadyExists)
        );
        assert!(retry.backend.trace.is_empty());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lock_rejects_symlinks_and_non_owner_permissions() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let directory = TestDirectory::new();
        let target = directory.0.join("target.lock");
        fs::write(&target, []).expect("create target lock file");
        let symlink_path = directory.0.join("symlink.lock");
        symlink(&target, &symlink_path).expect("create lock symlink");
        assert!(matches!(
            acquire_interprocess_lock(&symlink_path).map_err(map_lock_error),
            Err(LifecycleError::LockFailed)
        ));

        let permissive_path = directory.0.join("permissive.lock");
        fs::write(&permissive_path, []).expect("create permissive lock file");
        fs::set_permissions(&permissive_path, fs::Permissions::from_mode(0o644))
            .expect("set permissive lock mode");
        assert!(matches!(
            acquire_interprocess_lock(&permissive_path).map_err(map_lock_error),
            Err(LifecycleError::LockFailed)
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn identity_rejects_non_owner_only_vault_home() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o755))
            .expect("set insecure vault mode");

        assert!(matches!(
            CanonicalKeyIdentity::for_vault_home(&directory.0),
            Err(LifecycleError::InvalidVaultHome { .. })
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn identity_rejects_vault_home_with_extended_acl() {
        let directory = TestDirectory::new();
        let status = Command::new("/bin/chmod")
            .args(["+a", "everyone allow readattr"])
            .arg(&directory.0)
            .status()
            .expect("add test ACL");
        assert!(status.success());

        let result = CanonicalKeyIdentity::for_vault_home(&directory.0);

        let cleanup = Command::new("/bin/chmod")
            .arg("-N")
            .arg(&directory.0)
            .status()
            .expect("remove test ACL");
        assert!(cleanup.success());
        assert!(matches!(
            result,
            Err(LifecycleError::InvalidVaultHome { .. })
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn owner_only_predicate_rejects_foreign_owner_and_extra_permissions() {
        let effective_user = crate::platform::effective_user_id();
        assert!(vault_home_is_secure(
            effective_user,
            0o40700,
            effective_user
        ));
        assert!(!vault_home_is_secure(
            effective_user.wrapping_add(1),
            0o40700,
            effective_user
        ));
        assert!(!vault_home_is_secure(
            effective_user,
            0o40750,
            effective_user
        ));
        assert!(!vault_home_is_secure(
            effective_user,
            0o40500,
            effective_user
        ));
        assert!(!vault_home_is_secure(
            effective_user,
            0o40600,
            effective_user
        ));
        assert!(!vault_home_is_secure(
            effective_user,
            0o47700,
            effective_user
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lock_domain_survives_vault_directory_replacement() {
        use std::os::unix::fs::PermissionsExt;

        let directory = TestDirectory::new();
        let original = CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
        let parked = directory.0.with_extension("parked");
        fs::rename(&directory.0, &parked).expect("park original vault home");
        fs::create_dir(&directory.0).expect("create replacement vault home");
        fs::set_permissions(&directory.0, fs::Permissions::from_mode(0o700))
            .expect("secure replacement vault home");
        let replacement =
            CanonicalKeyIdentity::for_vault_home(&directory.0).expect("replacement identity");

        assert_eq!(original.application_tag(), replacement.application_tag());
        assert_eq!(original.lock_path(), replacement.lock_path());
        fs::remove_dir_all(parked).expect("remove parked vault home");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn interprocess_lock_probe_child() {
        let Ok(path) = env::var("KEYCLASP_LOCK_PROBE_PATH") else {
            return;
        };
        let expect_busy = env::var("KEYCLASP_LOCK_EXPECT_BUSY").as_deref() == Ok("1");
        let result = acquire_interprocess_lock(Path::new(&path)).map_err(map_lock_error);
        if expect_busy {
            assert!(matches!(result, Err(LifecycleError::LockBusy)));
        } else {
            assert!(result.is_ok());
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn passphrase_recovery_probe_child() {
        let Ok(home) = env::var("KEYCLASP_RECOVERY_PROBE_HOME") else {
            return;
        };
        let identity = CanonicalKeyIdentity::for_vault_home(Path::new(&home)).expect("identity");
        let mut transaction =
            KeyTransaction::new(RecordingBackend::complete(&identity), Path::new(&home))
                .expect("recovery child transaction");
        assert!(transaction
            .open_existing_from_recovery_descriptor(recovery_descriptor(
                Path::new(&home),
                RECOVERY_TEST_PASSPHRASE
            ))
            .is_ok());
        assert_eq!(transaction.backend.trace, vec![Operation::Open]);
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn lock_serializes_separate_processes() {
        let directory = TestDirectory::new();
        let identity = CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
        let path = identity.lock_path().to_path_buf();
        let lock = acquire_interprocess_lock(&path).expect("parent lock");

        run_lock_child(&path, true);
        drop(lock);
        run_lock_child(&path, false);
    }

    #[cfg(target_os = "macos")]
    fn run_lock_child(path: &Path, expect_busy: bool) {
        let status = Command::new(env::current_exe().expect("test executable"))
            .args([
                "--exact",
                "transaction::tests::interprocess_lock_probe_child",
                "--nocapture",
            ])
            .env("KEYCLASP_LOCK_PROBE_PATH", path)
            .env(
                "KEYCLASP_LOCK_EXPECT_BUSY",
                if expect_busy { "1" } else { "0" },
            )
            .status()
            .expect("run lock child");
        assert!(status.success());
    }
}
