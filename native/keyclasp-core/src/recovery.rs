use crate::owner_file::{OwnerFile, OwnerFileError};
use crate::platform::{aes_gcm_open, aes_gcm_seal, random_bytes, zeroize};
use crate::vault_key::FILE_NAME as VAULT_KEY_FILE_NAME;
use argon2::{Algorithm, Argon2, Block, Params, Version};
use std::fs;
use std::io::Read;
use std::os::fd::OwnedFd;
use std::path::{Path, PathBuf};
use zeroize::Zeroize;

pub(crate) const FILE_NAME: &str = ".hardware-recovery.v2";
const LEGACY_FILE_NAME: &str = ".hardware-recovery.v1";
const MAGIC: &[u8; 8] = b"KCHRVR02";
const FORMAT_VERSION: u8 = 2;
const KDF_ARGON2ID: u8 = 2;
const CIPHER_AES_256_GCM: u8 = 1;
const ARGON2_VERSION: u8 = 0x13;
const ARGON2_MEMORY_KIB: u32 = 65_536;
const ARGON2_TIME_COST: u32 = 3;
const ARGON2_PARALLELISM: u32 = 1;
const ROOT_LENGTH: usize = 32;
const SALT_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const MINIMUM_PASSPHRASE_BYTES: usize = 16;
const MAXIMUM_PASSPHRASE_BYTES: usize = 1_024;
const HEADER_LENGTH: usize = 32;
const AAD_LENGTH: usize = HEADER_LENGTH + SALT_LENGTH + NONCE_LENGTH;
const FILE_LENGTH: usize = AAD_LENGTH + TAG_LENGTH + ROOT_LENGTH;

#[cfg(test)]
thread_local! {
    static ARGON2_CALLS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
    static TRUNCATE_AFTER_CREATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LAST_RECOVERY_ZEROIZED: std::cell::Cell<Option<(usize, usize)>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(crate) fn truncate_after_create() {
    TRUNCATE_AFTER_CREATE.with(|enabled| enabled.set(true));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum RecoveryError {
    AlreadyExists,
    NotFound,
    RecoveryRequired,
    AuthenticationFailed,
    Insecure,
    Failed,
}

pub(crate) struct VerifiedRecovery {
    authentication_key: Box<[u8; ROOT_LENGTH]>,
}

/// An owned recovery passphrase. The native core takes this buffer by value so
/// callers cannot retain a mutable secret buffer across a recovery operation.
///
/// The status-only spike exposes no descriptor command yet. Block 4 must bind
/// this private descriptor path directly to terminal or inherited input rather
/// than hand a borrowed buffer through the lifecycle API.
pub(crate) struct RecoveryPassphrase(Vec<u8>);

impl RecoveryPassphrase {
    /// Read the recovery passphrase only after the native core has disabled
    /// traditional core-file capture for this process. There is intentionally
    /// no raw-byte constructor in non-test code.
    pub(crate) fn read_from_descriptor(
        descriptor: OwnedFd,
        _capture_guard: &crate::platform::SecretCaptureGuard,
    ) -> Result<Self, RecoveryError> {
        let reader = std::fs::File::from(descriptor);
        Self::read_from_owned_reader(reader)
    }

    fn read_from_owned_reader<R: Read>(mut reader: R) -> Result<Self, RecoveryError> {
        // Reserve the sentinel byte too: growing after a partial read could
        // leave a prior allocation containing passphrase bytes unzeroized.
        let mut bytes = Vec::with_capacity(MAXIMUM_PASSPHRASE_BYTES + 1);
        if reader
            .by_ref()
            .take((MAXIMUM_PASSPHRASE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .is_err()
        {
            zeroize(&mut bytes);
            return Err(RecoveryError::Failed);
        }
        if !passphrase_allowed(&bytes) {
            zeroize(&mut bytes);
            return Err(RecoveryError::AuthenticationFailed);
        }
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for RecoveryPassphrase {
    fn drop(&mut self) {
        zeroize(&mut self.0);
    }
}

impl VerifiedRecovery {
    pub(crate) fn authentication_key(&self) -> &[u8; ROOT_LENGTH] {
        self.authentication_key.as_ref()
    }

    fn zeroed() -> Self {
        Self {
            authentication_key: Box::new([0; ROOT_LENGTH]),
        }
    }

    #[cfg(test)]
    pub(crate) fn for_test(byte: u8) -> Self {
        let mut recovery = Self::zeroed();
        recovery.authentication_key.fill(byte);
        recovery
    }
}

impl Drop for VerifiedRecovery {
    fn drop(&mut self) {
        zeroize(self.authentication_key.as_mut());
        #[cfg(test)]
        LAST_RECOVERY_ZEROIZED.with(|observed| {
            let zeroized = self.authentication_key.iter().all(|byte| *byte == 0);
            observed.set(zeroized.then_some((
                self.authentication_key.as_ptr() as usize,
                self.authentication_key.len(),
            )));
        });
    }
}

pub(crate) struct RecoveryStore {
    vault_home: PathBuf,
    file: OwnerFile,
}

impl RecoveryStore {
    pub(crate) fn new(vault_home: &Path) -> Self {
        Self {
            vault_home: vault_home.to_path_buf(),
            file: OwnerFile::new(vault_home, FILE_NAME, FILE_LENGTH as u64),
        }
    }

    pub(crate) fn initialize_or_restore(
        &self,
        passphrase: RecoveryPassphrase,
    ) -> Result<VerifiedRecovery, RecoveryError> {
        match self.restore_bytes(passphrase.as_bytes()) {
            Ok(recovery) => Ok(recovery),
            Err(RecoveryError::NotFound) => self.initialize(passphrase.as_bytes()),
            Err(error) => Err(error),
        }
    }

    fn initialize(&self, passphrase: &[u8]) -> Result<VerifiedRecovery, RecoveryError> {
        if !passphrase_allowed(passphrase) {
            return Err(RecoveryError::AuthenticationFailed);
        }
        match self.file.read() {
            Ok(_) => return Err(RecoveryError::AlreadyExists),
            Err(OwnerFileError::NotFound) => {}
            Err(error) => return Err(map_owner_file_error(error)),
        }
        match fs::symlink_metadata(self.vault_home.join(VAULT_KEY_FILE_NAME)) {
            Ok(_) => return Err(RecoveryError::RecoveryRequired),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RecoveryError::Failed),
        }
        match fs::symlink_metadata(self.vault_home.join(LEGACY_FILE_NAME)) {
            Ok(_) => return Err(RecoveryError::RecoveryRequired),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(_) => return Err(RecoveryError::Failed),
        }

        let mut root = [0; ROOT_LENGTH];
        let mut salt = [0; SALT_LENGTH];
        let mut nonce = [0; NONCE_LENGTH];
        if !random_bytes(&mut root) || !random_bytes(&mut salt) || !random_bytes(&mut nonce) {
            zeroize(&mut root);
            return Err(RecoveryError::Failed);
        }
        let encoded = encode(passphrase, &salt, &nonce, &root);
        zeroize(&mut salt);
        zeroize(&mut nonce);
        let encoded = match encoded {
            Ok(encoded) => encoded,
            Err(error) => {
                zeroize(&mut root);
                return Err(error);
            }
        };
        if let Err(error) = self.file.create(&encoded).map_err(map_owner_file_error) {
            zeroize(&mut root);
            return Err(error);
        }
        #[cfg(test)]
        if TRUNCATE_AFTER_CREATE.with(|enabled| enabled.replace(false)) {
            let truncated = fs::OpenOptions::new()
                .write(true)
                .open(self.file.path())
                .and_then(|file| {
                    file.set_len(0)?;
                    file.sync_all()
                });
            if truncated.is_err() {
                zeroize(&mut root);
                return Err(RecoveryError::Failed);
            }
        }
        zeroize(&mut root);
        self.restore_bytes(passphrase)
    }

    pub(crate) fn restore_owned(
        &self,
        passphrase: RecoveryPassphrase,
    ) -> Result<VerifiedRecovery, RecoveryError> {
        self.restore_bytes(passphrase.as_bytes())
    }

    fn restore(&self, passphrase: &[u8]) -> Result<VerifiedRecovery, RecoveryError> {
        self.restore_bytes(passphrase)
    }

    #[cfg(test)]
    pub(crate) fn initialize_for_test(
        &self,
        passphrase: &[u8],
    ) -> Result<VerifiedRecovery, RecoveryError> {
        self.initialize(passphrase)
    }

    fn restore_bytes(&self, passphrase: &[u8]) -> Result<VerifiedRecovery, RecoveryError> {
        if !passphrase_allowed(passphrase) {
            return Err(RecoveryError::AuthenticationFailed);
        }
        let encoded = self.file.read().map_err(map_owner_file_error)?;
        decode(passphrase, &encoded)
    }

    #[cfg(test)]
    fn path(&self) -> &Path {
        self.file.path()
    }
}

fn encode(
    passphrase: &[u8],
    salt: &[u8; SALT_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
    root: &[u8; ROOT_LENGTH],
) -> Result<Vec<u8>, RecoveryError> {
    if !passphrase_allowed(passphrase) {
        return Err(RecoveryError::AuthenticationFailed);
    }
    let mut aad = Vec::with_capacity(AAD_LENGTH);
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&[
        FORMAT_VERSION,
        KDF_ARGON2ID,
        CIPHER_AES_256_GCM,
        ARGON2_VERSION,
    ]);
    aad.extend_from_slice(&ARGON2_MEMORY_KIB.to_be_bytes());
    aad.extend_from_slice(&ARGON2_TIME_COST.to_be_bytes());
    aad.extend_from_slice(&ARGON2_PARALLELISM.to_be_bytes());
    aad.extend_from_slice(&(ROOT_LENGTH as u16).to_be_bytes());
    aad.extend_from_slice(&(MINIMUM_PASSPHRASE_BYTES as u16).to_be_bytes());
    aad.extend_from_slice(&(MAXIMUM_PASSPHRASE_BYTES as u16).to_be_bytes());
    aad.extend_from_slice(&[SALT_LENGTH as u8, NONCE_LENGTH as u8]);
    aad.extend_from_slice(salt);
    aad.extend_from_slice(nonce);

    let mut wrapping_key = [0; ROOT_LENGTH];
    if derive_wrapping_key(passphrase, salt, &mut wrapping_key).is_err() {
        zeroize(&mut wrapping_key);
        return Err(RecoveryError::Failed);
    }
    let sealed = aes_gcm_seal(&wrapping_key, nonce, &aad, root);
    zeroize(&mut wrapping_key);
    let (ciphertext, tag) = sealed.ok_or(RecoveryError::Failed)?;

    let mut encoded = Vec::with_capacity(FILE_LENGTH);
    encoded.extend_from_slice(&aad);
    encoded.extend_from_slice(&tag);
    encoded.extend_from_slice(&ciphertext);
    Ok(encoded)
}

fn decode(passphrase: &[u8], encoded: &[u8]) -> Result<VerifiedRecovery, RecoveryError> {
    if encoded.len() != FILE_LENGTH
        || &encoded[..8] != MAGIC
        || encoded[8] != FORMAT_VERSION
        || encoded[9] != KDF_ARGON2ID
        || encoded[10] != CIPHER_AES_256_GCM
        || encoded[11] != ARGON2_VERSION
        || u32::from_be_bytes([encoded[12], encoded[13], encoded[14], encoded[15]])
            != ARGON2_MEMORY_KIB
        || u32::from_be_bytes([encoded[16], encoded[17], encoded[18], encoded[19]])
            != ARGON2_TIME_COST
        || u32::from_be_bytes([encoded[20], encoded[21], encoded[22], encoded[23]])
            != ARGON2_PARALLELISM
        || u16::from_be_bytes([encoded[24], encoded[25]]) != ROOT_LENGTH as u16
        || u16::from_be_bytes([encoded[26], encoded[27]]) != MINIMUM_PASSPHRASE_BYTES as u16
        || u16::from_be_bytes([encoded[28], encoded[29]]) != MAXIMUM_PASSPHRASE_BYTES as u16
        || encoded[30] != SALT_LENGTH as u8
        || encoded[31] != NONCE_LENGTH as u8
    {
        return Err(RecoveryError::AuthenticationFailed);
    }

    let salt: &[u8; SALT_LENGTH] = encoded[HEADER_LENGTH..HEADER_LENGTH + SALT_LENGTH]
        .try_into()
        .map_err(|_| RecoveryError::AuthenticationFailed)?;
    let nonce: &[u8; NONCE_LENGTH] = encoded[HEADER_LENGTH + SALT_LENGTH..AAD_LENGTH]
        .try_into()
        .map_err(|_| RecoveryError::AuthenticationFailed)?;
    let tag: &[u8; TAG_LENGTH] = encoded[AAD_LENGTH..AAD_LENGTH + TAG_LENGTH]
        .try_into()
        .map_err(|_| RecoveryError::AuthenticationFailed)?;
    let ciphertext: &[u8; ROOT_LENGTH] = encoded[AAD_LENGTH + TAG_LENGTH..]
        .try_into()
        .map_err(|_| RecoveryError::AuthenticationFailed)?;

    let mut wrapping_key = [0; ROOT_LENGTH];
    if derive_wrapping_key(passphrase, salt, &mut wrapping_key).is_err() {
        zeroize(&mut wrapping_key);
        return Err(RecoveryError::Failed);
    }
    let mut recovery = VerifiedRecovery::zeroed();
    let opened = aes_gcm_open(
        &wrapping_key,
        nonce,
        &encoded[..AAD_LENGTH],
        ciphertext,
        tag,
        recovery.authentication_key.as_mut(),
    );
    zeroize(&mut wrapping_key);
    if !opened {
        return Err(RecoveryError::AuthenticationFailed);
    }
    Ok(recovery)
}

fn passphrase_allowed(passphrase: &[u8]) -> bool {
    (MINIMUM_PASSPHRASE_BYTES..=MAXIMUM_PASSPHRASE_BYTES).contains(&passphrase.len())
}

fn derive_wrapping_key(
    passphrase: &[u8],
    salt: &[u8; SALT_LENGTH],
    output: &mut [u8; ROOT_LENGTH],
) -> Result<(), RecoveryError> {
    #[cfg(test)]
    ARGON2_CALLS.with(|calls| calls.set(calls.get() + 1));

    let params = Params::new(
        ARGON2_MEMORY_KIB,
        ARGON2_TIME_COST,
        ARGON2_PARALLELISM,
        Some(ROOT_LENGTH),
    )
    .map_err(|_| RecoveryError::Failed)?;
    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let block_count = argon2.params().block_count();
    let mut memory = Vec::new();
    memory
        .try_reserve_exact(block_count)
        .map_err(|_| RecoveryError::Failed)?;
    memory.resize(block_count, Block::default());
    let result = argon2
        .hash_password_into_with_memory(passphrase, salt, output, &mut memory)
        .map_err(|_| RecoveryError::Failed);
    for block in &mut memory {
        block.zeroize();
    }
    result
}

#[cfg(test)]
fn argon2_call_count() -> u64 {
    ARGON2_CALLS.with(std::cell::Cell::get)
}

fn map_owner_file_error(error: OwnerFileError) -> RecoveryError {
    match error {
        OwnerFileError::NotFound => RecoveryError::NotFound,
        OwnerFileError::ConcurrentChange => RecoveryError::AlreadyExists,
        OwnerFileError::Insecure => RecoveryError::Insecure,
        OwnerFileError::Oversized => RecoveryError::AuthenticationFailed,
        OwnerFileError::Failed | OwnerFileError::Indeterminate => RecoveryError::Failed,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "keyclasp-recovery-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create recovery test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure recovery test directory");
            Self(fs::canonicalize(path).expect("canonical recovery test directory"))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove recovery test directory");
        }
    }

    fn decode_hex(value: &str) -> Vec<u8> {
        assert_eq!(value.len() % 2, 0);
        (0..value.len())
            .step_by(2)
            .map(|offset| {
                u8::from_str_radix(&value[offset..offset + 2], 16).expect("valid test vector")
            })
            .collect()
    }

    #[test]
    fn recovery_owner_keeps_key_bytes_in_one_stable_allocation() {
        LAST_RECOVERY_ZEROIZED.with(|observed| observed.set(None));
        let recovery = VerifiedRecovery::for_test(0x5a);
        let allocation = recovery.authentication_key().as_ptr();
        let moved = Some(recovery);

        assert_eq!(
            moved
                .as_ref()
                .expect("moved recovery owner")
                .authentication_key()
                .as_ptr(),
            allocation
        );
        drop(moved);
        assert_eq!(
            LAST_RECOVERY_ZEROIZED.with(std::cell::Cell::get),
            Some((allocation as usize, ROOT_LENGTH))
        );
    }

    #[test]
    fn recovery_format_matches_independent_node_crypto_vector() {
        let passphrase = b"correct horse battery staple";
        let salt = std::array::from_fn(|index| index as u8);
        let nonce = std::array::from_fn(|index| 0xa0 + index as u8);
        let root = std::array::from_fn(|index| 0x40 + index as u8);
        let expected = decode_hex(concat!(
            "4b4348525652303202020113000100000000000300000001002000100400200c",
            "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
            "a0a1a2a3a4a5a6a7a8a9aaab",
            "e91d30cc259cbf97ffd9e45eb47669e4",
            "4db876264e403c1749f660fe4588cade272fec8bb8320402c78ee9e0584874e2"
        ));

        assert_eq!(
            encode(passphrase, &salt, &nonce, &root).expect("encode recovery vector"),
            expected
        );
        assert_eq!(
            decode(passphrase, &expected)
                .expect("decode recovery vector")
                .authentication_key(),
            &root
        );
    }

    #[test]
    fn initialize_restores_the_same_root_after_restart() {
        let directory = TestDirectory::new();
        let passphrase = b"restart recovery passphrase";
        let store = RecoveryStore::new(&directory.0);
        let calls_before_initialize = argon2_call_count();
        let initialized = store.initialize(passphrase).expect("initialize recovery");
        assert_eq!(argon2_call_count(), calls_before_initialize + 2);
        let expected = *initialized.authentication_key();
        drop(initialized);

        let restarted = RecoveryStore::new(&directory.0);
        let restored = restarted.restore(passphrase).expect("restore recovery");
        assert_eq!(restored.authentication_key(), &expected);
        assert_eq!(
            fs::metadata(restarted.path())
                .expect("recovery metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }

    #[test]
    fn fresh_vaults_get_distinct_roots_and_envelopes_for_the_same_passphrase() {
        let first_directory = TestDirectory::new();
        let second_directory = TestDirectory::new();
        let first_store = RecoveryStore::new(&first_directory.0);
        let second_store = RecoveryStore::new(&second_directory.0);
        let passphrase = b"shared recovery passphrase";
        let first = first_store.initialize(passphrase).expect("first recovery");
        let second = second_store
            .initialize(passphrase)
            .expect("second recovery");

        assert_ne!(first.authentication_key(), second.authentication_key());
        assert_ne!(
            fs::read(first_store.path()).expect("first recovery envelope"),
            fs::read(second_store.path()).expect("second recovery envelope")
        );
    }

    #[test]
    fn wrong_passphrase_and_ciphertext_tampering_share_one_failure() {
        let directory = TestDirectory::new();
        let store = RecoveryStore::new(&directory.0);
        store
            .initialize(b"correct recovery passphrase")
            .expect("initialize recovery");

        assert_eq!(
            store.restore(b"wrong recovery passphrase").err(),
            Some(RecoveryError::AuthenticationFailed)
        );
        let mut encoded = fs::read(store.path()).expect("read recovery envelope");
        let last = encoded.last_mut().expect("recovery ciphertext byte");
        *last ^= 0x01;
        fs::write(store.path(), encoded).expect("tamper recovery envelope");
        assert_eq!(
            store.restore(b"correct recovery passphrase").err(),
            Some(RecoveryError::AuthenticationFailed)
        );
    }

    #[test]
    fn malformed_or_out_of_policy_recovery_input_fails_without_creating_state() {
        let directory = TestDirectory::new();
        let store = RecoveryStore::new(&directory.0);
        let oversized = [b'x'; MAXIMUM_PASSPHRASE_BYTES + 1];
        for passphrase in [&b""[..], &b"123456789012345"[..], &oversized[..]] {
            assert_eq!(
                store.initialize(passphrase).err(),
                Some(RecoveryError::AuthenticationFailed)
            );
        }
        assert!(!store.path().exists());

        fs::write(store.path(), b"not a recovery envelope").expect("write malformed envelope");
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o600))
            .expect("secure malformed envelope permissions");
        assert_eq!(
            store.restore(b"recovery passphrase").err(),
            Some(RecoveryError::AuthenticationFailed)
        );
    }

    #[test]
    fn initialization_never_replaces_existing_recovery_or_lifecycle_state() {
        let directory = TestDirectory::new();
        let store = RecoveryStore::new(&directory.0);
        store
            .initialize(b"original recovery passphrase")
            .expect("initialize recovery");
        let original = fs::read(store.path()).expect("read original recovery");
        assert_eq!(
            store.initialize(b"replacement recovery passphrase").err(),
            Some(RecoveryError::AlreadyExists)
        );
        assert_eq!(
            fs::read(store.path()).expect("read preserved recovery"),
            original
        );

        let second_directory = TestDirectory::new();
        let second_store = RecoveryStore::new(&second_directory.0);
        let marker_path = second_directory.0.join(VAULT_KEY_FILE_NAME);
        let marker = b"orphaned vault-key record";
        fs::write(&marker_path, marker).expect("write orphaned vault-key marker");
        assert_eq!(
            second_store.initialize(b"recovery passphrase").err(),
            Some(RecoveryError::RecoveryRequired)
        );
        assert!(!second_store.path().exists());
        assert_eq!(
            fs::read(&marker_path).expect("read preserved marker"),
            marker
        );
        assert!(fs::symlink_metadata(&marker_path)
            .expect("preserved marker metadata")
            .file_type()
            .is_file());

        let third_directory = TestDirectory::new();
        let third_store = RecoveryStore::new(&third_directory.0);
        let legacy_path = third_directory.0.join(LEGACY_FILE_NAME);
        let legacy_marker = b"legacy PBKDF2 recovery envelope";
        fs::write(&legacy_path, legacy_marker).expect("write legacy recovery marker");
        assert_eq!(
            third_store
                .initialize(b"replacement recovery passphrase")
                .err(),
            Some(RecoveryError::RecoveryRequired)
        );
        assert!(!third_store.path().exists());
        assert_eq!(
            fs::read(&legacy_path).expect("read preserved legacy recovery"),
            legacy_marker
        );
    }

    #[test]
    fn unsupported_or_tampered_kdf_parameters_fail_before_argon2() {
        let directory = TestDirectory::new();
        let store = RecoveryStore::new(&directory.0);
        store
            .initialize(b"recovery passphrase")
            .expect("initialize recovery");
        let original = fs::read(store.path()).expect("read recovery envelope");
        for (offset, field) in [
            (8, "format version"),
            (9, "KDF identifier"),
            (10, "cipher identifier"),
            (11, "Argon2 version"),
            (15, "memory cost"),
            (19, "time cost"),
            (23, "parallelism"),
            (25, "output length"),
            (27, "minimum passphrase length"),
            (29, "maximum passphrase length"),
            (30, "salt length"),
            (31, "nonce length"),
        ] {
            let mut tampered = original.clone();
            tampered[offset] ^= 0x01;
            fs::write(store.path(), tampered).expect("tamper recovery parameter");
            let calls_before_header_check = argon2_call_count();
            assert_eq!(
                store.restore(b"recovery passphrase").err(),
                Some(RecoveryError::AuthenticationFailed),
                "accepted changed {field}"
            );
            assert_eq!(
                argon2_call_count(),
                calls_before_header_check,
                "ran Argon2 before rejecting changed {field}"
            );
        }
        fs::write(store.path(), original).expect("restore recovery envelope");
    }

    #[test]
    fn argon2id_parameters_are_versioned_and_memory_bounded() {
        let params = Params::new(
            ARGON2_MEMORY_KIB,
            ARGON2_TIME_COST,
            ARGON2_PARALLELISM,
            Some(ROOT_LENGTH),
        )
        .expect("valid Argon2id parameters");
        assert_eq!(params.block_count(), ARGON2_MEMORY_KIB as usize);
        assert_eq!(params.block_count() * Block::SIZE, 64 * 1_024 * 1_024);
        assert_eq!(ARGON2_VERSION, 0x13);
        assert_eq!(MINIMUM_PASSPHRASE_BYTES, 16);
        assert_eq!(MAXIMUM_PASSPHRASE_BYTES, 1_024);
    }

    #[test]
    fn insecure_or_hard_linked_recovery_files_are_rejected_before_kdf() {
        let directory = TestDirectory::new();
        let store = RecoveryStore::new(&directory.0);
        store
            .initialize(b"recovery passphrase")
            .expect("initialize recovery");
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o644))
            .expect("make recovery envelope insecure");
        let calls_before_mode_check = argon2_call_count();
        assert_eq!(
            store.restore(b"recovery passphrase").err(),
            Some(RecoveryError::Insecure)
        );
        assert_eq!(argon2_call_count(), calls_before_mode_check);
        fs::set_permissions(store.path(), fs::Permissions::from_mode(0o600))
            .expect("restore recovery permissions");
        fs::hard_link(store.path(), directory.0.join("recovery-copy"))
            .expect("hard link recovery envelope");
        let calls_before_link_check = argon2_call_count();
        assert_eq!(
            store.restore(b"recovery passphrase").err(),
            Some(RecoveryError::Insecure)
        );
        assert_eq!(argon2_call_count(), calls_before_link_check);
    }
}
