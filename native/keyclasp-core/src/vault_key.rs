use crate::owner_file::{OwnerFile, OwnerFileError};
use crate::platform::{
    aes_gcm_open, aes_gcm_seal, hmac_sha256_into, hmac_sha256_verify, p256_public_key_valid,
    random_bytes, zeroize,
};
use crate::recovery::VerifiedRecovery;
use crate::transaction::{AccessPolicy, AuthenticatedEnrollment, KeyBackendKind, KeyRecord};
use std::path::Path;

pub(crate) const FILE_NAME: &str = ".hardware-vault-key.v1";
const MAGIC: &[u8; 8] = b"KCHVLT01";
const FORMAT_VERSION: u8 = 1;
const STATE_PENDING: u8 = 1;
const STATE_ACTIVE: u8 = 2;
const RECOVERY_CIPHER_AES_256_GCM: u8 = 1;
const HARDWARE_CIPHER_ECIES_X963_SHA256_AES_GCM: u8 = 1;
const POLICY_BIOMETRIC_CURRENT_SET: u8 = 1;
const HEADER_LENGTH: usize = 22;
const NONCE_LENGTH: usize = 12;
const TAG_LENGTH: usize = 16;
const DATA_KEY_LENGTH: usize = 32;
const P256_PUBLIC_KEY_LENGTH: usize = 65;
const MAX_HARDWARE_CIPHERTEXT_LENGTH: usize = 4096;
const MAX_RECORD_LENGTH: u64 = 8192;
const WRAP_KEY_DOMAIN: &[u8] = b"keyclasp/vault-recovery-wrap/v1";
const EQUALITY_DOMAIN: &[u8] = b"keyclasp/vault-key-equality/v1";

#[cfg(test)]
thread_local! {
    static FAIL_NEXT_ACTIVATE: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
    static LAST_SECRET_BUFFER_ZEROIZED: std::cell::Cell<Option<(usize, usize)>> = const {
        std::cell::Cell::new(None)
    };
}

#[cfg(test)]
pub(crate) fn fail_next_activate() {
    FAIL_NEXT_ACTIVATE.with(|enabled| enabled.set(true));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum VaultKeyError {
    AlreadyActive,
    NotFound,
    RecoveryRequired,
    AuthenticationFailed,
    Damaged,
    Insecure,
    Failed,
    ActivationIndeterminate,
}

struct SecretBuffer32(Box<[u8; DATA_KEY_LENGTH]>);

impl SecretBuffer32 {
    fn zeroed() -> Self {
        Self(Box::new([0; DATA_KEY_LENGTH]))
    }

    fn as_bytes(&self) -> &[u8; DATA_KEY_LENGTH] {
        self.0.as_ref()
    }

    fn as_mut_bytes(&mut self) -> &mut [u8; DATA_KEY_LENGTH] {
        self.0.as_mut()
    }
}

impl Drop for SecretBuffer32 {
    fn drop(&mut self) {
        zeroize(self.0.as_mut());
        #[cfg(test)]
        LAST_SECRET_BUFFER_ZEROIZED.with(|observed| {
            let zeroized = self.0.iter().all(|byte| *byte == 0);
            observed.set(zeroized.then_some((self.0.as_ptr() as usize, self.0.len())));
        });
    }
}

pub(crate) struct VaultDataKey(SecretBuffer32);

impl VaultDataKey {
    pub(crate) fn as_bytes(&self) -> &[u8; DATA_KEY_LENGTH] {
        self.0.as_bytes()
    }

    fn zeroed() -> Self {
        Self(SecretBuffer32::zeroed())
    }

    pub(crate) fn matches(&self, other: &[u8; DATA_KEY_LENGTH]) -> bool {
        let mut expected = SecretBuffer32::zeroed();
        if !hmac_sha256_into(self.0.as_bytes(), EQUALITY_DOMAIN, expected.as_mut_bytes()) {
            return false;
        }
        hmac_sha256_verify(other, EQUALITY_DOMAIN, expected.as_bytes())
    }

    #[cfg(test)]
    fn for_test(byte: u8) -> Self {
        let mut key = Self::zeroed();
        key.0.as_mut_bytes().fill(byte);
        key
    }
}

pub(crate) struct ActiveVaultKey {
    pub(crate) data_key: VaultDataKey,
    pub(crate) public_key: Vec<u8>,
    pub(crate) hardware_ciphertext: Vec<u8>,
}

impl ActiveVaultKey {
    pub(crate) fn authenticated_enrollment(&self) -> AuthenticatedEnrollment {
        AuthenticatedEnrollment::from_authenticated_metadata(
            AccessPolicy::BiometricCurrentSet,
            self.public_key.clone(),
        )
    }
}

pub(crate) struct VaultKeyStore {
    file: OwnerFile,
    application_tag: Vec<u8>,
}

impl VaultKeyStore {
    pub(crate) fn new(vault_home: &Path, application_tag: &[u8]) -> Self {
        Self {
            file: OwnerFile::new(vault_home, FILE_NAME, MAX_RECORD_LENGTH),
            application_tag: application_tag.to_vec(),
        }
    }

    pub(crate) fn begin(&self, recovery: &VerifiedRecovery) -> Result<VaultDataKey, VaultKeyError> {
        match self.load_record(recovery) {
            Ok(VaultKeyState::Active(_)) => return Err(VaultKeyError::AlreadyActive),
            Ok(VaultKeyState::Pending(_)) => return Err(VaultKeyError::RecoveryRequired),
            Err(VaultKeyError::NotFound) => {}
            Err(error) => return Err(error),
        }

        let mut data_key = VaultDataKey::zeroed();
        if !random_bytes(data_key.0.as_mut_bytes()) {
            return Err(VaultKeyError::Failed);
        }
        let encoded = encode_record(
            recovery,
            STATE_PENDING,
            &self.application_tag,
            &[],
            &[],
            &data_key,
        )?;
        self.file.create(&encoded).map_err(map_owner_file_error)?;
        Ok(data_key)
    }

    pub(crate) fn activate(
        &self,
        recovery: &VerifiedRecovery,
        data_key: &VaultDataKey,
        record: &KeyRecord,
        hardware_ciphertext: &[u8],
    ) -> Result<(), VaultKeyError> {
        #[cfg(test)]
        if FAIL_NEXT_ACTIVATE.with(|enabled| enabled.replace(false)) {
            return Err(VaultKeyError::Failed);
        }
        let pending = match self.load_record(recovery)? {
            VaultKeyState::Pending(data_key) => data_key,
            VaultKeyState::Active(_) => return Err(VaultKeyError::AlreadyActive),
        };
        if !pending.matches(data_key.as_bytes())
            || record.application_tag != self.application_tag
            || record.backend != KeyBackendKind::SecureEnclave
            || record.required_policy != AccessPolicy::BiometricCurrentSet
            || record.public_key.len() != P256_PUBLIC_KEY_LENGTH
            || !p256_public_key_valid(&record.public_key)
            || hardware_ciphertext.is_empty()
            || hardware_ciphertext.len() > MAX_HARDWARE_CIPHERTEXT_LENGTH
        {
            return Err(VaultKeyError::Damaged);
        }

        let encoded = encode_record(
            recovery,
            STATE_ACTIVE,
            &self.application_tag,
            &record.public_key,
            hardware_ciphertext,
            data_key,
        )?;
        self.file.replace(&encoded).map_err(map_owner_file_error)
    }

    pub(crate) fn load_active(
        &self,
        recovery: &VerifiedRecovery,
    ) -> Result<ActiveVaultKey, VaultKeyError> {
        match self.load_record(recovery)? {
            VaultKeyState::Pending(_) => Err(VaultKeyError::RecoveryRequired),
            VaultKeyState::Active(active) => Ok(active),
        }
    }

    fn load_record(&self, recovery: &VerifiedRecovery) -> Result<VaultKeyState, VaultKeyError> {
        let bytes = self.file.read().map_err(map_owner_file_error)?;
        decode_record(recovery, &self.application_tag, &bytes)
    }

    #[cfg(test)]
    fn record_path(&self) -> &Path {
        self.file.path()
    }
}

enum VaultKeyState {
    Pending(VaultDataKey),
    Active(ActiveVaultKey),
}

fn encode_record(
    recovery: &VerifiedRecovery,
    state: u8,
    application_tag: &[u8],
    public_key: &[u8],
    hardware_ciphertext: &[u8],
    data_key: &VaultDataKey,
) -> Result<Vec<u8>, VaultKeyError> {
    let mut nonce = [0; NONCE_LENGTH];
    if !random_bytes(&mut nonce) {
        return Err(VaultKeyError::Failed);
    }
    let encoded = encode_record_with_nonce(
        recovery,
        state,
        application_tag,
        public_key,
        hardware_ciphertext,
        data_key,
        &nonce,
    );
    zeroize(&mut nonce);
    encoded
}

fn encode_record_with_nonce(
    recovery: &VerifiedRecovery,
    state: u8,
    application_tag: &[u8],
    public_key: &[u8],
    hardware_ciphertext: &[u8],
    data_key: &VaultDataKey,
    nonce: &[u8; NONCE_LENGTH],
) -> Result<Vec<u8>, VaultKeyError> {
    let tag_length = u16::try_from(application_tag.len()).map_err(|_| VaultKeyError::Failed)?;
    let public_key_length = u16::try_from(public_key.len()).map_err(|_| VaultKeyError::Failed)?;
    let hardware_length =
        u32::try_from(hardware_ciphertext.len()).map_err(|_| VaultKeyError::Failed)?;

    let mut aad = Vec::with_capacity(
        HEADER_LENGTH
            + application_tag.len()
            + public_key.len()
            + hardware_ciphertext.len()
            + NONCE_LENGTH,
    );
    aad.extend_from_slice(MAGIC);
    aad.extend_from_slice(&[
        FORMAT_VERSION,
        state,
        RECOVERY_CIPHER_AES_256_GCM,
        HARDWARE_CIPHER_ECIES_X963_SHA256_AES_GCM,
        POLICY_BIOMETRIC_CURRENT_SET,
        0,
    ]);
    aad.extend_from_slice(&tag_length.to_be_bytes());
    aad.extend_from_slice(&public_key_length.to_be_bytes());
    aad.extend_from_slice(&hardware_length.to_be_bytes());
    aad.extend_from_slice(application_tag);
    aad.extend_from_slice(public_key);
    aad.extend_from_slice(hardware_ciphertext);
    aad.extend_from_slice(nonce);

    let wrapping_key = derive_wrapping_key(recovery)?;
    let sealed = aes_gcm_seal(wrapping_key.as_bytes(), nonce, &aad, data_key.as_bytes());
    let (ciphertext, tag) = sealed.ok_or(VaultKeyError::Failed)?;
    let mut encoded = aad;
    encoded.extend_from_slice(&tag);
    encoded.extend_from_slice(&ciphertext);
    Ok(encoded)
}

fn decode_record(
    recovery: &VerifiedRecovery,
    application_tag: &[u8],
    bytes: &[u8],
) -> Result<VaultKeyState, VaultKeyError> {
    let minimum = HEADER_LENGTH + NONCE_LENGTH + TAG_LENGTH + DATA_KEY_LENGTH;
    if bytes.len() < minimum || bytes.len() as u64 > MAX_RECORD_LENGTH {
        return Err(VaultKeyError::AuthenticationFailed);
    }
    if &bytes[..8] != MAGIC
        || bytes[8] != FORMAT_VERSION
        || bytes[10] != RECOVERY_CIPHER_AES_256_GCM
        || bytes[11] != HARDWARE_CIPHER_ECIES_X963_SHA256_AES_GCM
        || bytes[12] != POLICY_BIOMETRIC_CURRENT_SET
        || bytes[13] != 0
    {
        return Err(VaultKeyError::AuthenticationFailed);
    }
    let tag_length = usize::from(u16::from_be_bytes([bytes[14], bytes[15]]));
    let public_key_length = usize::from(u16::from_be_bytes([bytes[16], bytes[17]]));
    let hardware_length = usize::try_from(u32::from_be_bytes([
        bytes[18], bytes[19], bytes[20], bytes[21],
    ]))
    .map_err(|_| VaultKeyError::AuthenticationFailed)?;
    if hardware_length > MAX_HARDWARE_CIPHERTEXT_LENGTH {
        return Err(VaultKeyError::AuthenticationFailed);
    }
    let aad_length = HEADER_LENGTH
        .checked_add(tag_length)
        .and_then(|length| length.checked_add(public_key_length))
        .and_then(|length| length.checked_add(hardware_length))
        .and_then(|length| length.checked_add(NONCE_LENGTH))
        .ok_or(VaultKeyError::AuthenticationFailed)?;
    if bytes.len() != aad_length + TAG_LENGTH + DATA_KEY_LENGTH {
        return Err(VaultKeyError::AuthenticationFailed);
    }
    if &bytes[HEADER_LENGTH..HEADER_LENGTH + tag_length] != application_tag {
        return Err(VaultKeyError::AuthenticationFailed);
    }

    let public_key_start = HEADER_LENGTH + tag_length;
    let hardware_start = public_key_start + public_key_length;
    let nonce_start = hardware_start + hardware_length;
    let public_key = &bytes[public_key_start..hardware_start];
    let hardware_ciphertext = &bytes[hardware_start..nonce_start];
    let nonce: &[u8; NONCE_LENGTH] = bytes[nonce_start..aad_length]
        .try_into()
        .map_err(|_| VaultKeyError::AuthenticationFailed)?;
    let tag: &[u8; TAG_LENGTH] = bytes[aad_length..aad_length + TAG_LENGTH]
        .try_into()
        .map_err(|_| VaultKeyError::AuthenticationFailed)?;
    let ciphertext: &[u8; DATA_KEY_LENGTH] = bytes[aad_length + TAG_LENGTH..]
        .try_into()
        .map_err(|_| VaultKeyError::AuthenticationFailed)?;

    let wrapping_key = derive_wrapping_key(recovery)?;
    let mut data_key = VaultDataKey::zeroed();
    let opened = aes_gcm_open(
        wrapping_key.as_bytes(),
        nonce,
        &bytes[..aad_length],
        ciphertext,
        tag,
        data_key.0.as_mut_bytes(),
    );
    if !opened {
        return Err(VaultKeyError::AuthenticationFailed);
    }
    match bytes[9] {
        STATE_PENDING if public_key.is_empty() && hardware_ciphertext.is_empty() => {
            Ok(VaultKeyState::Pending(data_key))
        }
        STATE_ACTIVE
            if public_key.len() == P256_PUBLIC_KEY_LENGTH
                && p256_public_key_valid(public_key)
                && !hardware_ciphertext.is_empty() =>
        {
            Ok(VaultKeyState::Active(ActiveVaultKey {
                data_key,
                public_key: public_key.to_vec(),
                hardware_ciphertext: hardware_ciphertext.to_vec(),
            }))
        }
        _ => Err(VaultKeyError::Damaged),
    }
}

fn derive_wrapping_key(recovery: &VerifiedRecovery) -> Result<SecretBuffer32, VaultKeyError> {
    let mut wrapping_key = SecretBuffer32::zeroed();
    if !hmac_sha256_into(
        recovery.authentication_key(),
        WRAP_KEY_DOMAIN,
        wrapping_key.as_mut_bytes(),
    ) {
        return Err(VaultKeyError::Failed);
    }
    Ok(wrapping_key)
}

fn map_owner_file_error(error: OwnerFileError) -> VaultKeyError {
    match error {
        OwnerFileError::NotFound => VaultKeyError::NotFound,
        OwnerFileError::ConcurrentChange => VaultKeyError::RecoveryRequired,
        OwnerFileError::Insecure => VaultKeyError::Insecure,
        OwnerFileError::Oversized => VaultKeyError::AuthenticationFailed,
        OwnerFileError::Failed => VaultKeyError::Failed,
        OwnerFileError::Indeterminate => VaultKeyError::ActivationIndeterminate,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transaction::CanonicalKeyIdentity;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "keyclasp-vault-key-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create vault-key test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure vault-key test directory");
            Self(path)
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove vault-key test directory");
        }
    }

    fn setup() -> (TestDirectory, CanonicalKeyIdentity, VerifiedRecovery) {
        let directory = TestDirectory::new();
        let identity = CanonicalKeyIdentity::for_vault_home(&directory.0).expect("identity");
        (directory, identity, VerifiedRecovery::for_test(0x5a))
    }

    fn record(identity: &CanonicalKeyIdentity) -> KeyRecord {
        KeyRecord {
            application_tag: identity.application_tag().to_vec(),
            label: identity.label().to_owned(),
            backend: KeyBackendKind::SecureEnclave,
            required_policy: AccessPolicy::BiometricCurrentSet,
            public_key: vec![
                0x04, 0x6b, 0x17, 0xd1, 0xf2, 0xe1, 0x2c, 0x42, 0x47, 0xf8, 0xbc, 0xe6, 0xe5, 0x63,
                0xa4, 0x40, 0xf2, 0x77, 0x03, 0x7d, 0x81, 0x2d, 0xeb, 0x33, 0xa0, 0xf4, 0xa1, 0x39,
                0x45, 0xd8, 0x98, 0xc2, 0x96, 0x4f, 0xe3, 0x42, 0xe2, 0xfe, 0x1a, 0x7f, 0x9b, 0x8e,
                0xe7, 0xeb, 0x4a, 0x7c, 0x0f, 0x9e, 0x16, 0x2b, 0xce, 0x33, 0x57, 0x6b, 0x31, 0x5e,
                0xce, 0xcb, 0xb6, 0x40, 0x68, 0x37, 0xbf, 0x51, 0xf5,
            ],
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
    fn vault_key_owner_keeps_key_bytes_in_one_stable_allocation() {
        LAST_SECRET_BUFFER_ZEROIZED.with(|observed| observed.set(None));
        let data_key = VaultDataKey::for_test(0x44);
        let allocation = data_key.as_bytes().as_ptr();
        let moved = Some(data_key);

        assert_eq!(
            moved
                .as_ref()
                .expect("moved vault-key owner")
                .as_bytes()
                .as_ptr(),
            allocation
        );
        drop(moved);
        assert_eq!(
            LAST_SECRET_BUFFER_ZEROIZED.with(std::cell::Cell::get),
            Some((allocation as usize, DATA_KEY_LENGTH))
        );
    }

    #[test]
    fn comparison_mac_uses_and_clears_the_stable_secret_owner() {
        const SOURCE: &str = include_str!("vault_key.rs");
        let matches = SOURCE
            .split("pub(crate) fn matches(")
            .nth(1)
            .expect("vault-key comparison")
            .split("#[cfg(test)]")
            .next()
            .expect("vault-key comparison body");
        assert!(matches.contains("let mut expected = SecretBuffer32::zeroed();"));
        assert!(matches.contains("hmac_sha256_into("));
        assert!(matches.contains("expected.as_mut_bytes()"));

        LAST_SECRET_BUFFER_ZEROIZED.with(|observed| observed.set(None));
        let data_key = VaultDataKey::for_test(0x44);
        assert!(data_key.matches(data_key.as_bytes()));
        assert_eq!(
            LAST_SECRET_BUFFER_ZEROIZED
                .with(std::cell::Cell::get)
                .map(|(_, length)| length),
            Some(DATA_KEY_LENGTH)
        );
    }

    #[test]
    fn pending_format_matches_independent_node_crypto_vector() {
        let recovery = VerifiedRecovery::for_test(0x5a);
        let nonce = std::array::from_fn(|index| 0xa0 + index as u8);
        let mut data_key = VaultDataKey::zeroed();
        for (index, byte) in data_key.0.as_mut_bytes().iter_mut().enumerate() {
            *byte = 0x40 + index as u8;
        }
        let expected = decode_hex(concat!(
            "4b4348564c5430310101010101000008000000000000",
            "746573742d746167",
            "a0a1a2a3a4a5a6a7a8a9aaab",
            "47914a07c30569f498b5bf5d51cc82c9",
            "6f33f65ed1c0e1fe931b229eee70fa9f2cb8594882089ef6f6fc9fefe019e87e"
        ));
        assert_eq!(
            encode_record_with_nonce(
                &recovery,
                STATE_PENDING,
                b"test-tag",
                &[],
                &[],
                &data_key,
                &nonce,
            )
            .expect("encode vault-key vector"),
            expected
        );
        let decoded =
            decode_record(&recovery, b"test-tag", &expected).expect("decode vault-key vector");
        let VaultKeyState::Pending(restored) = decoded else {
            panic!("pending vector became active");
        };
        assert!(restored.matches(data_key.as_bytes()));
    }

    #[test]
    fn pending_recovery_copy_is_durable_before_activation() {
        let (_directory, identity, recovery) = setup();
        let store = VaultKeyStore::new(identity.vault_home(), identity.application_tag());
        let original = store.begin(&recovery).expect("begin vault key");
        assert_eq!(
            store.begin(&recovery).err(),
            Some(VaultKeyError::RecoveryRequired)
        );
        let restored = match store.load_record(&recovery).expect("restore pending key") {
            VaultKeyState::Pending(key) => key,
            VaultKeyState::Active(_) => panic!("pending state became active"),
        };
        assert!(restored.matches(original.as_bytes()));
        assert_eq!(
            fs::metadata(store.record_path())
                .expect("vault-key metadata")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[test]
    fn activation_binds_both_wrappers_to_the_same_data_key() {
        let (_directory, identity, recovery) = setup();
        let store = VaultKeyStore::new(identity.vault_home(), identity.application_tag());
        let data_key = store.begin(&recovery).expect("begin vault key");
        let record = record(&identity);
        let hardware_ciphertext = b"test-only hardware ciphertext";
        store
            .activate(&recovery, &data_key, &record, hardware_ciphertext)
            .expect("activate dual-wrapped key");

        let active = store.load_active(&recovery).expect("load active key");
        assert!(active.data_key.matches(data_key.as_bytes()));
        assert_eq!(active.public_key, record.public_key);
        assert_eq!(active.hardware_ciphertext, hardware_ciphertext);
    }

    #[test]
    fn wrong_recovery_and_tampering_fail_closed() {
        let (_directory, identity, recovery) = setup();
        let store = VaultKeyStore::new(identity.vault_home(), identity.application_tag());
        let data_key = store.begin(&recovery).expect("begin vault key");
        store
            .activate(
                &recovery,
                &data_key,
                &record(&identity),
                b"hardware ciphertext",
            )
            .expect("activate dual-wrapped key");
        assert!(matches!(
            store.load_active(&VerifiedRecovery::for_test(0x6b)),
            Err(VaultKeyError::AuthenticationFailed)
        ));

        let mut bytes = fs::read(store.record_path()).expect("read vault-key metadata");
        let offset = bytes.len() - DATA_KEY_LENGTH - 1;
        bytes[offset] ^= 0x80;
        fs::write(store.record_path(), bytes).expect("tamper vault-key metadata");
        assert!(matches!(
            store.load_active(&recovery),
            Err(VaultKeyError::AuthenticationFailed)
        ));
    }

    #[test]
    fn activation_rejects_a_different_in_memory_key() {
        let (_directory, identity, recovery) = setup();
        let store = VaultKeyStore::new(identity.vault_home(), identity.application_tag());
        let _original = store.begin(&recovery).expect("begin vault key");
        assert_eq!(
            store.activate(
                &recovery,
                &VaultDataKey::for_test(0x44),
                &record(&identity),
                b"hardware ciphertext",
            ),
            Err(VaultKeyError::Damaged)
        );
    }
}
