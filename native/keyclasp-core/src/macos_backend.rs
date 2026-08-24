use crate::platform::{
    create_hardware_key, delete_exact_hardware_key, open_hardware_key, HardwareKeyBridgeError,
};
use crate::transaction::{
    AccessPolicy, AuthenticatedEnrollment, BackendError, CanonicalKeyIdentity, HardwareKeyBackend,
    KeyBackendKind, KeyRecord, RecordError,
};

#[derive(Default)]
struct MacOsHardwareKeyBackend {
    created: Option<CreatedKey>,
}

struct CreatedKey {
    application_tag: Vec<u8>,
    label: String,
    public_key: Vec<u8>,
}

impl HardwareKeyBackend for MacOsHardwareKeyBackend {
    fn create_new(
        &mut self,
        identity: &CanonicalKeyIdentity,
        policy: AccessPolicy,
        data_key: &[u8; 32],
        validate: &dyn Fn(&KeyRecord) -> Result<(), RecordError>,
    ) -> Result<(KeyRecord, Vec<u8>), BackendError> {
        require_current_set(policy)?;
        let mut validate_public_key = |public_key: &[u8]| {
            let record = record(identity, policy, public_key.to_vec());
            validate(&record).map_err(HardwareKeyBridgeError::from)
        };
        let (public_key, hardware_ciphertext) = create_hardware_key(
            identity.application_tag(),
            identity.label(),
            data_key,
            &mut validate_public_key,
        )
        .map_err(BackendError::from)?;
        self.created = Some(CreatedKey {
            application_tag: identity.application_tag().to_vec(),
            label: identity.label().to_owned(),
            public_key: public_key.clone(),
        });
        Ok((record(identity, policy, public_key), hardware_ciphertext))
    }

    fn open_existing(
        &mut self,
        identity: &CanonicalKeyIdentity,
        enrollment: &AuthenticatedEnrollment,
        hardware_ciphertext: &[u8],
        data_key: &mut [u8; 32],
    ) -> Result<KeyRecord, BackendError> {
        let required_policy = enrollment.required_policy();
        require_current_set(required_policy)?;
        let public_key = open_hardware_key(
            identity.application_tag(),
            identity.label(),
            enrollment.public_key(),
            hardware_ciphertext,
            data_key,
        )
        .map_err(BackendError::from)?;
        Ok(record(identity, required_policy, public_key))
    }

    fn rollback_created(&mut self) -> Result<(), BackendError> {
        let created = self.created.as_ref().ok_or(BackendError::CleanupFailed)?;
        delete_exact_hardware_key(
            &created.application_tag,
            &created.label,
            &created.public_key,
        )
        .map_err(BackendError::from)?;
        self.created = None;
        Ok(())
    }
}

fn require_current_set(policy: AccessPolicy) -> Result<(), BackendError> {
    if policy == AccessPolicy::BiometricCurrentSet {
        Ok(())
    } else {
        Err(BackendError::Unsupported)
    }
}

fn record(identity: &CanonicalKeyIdentity, policy: AccessPolicy, public_key: Vec<u8>) -> KeyRecord {
    KeyRecord {
        application_tag: identity.application_tag().to_vec(),
        label: identity.label().to_owned(),
        backend: KeyBackendKind::SecureEnclave,
        required_policy: policy,
        public_key,
    }
}

impl From<RecordError> for HardwareKeyBridgeError {
    fn from(error: RecordError) -> Self {
        match error {
            RecordError::IncompleteState(_) => Self::Incomplete,
            RecordError::IdentityMismatch => Self::IdentityMismatch,
            RecordError::PolicyMismatch => Self::PolicyMismatch,
            RecordError::BackendMismatch => Self::BackendMismatch,
            RecordError::InvalidPublicKey => Self::InvalidPublicKey,
        }
    }
}

impl From<HardwareKeyBridgeError> for BackendError {
    fn from(error: HardwareKeyBridgeError) -> Self {
        match error {
            HardwareKeyBridgeError::AlreadyExists => Self::AlreadyExists,
            HardwareKeyBridgeError::NotFound => Self::NotFound,
            HardwareKeyBridgeError::PermissionDenied => Self::PermissionDenied,
            HardwareKeyBridgeError::Unsupported => Self::Unsupported,
            HardwareKeyBridgeError::Failed => Self::Failed,
            HardwareKeyBridgeError::Incomplete => {
                Self::InvalidRecord(RecordError::IncompleteState("platform key record"))
            }
            HardwareKeyBridgeError::IdentityMismatch => {
                Self::InvalidRecord(RecordError::IdentityMismatch)
            }
            HardwareKeyBridgeError::PolicyMismatch => {
                Self::InvalidRecord(RecordError::PolicyMismatch)
            }
            HardwareKeyBridgeError::BackendMismatch => {
                Self::InvalidRecord(RecordError::BackendMismatch)
            }
            HardwareKeyBridgeError::InvalidPublicKey => {
                Self::InvalidRecord(RecordError::InvalidPublicKey)
            }
            HardwareKeyBridgeError::CleanupFailed => Self::CleanupFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SOURCE: &str = include_str!("macos_backend.rs");

    #[test]
    fn bridge_errors_preserve_lifecycle_meaning() {
        for (bridge, backend) in [
            (
                HardwareKeyBridgeError::AlreadyExists,
                BackendError::AlreadyExists,
            ),
            (HardwareKeyBridgeError::NotFound, BackendError::NotFound),
            (
                HardwareKeyBridgeError::PermissionDenied,
                BackendError::PermissionDenied,
            ),
            (
                HardwareKeyBridgeError::Unsupported,
                BackendError::Unsupported,
            ),
            (HardwareKeyBridgeError::Failed, BackendError::Failed),
            (
                HardwareKeyBridgeError::CleanupFailed,
                BackendError::CleanupFailed,
            ),
        ] {
            assert_eq!(BackendError::from(bridge), backend);
        }
    }

    #[test]
    fn weaker_policy_guard_rejects_every_non_current_set_value() {
        for policy in [
            AccessPolicy::BiometricAny,
            AccessPolicy::UserPresence,
            AccessPolicy::Unknown,
        ] {
            assert_eq!(require_current_set(policy), Err(BackendError::Unsupported));
        }
    }

    #[test]
    fn both_backend_operations_guard_policy_before_platform_access() {
        let create = SOURCE
            .split("fn create_new(")
            .nth(1)
            .expect("create method")
            .split("fn open_existing(")
            .next()
            .expect("create body");
        let open = SOURCE
            .split("fn open_existing(")
            .nth(1)
            .expect("open method")
            .split("fn require_current_set(")
            .next()
            .expect("open body");
        assert!(
            create.find("require_current_set(").expect("create guard")
                < create.find("create_hardware_key(").expect("create call")
        );
        assert!(
            open.find("require_current_set(").expect("open guard")
                < open.find("open_hardware_key(").expect("open call")
        );
    }

    #[test]
    fn rollback_uses_the_trusted_creation_token_not_a_returned_record() {
        let rollback = SOURCE
            .split("fn rollback_created(")
            .nth(1)
            .expect("rollback method")
            .split("fn require_current_set(")
            .next()
            .expect("rollback body");
        assert!(rollback.contains("self.created.as_ref()"));
        assert!(rollback.contains("&created.application_tag"));
        assert!(rollback.contains("&created.label"));
        assert!(rollback.contains("&created.public_key"));
        assert!(!rollback.contains("identity."));
        assert!(!rollback.contains("record.public_key"));
    }
}
