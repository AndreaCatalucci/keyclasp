use crate::platform::{directory_secure, file_descriptor_secure};
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

const O_NOFOLLOW_ANY: i32 = 0x2000_0000;

#[cfg(test)]
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) enum SyncEvent {
    File(PathBuf),
    Directory(PathBuf),
}

#[cfg(test)]
thread_local! {
    static SYNC_EVENTS: std::cell::RefCell<Vec<SyncEvent>> = const {
        std::cell::RefCell::new(Vec::new())
    };
    static FAIL_NEXT_POST_RENAME_SYNC: std::cell::Cell<bool> = const {
        std::cell::Cell::new(false)
    };
}

#[cfg(test)]
pub(crate) fn take_sync_events() -> Vec<SyncEvent> {
    SYNC_EVENTS.with(|events| std::mem::take(&mut *events.borrow_mut()))
}

#[cfg(test)]
fn record_sync(event: SyncEvent) {
    SYNC_EVENTS.with(|events| events.borrow_mut().push(event));
}

#[cfg(test)]
pub(crate) fn fail_next_post_rename_sync() {
    FAIL_NEXT_POST_RENAME_SYNC.with(|enabled| enabled.set(true));
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OwnerFileError {
    NotFound,
    ConcurrentChange,
    Insecure,
    Oversized,
    Failed,
    /// The replacement name is already visible, but directory persistence was
    /// not confirmed. Callers must not undo state that may have committed.
    Indeterminate,
}

pub(crate) struct OwnerFile {
    home: PathBuf,
    path: PathBuf,
    temp_path: PathBuf,
    maximum_length: u64,
}

impl OwnerFile {
    pub(crate) fn new(home: &Path, file_name: &str, maximum_length: u64) -> Self {
        Self {
            home: home.to_path_buf(),
            path: home.join(file_name),
            temp_path: home.join(format!("{file_name}.tmp")),
            maximum_length,
        }
    }

    pub(crate) fn read(&self) -> Result<Vec<u8>, OwnerFileError> {
        self.prepare()?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(O_NOFOLLOW_ANY)
            .open(&self.path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::NotFound {
                    OwnerFileError::NotFound
                } else {
                    OwnerFileError::Insecure
                }
            })?;
        if !file_descriptor_secure(file.as_raw_fd()) {
            return Err(OwnerFileError::Insecure);
        }
        if file.metadata().map_err(|_| OwnerFileError::Failed)?.len() > self.maximum_length {
            return Err(OwnerFileError::Oversized);
        }
        let mut bytes = Vec::new();
        file.take(self.maximum_length + 1)
            .read_to_end(&mut bytes)
            .map_err(|_| OwnerFileError::Failed)?;
        if bytes.len() as u64 > self.maximum_length {
            return Err(OwnerFileError::Oversized);
        }
        Ok(bytes)
    }

    pub(crate) fn replace(&self, bytes: &[u8]) -> Result<(), OwnerFileError> {
        let mut cleanup = self.stage(bytes)?;
        fs::rename(&self.temp_path, &self.path).map_err(|_| OwnerFileError::Failed)?;
        cleanup.disarm();
        #[cfg(test)]
        if FAIL_NEXT_POST_RENAME_SYNC.with(|enabled| enabled.replace(false)) {
            return Err(OwnerFileError::Indeterminate);
        }
        self.sync_home().map_err(|_| OwnerFileError::Indeterminate)
    }

    pub(crate) fn create(&self, bytes: &[u8]) -> Result<(), OwnerFileError> {
        let mut cleanup = self.stage(bytes)?;
        fs::hard_link(&self.temp_path, &self.path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::AlreadyExists {
                OwnerFileError::ConcurrentChange
            } else {
                OwnerFileError::Failed
            }
        })?;
        fs::remove_file(&self.temp_path).map_err(|_| OwnerFileError::Failed)?;
        cleanup.disarm();
        self.sync_home()
    }

    fn stage(&self, bytes: &[u8]) -> Result<TempFile, OwnerFileError> {
        if bytes.len() as u64 > self.maximum_length {
            return Err(OwnerFileError::Oversized);
        }
        self.prepare()?;

        let cleanup = TempFile::new(self.temp_path.clone());
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(O_NOFOLLOW_ANY)
            .open(&self.temp_path)
            .map_err(|error| {
                if error.kind() == std::io::ErrorKind::AlreadyExists {
                    OwnerFileError::ConcurrentChange
                } else {
                    OwnerFileError::Failed
                }
            })?;
        if !file_descriptor_secure(file.as_raw_fd()) {
            return Err(OwnerFileError::Insecure);
        }
        file.write_all(bytes).map_err(|_| OwnerFileError::Failed)?;
        file.sync_all().map_err(|_| OwnerFileError::Failed)?;
        #[cfg(test)]
        record_sync(SyncEvent::File(self.temp_path.clone()));
        Ok(cleanup)
    }

    fn sync_home(&self) -> Result<(), OwnerFileError> {
        OpenOptions::new()
            .read(true)
            .custom_flags(O_NOFOLLOW_ANY)
            .open(&self.home)
            .and_then(|directory| directory.sync_all())
            .map_err(|_| OwnerFileError::Failed)?;
        #[cfg(test)]
        record_sync(SyncEvent::Directory(self.home.clone()));
        Ok(())
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    pub(crate) fn temp_path(&self) -> &Path {
        &self.temp_path
    }

    fn prepare(&self) -> Result<(), OwnerFileError> {
        if !directory_secure(&self.home) {
            return Err(OwnerFileError::Insecure);
        }
        match fs::remove_file(&self.temp_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::IsADirectory => {
                Err(OwnerFileError::Insecure)
            }
            Err(_) => Err(OwnerFileError::Failed),
        }
    }
}

struct TempFile {
    path: Option<PathBuf>,
}

impl TempFile {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn disarm(&mut self) {
        self.path = None;
    }
}

impl Drop for TempFile {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = fs::remove_file(path);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{symlink, PermissionsExt};
    use std::process::Command;
    use std::sync::atomic::{AtomicU64, Ordering};

    static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

    struct TestDirectory(PathBuf);

    impl TestDirectory {
        fn new() -> Self {
            let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
            let path = std::env::temp_dir().join(format!(
                "keyclasp-owner-file-{}-{sequence}",
                std::process::id()
            ));
            fs::create_dir(&path).expect("create owner-file test directory");
            fs::set_permissions(&path, fs::Permissions::from_mode(0o700))
                .expect("secure owner-file test directory");
            Self(fs::canonicalize(path).expect("canonical owner-file test directory"))
        }
    }

    impl Drop for TestDirectory {
        fn drop(&mut self) {
            fs::remove_dir_all(&self.0).expect("remove owner-file test directory");
        }
    }

    #[test]
    fn read_rejects_a_symlink_without_changing_its_target() {
        let directory = TestDirectory::new();
        let file = OwnerFile::new(&directory.0, "state", 32);
        file.create(b"authenticated state")
            .expect("create owner file");
        let target = directory.0.join("state-target");
        fs::rename(file.path(), &target).expect("move owner file to target");
        symlink(&target, file.path()).expect("link owner file path");

        assert_eq!(file.read(), Err(OwnerFileError::Insecure));
        assert_eq!(
            fs::read(target).expect("read unchanged symlink target"),
            b"authenticated state"
        );
    }

    #[test]
    fn read_rejects_an_owner_only_file_with_an_extended_acl() {
        let directory = TestDirectory::new();
        let file = OwnerFile::new(&directory.0, "state", 32);
        file.create(b"authenticated state")
            .expect("create owner file");
        let status = Command::new("/bin/chmod")
            .args(["+a", "everyone allow readattr"])
            .arg(file.path())
            .status()
            .expect("add owner-file ACL");
        assert!(status.success());

        let result = file.read();

        let cleanup = Command::new("/bin/chmod")
            .arg("-N")
            .arg(file.path())
            .status()
            .expect("remove owner-file ACL");
        assert!(cleanup.success());
        assert_eq!(result, Err(OwnerFileError::Insecure));
    }
}
