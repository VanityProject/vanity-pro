//! Bounded reads, owner-only files, atomic persistence, and a session writer lock.
use anyhow::{Context, Result, ensure};
use fs2::FileExt;
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::fs::OpenOptions;

const MAX_FILE: u64 = 16 * 1024 * 1024;
/// Keeps the local path and its non-replaceable Windows ancestors alive.
pub struct PathGuard {
    path: PathBuf,
    #[cfg(windows)]
    _windows: crate::windows_paths::Guard,
}
impl PathGuard {
    pub fn path(&self) -> &Path {
        &self.path
    }
}
pub fn guard(path: &Path) -> Result<PathGuard> {
    #[cfg(windows)]
    {
        let inner = crate::windows_paths::guard(path, false)?;
        Ok(PathGuard {
            path: inner.path.clone(),
            _windows: inner,
        })
    }
    #[cfg(not(windows))]
    {
        Ok(PathGuard {
            path: path.to_owned(),
        })
    }
}
/// Pin against reparse mutation during unavoidable path-based read-only APIs.
pub fn read_guard(path: &Path) -> Result<PathGuard> {
    #[cfg(windows)]
    {
        let inner = crate::windows_paths::guard_mode(path, false, true)?;
        Ok(PathGuard {
            path: inner.path.clone(),
            _windows: inner,
        })
    }
    #[cfg(not(windows))]
    {
        guard(path)
    }
}
/// Pure spelling validation for persisted receipts. Does not access the target.
pub fn receipt_path(path: &Path) -> bool {
    if !path.is_absolute() {
        return false;
    }
    #[cfg(windows)]
    {
        crate::windows_paths::lexical(path).is_ok()
    }
    #[cfg(not(windows))]
    {
        true
    }
}
pub fn create_directory(path: &Path, recursive: bool) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let _parent = guard(parent)?;
    #[cfg(windows)]
    {
        if recursive {
            crate::windows_paths::guard(path, true)?;
        } else {
            crate::windows_native::open(
                &crate::windows_paths::lexical(path)?,
                0x81,
                3,
                2,
                1,
                std::ptr::null_mut(),
            )?;
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        if recursive {
            fs::create_dir_all(path)?;
        } else {
            fs::create_dir(path)?;
        }
        let _created = guard(path)?;
        Ok(())
    }
}
pub fn exists(path: &Path) -> Result<bool> {
    match metadata(path) {
        Ok(_) => Ok(true),
        Err(error)
            if error
                .downcast_ref::<std::io::Error>()
                .is_some_and(|e| e.kind() == std::io::ErrorKind::NotFound) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}
pub fn metadata(path: &Path) -> Result<fs::Metadata> {
    let guard = guard(path)?;
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        let metadata =
            crate::windows_native::open(guard.path(), 0x80, 7, 1, 0, std::ptr::null_mut())?
                .metadata()?;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "file is a reparse point"
        );
        Ok(metadata)
    }
    #[cfg(not(windows))]
    {
        Ok(fs::symlink_metadata(guard.path())?)
    }
}
pub fn private(path: &Path) -> Result<()> {
    let path_guard = read_guard(path)?;
    let path = path_guard.path();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(
            path,
            fs::Permissions::from_mode(if path.is_dir() { 0o700 } else { 0o600 }),
        )?;
    }
    #[cfg(windows)]
    crate::windows_acl::private(path)?;
    Ok(())
}
pub fn regular(path: &Path) -> Result<()> {
    let path = guard(path)?;
    let metadata = metadata(path.path())?;
    ensure!(
        metadata.is_file() && !metadata.file_type().is_symlink(),
        "expected a regular file"
    );
    ensure!(metadata.len() <= MAX_FILE, "file exceeds 16 MiB limit");
    Ok(())
}
pub fn read_bytes(path: &Path) -> Result<Vec<u8>> {
    let path = guard(path)?;
    #[cfg(windows)]
    let file =
        crate::windows_native::open(path.path(), 0x80000000, 7, 1, 0x40, std::ptr::null_mut())?;
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        let mut options = OpenOptions::new();
        options.read(true);
        options.custom_flags(libc::O_NOFOLLOW);
        options.open(path.path())?
    };
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_FILE,
        "invalid regular file"
    );
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "file is a reparse point"
        );
    }
    let mut bytes = vec![];
    file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_FILE, "file exceeds limit");
    Ok(bytes)
}
fn private_open(path: &Path) -> Result<File> {
    let path_guard = guard(path)?;
    let path = path_guard.path();
    ensure!(
        !metadata(path)?.file_type().is_symlink(),
        "private cache is a symlink"
    );
    #[cfg(unix)]
    let file = {
        use std::os::unix::fs::OpenOptionsExt;
        OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(path)?
    };
    #[cfg(windows)]
    let file = crate::windows_native::open(path, 0x80000000, 1, 1, 0, std::ptr::null_mut())?;
    assert_private_handle(&file)?;
    Ok(file)
}
fn assert_private_handle(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let metadata = file.metadata()?;
        // SAFETY: geteuid has no arguments and returns the effective process identity.
        let owner = unsafe { libc::geteuid() };
        ensure!(
            metadata.uid() == owner && metadata.mode() & 0o077 == 0,
            "cache must be owned by the current user and inaccessible to other accounts; use a fresh directory"
        );
    }
    #[cfg(windows)]
    crate::windows_acl::assert_private(file)?;
    Ok(())
}
pub fn assert_private_directory(path: &Path) -> Result<()> {
    let file = private_open(path)?;
    ensure!(file.metadata()?.is_dir(), "cache path is not a directory");
    Ok(())
}
pub fn read_private_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    let file = private_open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && metadata.len() <= MAX_FILE,
        "invalid private cache file"
    );
    let mut bytes = vec![];
    file.take(MAX_FILE + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= MAX_FILE, "cache exceeds limit");
    Ok(serde_json::from_slice(&bytes)?)
}
pub fn read_json<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&read_bytes(path).with_context(|| format!("read {}", path.display()))?)
        .with_context(|| format!("invalid JSON in {}", path.display()))
}
pub fn write_bytes(path: &Path, bytes: &[u8], replace: bool) -> Result<()> {
    let path_guard = guard(path)?;
    let path = path_guard.path();
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    ensure!(metadata(parent)?.is_dir(), "output parent does not exist");
    ensure!(
        !metadata(parent)?.file_type().is_symlink(),
        "output directory is a symlink"
    );
    if exists(path)? {
        regular(path)?;
        ensure!(replace, "output already exists");
    }
    let mut temporary = private_temporary(parent)
        .with_context(|| format!("create private temporary file in {}", parent.display()))?;
    #[cfg(windows)]
    {
        // Cleanup and persistence use handles, so a subsequently changed reparse
        // point cannot redirect either operation to a different filesystem.
        temporary.disable_cleanup(true);
        let result = (|| -> Result<()> {
            temporary.write_all(bytes)?;
            temporary.as_file().sync_all()?;
            let parent = crate::windows_native::open(parent, 0x81, 3, 1, 1, std::ptr::null_mut())?;
            let name = path.file_name().context("output needs a filename")?;
            for attempt in 0..=8 {
                match crate::windows_native::persist(temporary.as_file(), &parent, name, replace) {
                    Ok(()) => return Ok(()),
                    Err(e) if attempt < 8 && matches!(e.raw_os_error(), Some(5 | 32 | 33)) => {
                        std::thread::sleep(std::time::Duration::from_millis(5 * (attempt + 1)))
                    }
                    Err(e) => return Err(e).context("persist protected output"),
                }
            }
            unreachable!()
        })();
        if result.is_err() {
            crate::windows_native::delete_on_close(temporary.as_file());
        }
        result
    }
    #[cfg(not(windows))]
    {
        temporary.write_all(bytes).context("write temporary file")?;
        temporary
            .as_file()
            .sync_all()
            .context("flush temporary file")?;
        if replace {
            temporary
                .persist(path)
                .map_err(|e| e.error)
                .with_context(|| format!("atomically replace {}", path.display()))?;
        } else {
            temporary
                .persist_noclobber(path)
                .map_err(|e| e.error)
                .with_context(|| format!("create non-overwriting output {}", path.display()))?;
        }
        #[cfg(unix)]
        File::open(parent)?.sync_all()?;
        Ok(())
    }
}
fn private_temporary(parent: &Path) -> Result<tempfile::NamedTempFile> {
    #[cfg(windows)]
    let temporary =
        tempfile::Builder::new().make_in(parent, crate::windows_acl::create_private_file)?;
    #[cfg(not(windows))]
    let temporary = tempfile::NamedTempFile::new_in(parent)?;
    assert_private_handle(temporary.as_file())?;
    Ok(temporary)
}
pub fn write_json<T: Serialize>(path: &Path, value: &T, replace: bool) -> Result<()> {
    write_bytes(path, &serde_json::to_vec_pretty(value)?, replace)
}
#[derive(serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Envelope<T> {
    sha256: String,
    payload: T,
}
pub fn save_checkpoint(path: &Path, checkpoint: &crate::model::Checkpoint) -> Result<()> {
    let sha256 = hex::encode(Sha256::digest(serde_json::to_vec(checkpoint)?));
    write_json(
        path,
        &Envelope {
            sha256,
            payload: checkpoint,
        },
        true,
    )
}
pub fn load_checkpoint(path: &Path, job: &crate::model::Job) -> Result<crate::model::Checkpoint> {
    let envelope: Envelope<crate::model::Checkpoint> = read_json(path)?;
    ensure!(
        envelope.sha256 == hex::encode(Sha256::digest(serde_json::to_vec(&envelope.payload)?)),
        "checkpoint integrity check failed"
    );
    envelope.payload.validate(job)?;
    Ok(envelope.payload)
}
pub fn lock_session(path: &Path) -> Result<File> {
    let path_guard = guard(path)?;
    let path = path_guard.path();
    ensure!(
        metadata(path)?.is_dir() && !metadata(path)?.file_type().is_symlink(),
        "invalid session directory"
    );
    let lock_path = path.join(".session.lock");
    if exists(&lock_path)? {
        regular(&lock_path)?;
    }
    #[cfg(not(windows))]
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&lock_path)?;
    #[cfg(windows)]
    let file =
        crate::windows_native::open(&lock_path, 0xc0000000, 7, 3, 0x40, std::ptr::null_mut())?;
    file.try_lock_exclusive()
        .context("session is already in use")?;
    private(&lock_path)?;
    Ok(file)
}
