//! Local Win32 paths with pinned, non-reparse ancestors. Never resolve UNC input.
use anyhow::{Context, Result, ensure};
use std::{
    fs::File,
    os::windows::fs::MetadataExt,
    path::{Component, Path, PathBuf, Prefix},
};
use windows_sys::Win32::Storage::FileSystem::{
    FILE_LIST_DIRECTORY, FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, GetDriveTypeW,
};

pub struct Guard {
    pub path: PathBuf,
    // Deny renames. Native opens separately reject reparse points at use time.
    _ancestors: Vec<File>,
}

fn normalize(path: &Path, cwd: &Path) -> Result<PathBuf> {
    let absolute = match path.components().next() {
        Some(Component::Prefix(p)) => {
            ensure!(
                matches!(p.kind(), Prefix::Disk(_)) && path.is_absolute(),
                "use an ordinary local drive path"
            );
            path.to_owned()
        }
        Some(Component::RootDir) => anyhow::bail!("drive-relative paths are not supported"),
        _ => {
            ensure!(
                matches!(cwd.components().next(), Some(Component::Prefix(p)) if matches!(p.kind(), Prefix::Disk(_)))
                    && cwd.is_absolute(),
                "working directory must be on a local drive"
            );
            cwd.join(path)
        }
    };
    let mut result = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::Prefix(p) => result.push(p.as_os_str()),
            Component::RootDir => result.push("\\"),
            Component::CurDir => (),
            Component::ParentDir => {
                ensure!(result.pop(), "path escapes drive root");
            }
            Component::Normal(name) => {
                let text = name.to_string_lossy();
                ensure!(
                    !text.ends_with(['.', ' '])
                        && !text.chars().any(|c| c < ' ' || ":<>\"|?*".contains(c)),
                    "unsupported Windows path component"
                );
                let base = text
                    .split('.')
                    .next()
                    .unwrap_or_default()
                    .to_ascii_uppercase();
                ensure!(
                    !matches!(
                        base.as_str(),
                        "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
                    ) && !((base.starts_with("COM") || base.starts_with("LPT"))
                        && matches!(
                            &base[3..],
                            "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9" | "¹" | "²" | "³"
                        )),
                    "reserved Windows device name"
                );
                result.push(name);
            }
        }
    }
    Ok(result)
}

fn local_drive(kind: u32) -> Result<()> {
    ensure!(
        matches!(kind, 2 | 3 | 6),
        "storage must be on a local fixed, removable or RAM drive"
    );
    Ok(())
}

pub fn lexical(path: &Path) -> Result<PathBuf> {
    normalize(path, &std::env::current_dir()?)
}

pub fn guard(path: &Path, create_directories: bool) -> Result<Guard> {
    guard_mode(path, create_directories, false)
}
pub fn guard_mode(path: &Path, create_directories: bool, read_only: bool) -> Result<Guard> {
    guard_at(
        path,
        create_directories,
        read_only,
        &std::env::current_dir()?,
    )
}
fn guard_at(path: &Path, create_directories: bool, read_only: bool, cwd: &Path) -> Result<Guard> {
    use std::os::windows::ffi::OsStrExt;
    let relative = !path.is_absolute();
    let path = normalize(path, cwd)?;
    // Validate and retain the original working directory even when `..` removes
    // one of its components from the normalized destination.
    let mut ancestors = if relative {
        guard_at(cwd, false, read_only, cwd)?._ancestors
    } else {
        vec![]
    };
    let mut components = path.components();
    let mut current = PathBuf::from(components.next().context("missing drive")?.as_os_str());
    current.push("\\");
    let root: Vec<_> = current.as_os_str().encode_wide().chain(Some(0)).collect();
    // SAFETY: root is a terminated, ordinary drive-rooted string, never a UNC path.
    local_drive(unsafe { GetDriveTypeW(root.as_ptr()) })?;
    // Include the drive root, then each ordinary component. RootDir is already used.
    let paths = std::iter::once(current.clone()).chain(components.filter_map(|c| {
        if let Component::Normal(n) = c {
            current.push(n);
            Some(current.clone())
        } else {
            None
        }
    }));
    for current in paths {
        let share = FILE_SHARE_READ | if read_only { 0 } else { FILE_SHARE_WRITE };
        let initial_share = if current == path { 7 } else { share };
        let open = || {
            crate::windows_native::open(
                &current,
                FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                initial_share,
                1,
                0,
                std::ptr::null_mut(),
            )
        };
        let file = match open() {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                if !create_directories {
                    break;
                }
                match crate::windows_native::open(
                    &current,
                    FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                    share,
                    2,
                    1,
                    std::ptr::null_mut(),
                ) {
                    Ok(_) => (),
                    Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => (),
                    Err(e) => return Err(e.into()),
                }
                open()?
            }
            Err(error) => return Err(error).context("open local storage ancestor"),
        };
        let metadata = file.metadata()?;
        ensure!(
            metadata.file_attributes() & 0x400 == 0,
            "storage cannot traverse a reparse point, junction or cloud placeholder"
        );
        if metadata.is_dir() {
            if current == path {
                // The leaf may be a live writer-locked file. Inspect it with
                // permissive sharing, but pin directory leaves with the policy.
                let pinned = crate::windows_native::open(
                    &current,
                    FILE_READ_ATTRIBUTES | FILE_LIST_DIRECTORY,
                    share,
                    1,
                    1,
                    std::ptr::null_mut(),
                )?;
                ancestors.push(pinned);
            } else {
                ancestors.push(file);
            }
        } else {
            ensure!(
                current == path && !create_directories,
                "storage ancestor is not a directory"
            );
        }
    }
    Ok(Guard {
        path,
        _ancestors: ancestors,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_FLAG_OPEN_REPARSE_POINT,
    };
    #[test]
    fn path_spellings_and_drive_types() {
        let cwd = Path::new(r"C:\local\work");
        for text in [
            r"\\server\share\wallet",
            r"\\?\UNC\server\share",
            r"\\?\C:\wallet",
            r"\\.\C:\wallet",
            r"C:wallet",
            r"\wallet",
            r"C:\a:stream",
            r"C:\NUL.txt",
            r"C:\COM1",
            r"C:\LPT¹.txt",
            r"C:\folder.\wallet",
            r"C:\folder \wallet",
        ] {
            assert!(normalize(Path::new(text), cwd).is_err(), "{text}");
        }
        assert_eq!(
            normalize(Path::new(r"..\wallet.json"), cwd).unwrap(),
            Path::new(r"C:\local\wallet.json")
        );
        for kind in [2, 3, 6] {
            local_drive(kind).unwrap();
        }
        for kind in [0, 1, 4, 5] {
            assert!(local_drive(kind).is_err());
        }
    }
    #[test]
    fn pinned_directory_cannot_be_renamed_or_opened_for_reparse_write() {
        let temp = tempfile::tempdir().unwrap();
        let folder = temp.path().join("parent");
        std::fs::create_dir(&folder).unwrap();
        let guard = guard_mode(&folder.join("wallet"), false, true).unwrap();
        assert!(std::fs::rename(&folder, temp.path().join("renamed")).is_err());
        assert!(
            OpenOptions::new()
                .write(true)
                .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&folder)
                .is_err()
        );
        drop(guard);
        std::fs::rename(&folder, temp.path().join("renamed")).unwrap();
    }
    #[test]
    fn junctions_are_rejected_without_following_them() {
        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        let link = temp.path().join("link");
        std::fs::create_dir(&target).unwrap();
        let output = std::process::Command::new("cmd")
            .args(["/c", "mklink", "/J"])
            .arg(&link)
            .arg(&target)
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        assert!(guard(&link.join("wallet"), false).is_err());
        assert!(guard_at(Path::new(r"..\wallet"), false, false, &link).is_err());
        assert!(guard_at(Path::new(r"..\wallet"), false, false, &target).is_ok());
        std::fs::remove_dir(&link).unwrap();
    }
    #[test]
    fn native_use_rejects_a_reparse_added_after_validation() {
        use std::os::windows::{ffi::OsStrExt, io::AsRawHandle};
        #[link(name = "kernel32")]
        unsafe extern "system" {
            fn DeviceIoControl(
                handle: windows_sys::Win32::Foundation::HANDLE,
                code: u32,
                input: *const std::ffi::c_void,
                length: u32,
                output: *mut std::ffi::c_void,
                output_length: u32,
                returned: *mut u32,
                overlapped: *mut std::ffi::c_void,
            ) -> i32;
        }
        let temp = tempfile::tempdir().unwrap();
        let parent = temp.path().join("parent");
        let target = temp.path().join("target");
        std::fs::create_dir(&parent).unwrap();
        std::fs::create_dir(&target).unwrap();
        let pin = guard(&parent.join("wallet"), false).unwrap();
        let writer = OpenOptions::new()
            .write(true)
            .custom_flags(FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&parent)
            .unwrap();
        let substitute: Vec<u16> = std::ffi::OsStr::new("\\??\\")
            .encode_wide()
            .chain(target.as_os_str().encode_wide())
            .collect();
        let display: Vec<u16> = target.as_os_str().encode_wide().collect();
        let mut data = vec![];
        data.extend_from_slice(&0xa0000003u32.to_le_bytes());
        data.extend_from_slice(
            &((8 + (substitute.len() + display.len() + 2) * 2) as u16).to_le_bytes(),
        );
        for value in [
            0u16,
            0,
            (substitute.len() * 2) as u16,
            ((substitute.len() + 1) * 2) as u16,
            (display.len() * 2) as u16,
        ] {
            data.extend_from_slice(&value.to_le_bytes());
        }
        for value in substitute
            .into_iter()
            .chain(Some(0))
            .chain(display)
            .chain(Some(0))
        {
            data.extend_from_slice(&value.to_le_bytes());
        }
        let mut returned = 0;
        // SAFETY: a well-formed mount-point buffer affects only this test's empty
        // local directory. The pin remains live to exercise validation-to-use.
        let changed = unsafe {
            DeviceIoControl(
                writer.as_raw_handle(),
                0x900a4,
                data.as_ptr().cast(),
                data.len() as u32,
                std::ptr::null_mut(),
                0,
                &mut returned,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(changed, 0, "{}", std::io::Error::last_os_error());
        drop(writer);
        assert!(
            crate::windows_native::open(
                &parent.join("wallet"),
                0xc0010000,
                7,
                2,
                0x40,
                std::ptr::null_mut()
            )
            .is_err()
        );
        assert!(!target.join("wallet").exists());
        drop(pin);
        std::fs::remove_dir(&parent).unwrap();
    }
}
