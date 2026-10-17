//! Native protected owner-only DACLs. No executable/environment-based identity.
use anyhow::{Result, ensure};
use std::{
    ffi::c_void,
    fs::File,
    os::windows::{ffi::OsStrExt, io::AsRawHandle},
    path::Path,
    ptr,
};
use windows_sys::Win32::{
    Foundation::{CloseHandle, HANDLE, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE,
        Authorization::{
            ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW,
            GetSecurityInfo, SE_FILE_OBJECT,
        },
        DACL_SECURITY_INFORMATION, EqualSid, GetAce, GetSecurityDescriptorControl,
        GetSecurityDescriptorDacl, GetSecurityDescriptorOwner, GetTokenInformation,
        OWNER_SECURITY_INFORMATION, PROTECTED_DACL_SECURITY_INFORMATION, SE_DACL_PROTECTED,
        SetFileSecurityW, TOKEN_QUERY, TOKEN_USER, TokenUser,
    },
    System::Threading::{GetCurrentProcess, OpenProcessToken},
};
struct Allocation(*mut c_void);
impl Drop for Allocation {
    fn drop(&mut self) {
        // SAFETY: these allocations come only from APIs documented to use LocalFree.
        unsafe {
            LocalFree(self.0);
        }
    }
}
struct Token(HANDLE);
impl Drop for Token {
    fn drop(&mut self) {
        // SAFETY: this is the owned process token opened by OpenProcessToken.
        unsafe {
            CloseHandle(self.0);
        }
    }
}
fn check(ok: i32) -> Result<()> {
    if ok == 0 {
        return Err(std::io::Error::last_os_error().into());
    }
    Ok(())
}
fn wide(text: &std::ffi::OsStr) -> Result<Vec<u16>> {
    let mut v: Vec<_> = text.encode_wide().collect();
    ensure!(!v.contains(&0), "NUL in filesystem path");
    v.push(0);
    Ok(v)
}
unsafe fn allocated_string(value: *const u16) -> String {
    let mut len = 0;
    // SAFETY: caller supplies a successful Windows allocated, NUL-terminated string.
    unsafe {
        while *value.add(len) != 0 {
            len += 1;
        }
        String::from_utf16_lossy(std::slice::from_raw_parts(value, len))
    }
}
fn sid() -> Result<String> {
    // SAFETY: token handles and aligned TOKEN_USER storage remain live until SID
    // conversion finishes; API-returned allocation ownership is transferred to RAII.
    unsafe {
        let mut token = ptr::null_mut();
        check(OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY,
            &mut token,
        ))?;
        let token = Token(token);
        let mut length = 0;
        GetTokenInformation(token.0, TokenUser, ptr::null_mut(), 0, &mut length);
        ensure!(
            length as usize >= size_of::<TOKEN_USER>() && length < 65536,
            "invalid token information size"
        );
        let mut buffer = vec![0usize; (length as usize).div_ceil(size_of::<usize>())];
        check(GetTokenInformation(
            token.0,
            TokenUser,
            buffer.as_mut_ptr().cast(),
            length,
            &mut length,
        ))?;
        let user = &*buffer.as_ptr().cast::<TOKEN_USER>();
        let mut text = ptr::null_mut();
        check(ConvertSidToStringSidW(user.User.Sid, &mut text))?;
        let _allocation = Allocation(text.cast());
        Ok(allocated_string(text))
    }
}
fn expected(directory: bool) -> Result<String> {
    let sid = sid()?;
    let flags = if directory { "OICI" } else { "" };
    Ok(format!("O:{sid}D:P(A;{flags};FA;;;{sid})"))
}
fn descriptor(sddl: &str) -> Result<Allocation> {
    let text = wide(std::ffi::OsStr::new(sddl))?;
    let mut descriptor = ptr::null_mut();
    // SAFETY: text is terminated; successful allocation is owned by Allocation.
    unsafe {
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            text.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        ))?;
    }
    Ok(Allocation(descriptor))
}
/// Native FILE_CREATE attaches the protected DACL before the name is visible.
pub fn create_private_file(path: &Path) -> std::io::Result<File> {
    let create = || -> Result<File> {
        let descriptor = descriptor(&expected(false)?)?;
        let file = crate::windows_native::open(path, 0xc0010000, 7, 2, 0x40, descriptor.0)?;
        if let Err(error) = assert_private(&file) {
            crate::windows_native::delete_on_close(&file);
            return Err(error);
        }
        Ok(file)
    };
    match create() {
        Ok(file) => Ok(file),
        Err(error) => {
            // Preserve AlreadyExists so tempfile can retry a colliding random name.
            match error.downcast::<std::io::Error>() {
                Ok(error) => Err(error),
                Err(error) => Err(std::io::Error::other(error)),
            }
        }
    }
}
pub fn private(path: &Path) -> Result<()> {
    let sddl = wide(std::ffi::OsStr::new(&expected(path.is_dir())?))?;
    let path = wide(path.as_os_str())?;
    // SAFETY: both UTF-16 strings are terminated and live for the call; descriptor
    // is allocated by Windows, and SetFileSecurity consumes it synchronously.
    unsafe {
        let mut descriptor = ptr::null_mut();
        check(ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl.as_ptr(),
            1,
            &mut descriptor,
            ptr::null_mut(),
        ))?;
        let _allocation = Allocation(descriptor);
        check(SetFileSecurityW(
            path.as_ptr(),
            OWNER_SECURITY_INFORMATION
                | DACL_SECURITY_INFORMATION
                | PROTECTED_DACL_SECURITY_INFORMATION,
            descriptor,
        ))?;
    }
    Ok(())
}
pub fn assert_private(file: &File) -> Result<()> {
    let expected = descriptor(&expected(file.metadata()?.is_dir())?)?;
    // SAFETY: File owns a live kernel handle. GetSecurityInfo allocates the
    // returned descriptor, which remains owned by Allocation during validation.
    unsafe {
        let mut descriptor = ptr::null_mut();
        let status = GetSecurityInfo(
            file.as_raw_handle().cast(),
            SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            ptr::null_mut(),
            &mut descriptor,
        );
        ensure!(status == 0, "cannot inspect cache ACL: {status}");
        assert_private_descriptor(&Allocation(descriptor), &expected)?;
    }
    Ok(())
}

fn assert_private_descriptor(actual: &Allocation, expected: &Allocation) -> Result<()> {
    const INVALID: &str =
        "cache must have a protected current-owner-only DACL; use a fresh private directory";
    // Compare security properties rather than SDDL spelling. Windows can render
    // numeric SIDs as aliases and add auto-inheritance bookkeeping flags without
    // changing the protected, single-owner grant.
    // SAFETY: both allocations are valid descriptors returned by Windows APIs.
    // The owner, ACL, and ACE pointers borrow them and never outlive their storage.
    unsafe {
        let mut control = 0;
        let mut revision = 0;
        check(GetSecurityDescriptorControl(
            actual.0,
            &mut control,
            &mut revision,
        ))?;
        ensure!(control & SE_DACL_PROTECTED != 0, INVALID);
        let mut actual_owner = ptr::null_mut();
        let mut expected_owner = ptr::null_mut();
        let mut defaulted = 0;
        check(GetSecurityDescriptorOwner(
            actual.0,
            &mut actual_owner,
            &mut defaulted,
        ))?;
        check(GetSecurityDescriptorOwner(
            expected.0,
            &mut expected_owner,
            &mut defaulted,
        ))?;
        ensure!(
            !actual_owner.is_null()
                && !expected_owner.is_null()
                && EqualSid(actual_owner, expected_owner) != 0,
            INVALID
        );
        let mut actual_acl = ptr::null_mut();
        let mut expected_acl = ptr::null_mut();
        let mut present = 0;
        check(GetSecurityDescriptorDacl(
            actual.0,
            &mut present,
            &mut actual_acl,
            &mut defaulted,
        ))?;
        ensure!(
            present != 0 && !actual_acl.is_null() && (*actual_acl).AceCount == 1,
            INVALID
        );
        check(GetSecurityDescriptorDacl(
            expected.0,
            &mut present,
            &mut expected_acl,
            &mut defaulted,
        ))?;
        ensure!(
            present != 0 && !expected_acl.is_null() && (*expected_acl).AceCount == 1,
            INVALID
        );
        let mut actual_ace = ptr::null_mut();
        let mut expected_ace = ptr::null_mut();
        check(GetAce(actual_acl, 0, &mut actual_ace))?;
        check(GetAce(expected_acl, 0, &mut expected_ace))?;
        let actual_ace = &*actual_ace.cast::<ACCESS_ALLOWED_ACE>();
        let expected_ace = &*expected_ace.cast::<ACCESS_ALLOWED_ACE>();
        ensure!(
            actual_ace.Header.AceType == expected_ace.Header.AceType
                && actual_ace.Header.AceFlags == expected_ace.Header.AceFlags
                && actual_ace.Mask == expected_ace.Mask
                && EqualSid(
                    ptr::addr_of!(actual_ace.SidStart).cast_mut().cast(),
                    ptr::addr_of!(expected_ace.SidStart).cast_mut().cast(),
                ) != 0,
            INVALID
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use windows_sys::Win32::Security::{
        Authorization::ConvertStringSidToSidW, CreateRestrictedToken, DISABLE_MAX_PRIVILEGE,
        ImpersonateLoggedOnUser, RevertToSelf, SID_AND_ATTRIBUTES, TOKEN_DUPLICATE,
        TOKEN_IMPERSONATE,
    };

    #[test]
    fn equivalent_sid_spelling_and_acl_bookkeeping_are_accepted() {
        for flags in ["", "OICI"] {
            let expected = descriptor(&format!("O:S-1-5-18D:P(A;{flags};FA;;;S-1-5-18)")).unwrap();
            for control in ["P", "PAI", "PAR"] {
                let actual = descriptor(&format!("O:SYD:{control}(A;{flags};FA;;;SY)")).unwrap();
                assert_private_descriptor(&actual, &expected).unwrap();
            }
        }
    }

    #[test]
    fn owner_only_validation_rejects_changed_security_properties() {
        let expected = descriptor("O:SYD:P(A;;FA;;;SY)").unwrap();
        for sddl in [
            "O:BAD:P(A;;FA;;;SY)",
            "O:SYD:(A;;FA;;;SY)",
            "O:SYD:PNO_ACCESS_CONTROL",
            "O:SYD:P",
            "O:SYD:P(A;;FA;;;SY)(A;;GR;;;WD)",
            "O:SYD:P(A;;FA;;;WD)",
            "O:SYD:P(D;;FA;;;SY)",
            "O:SYD:P(A;;GR;;;SY)",
            "O:SYD:P(A;ID;FA;;;SY)",
            "O:SYD:P(A;OICI;FA;;;SY)",
        ] {
            let actual = descriptor(sddl).unwrap();
            assert!(
                assert_private_descriptor(&actual, &expected).is_err(),
                "{sddl}"
            );
        }
        let expected_directory = descriptor("O:SYD:P(A;OICI;FA;;;SY)").unwrap();
        for flags in ["", "OI", "CI", "OICIIO", "OICIID"] {
            let actual = descriptor(&format!("O:SYD:P(A;{flags};FA;;;SY)")).unwrap();
            assert!(
                assert_private_descriptor(&actual, &expected_directory).is_err(),
                "{flags}"
            );
        }
    }
    fn restricted_open(path: &Path) -> Result<std::io::Result<File>> {
        // SAFETY: all token/SID outputs are owned by RAII; impersonation is thread-local
        // and reverted before the result is returned, including during unwinding.
        unsafe {
            let mut process = ptr::null_mut();
            check(OpenProcessToken(
                GetCurrentProcess(),
                TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_IMPERSONATE,
                &mut process,
            ))?;
            let process = Token(process);
            let mut world = ptr::null_mut();
            let text = wide(std::ffi::OsStr::new("S-1-1-0"))?;
            check(ConvertStringSidToSidW(text.as_ptr(), &mut world))?;
            let _world = Allocation(world);
            let restricting = SID_AND_ATTRIBUTES {
                Sid: world,
                Attributes: 0,
            };
            let mut restricted = ptr::null_mut();
            check(CreateRestrictedToken(
                process.0,
                DISABLE_MAX_PRIVILEGE,
                0,
                ptr::null(),
                0,
                ptr::null(),
                1,
                &restricting,
                &mut restricted,
            ))?;
            let restricted = Token(restricted);
            check(ImpersonateLoggedOnUser(restricted.0))?;
            struct Revert;
            impl Drop for Revert {
                fn drop(&mut self) {
                    // SAFETY: restores this test thread's process identity.
                    assert_ne!(unsafe { RevertToSelf() }, 0);
                }
            }
            let _revert = Revert;
            Ok(File::open(path))
        }
    }
    #[test]
    fn owner_acl_exists_before_first_write_in_shared_parent() {
        use std::io::Write;
        use std::os::windows::fs::OpenOptionsExt;
        let temp = tempfile::tempdir().unwrap();
        let shared = descriptor(&format!(
            "O:{}D:P(A;OICI;FA;;;{})(A;OICI;GRGX;;;WD)",
            sid().unwrap(),
            sid().unwrap()
        ))
        .unwrap();
        let path = wide(temp.path().as_os_str()).unwrap();
        // SAFETY: test-owned directory and valid security descriptor are live.
        unsafe {
            check(SetFileSecurityW(
                path.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                shared.0,
            ))
            .unwrap();
        }
        let legacy = tempfile::NamedTempFile::new_in(temp.path()).unwrap();
        assert!(
            restricted_open(legacy.path()).unwrap().is_ok(),
            "control must grant the adversarial token access under the inherited ACL"
        );
        let mut protected = tempfile::Builder::new()
            .make_in(temp.path(), create_private_file)
            .unwrap();
        // This is the deterministic pause point: the name exists, no bytes written.
        assert_private(protected.as_file()).unwrap();
        let error = restricted_open(protected.path()).unwrap().unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        protected.write_all(b"synthetic secret bytes").unwrap();
        let destination = temp.path().join("native.txt");
        protected.persist_noclobber(&destination).unwrap();
        assert_private(&File::open(&destination).unwrap()).unwrap();
        assert!(restricted_open(&destination).unwrap().is_err());
        assert!(crate::storage::write_bytes(&destination, b"overwrite", false).is_err());
        crate::storage::write_bytes(&destination, b"replacement", true).unwrap();
        assert_eq!(std::fs::read(&destination).unwrap(), b"replacement");
        let locked = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(1)
            .open(&destination)
            .unwrap();
        assert!(crate::storage::write_bytes(&destination, b"failed replacement", true).is_err());
        drop(locked);
        assert_eq!(std::fs::read(&destination).unwrap(), b"replacement");
        assert_eq!(std::fs::read_dir(temp.path()).unwrap().count(), 2);
    }
}
