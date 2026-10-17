//! Native file opens reject reparse traversal at use, not just at validation.
use std::{
    fs::File,
    os::windows::{
        ffi::OsStrExt,
        io::{AsRawHandle, FromRawHandle},
    },
    path::Path,
};
use windows_sys::Win32::Foundation::HANDLE;
#[repr(C)]
struct UnicodeString {
    length: u16,
    maximum_length: u16,
    buffer: *mut u16,
}
#[repr(C)]
struct ObjectAttributes {
    length: u32,
    root: HANDLE,
    name: *mut UnicodeString,
    attributes: u32,
    descriptor: *mut std::ffi::c_void,
    qos: *mut std::ffi::c_void,
}
#[repr(C)]
struct IoStatus {
    status: isize,
    information: usize,
}
#[link(name = "ntdll")]
unsafe extern "system" {
    fn NtCreateFile(
        handle: *mut HANDLE,
        access: u32,
        attributes: *const ObjectAttributes,
        status: *mut IoStatus,
        allocation: *const i64,
        file_attributes: u32,
        share: u32,
        disposition: u32,
        options: u32,
        ea: *const std::ffi::c_void,
        ea_length: u32,
    ) -> i32;
    fn NtSetInformationFile(
        handle: HANDLE,
        status: *mut IoStatus,
        information: *const std::ffi::c_void,
        length: u32,
        class: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}
fn result(status: i32) -> std::io::Result<()> {
    if status < 0 {
        // SAFETY: pure conversion of an NTSTATUS returned by the native API.
        Err(std::io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(status) } as i32,
        ))
    } else {
        Ok(())
    }
}
/// OBJ_DONT_REPARSE stops even an ancestor which changed after validation.
pub fn open(
    path: &Path,
    access: u32,
    share: u32,
    disposition: u32,
    options: u32,
    descriptor: *mut std::ffi::c_void,
) -> std::io::Result<File> {
    let path = crate::windows_paths::lexical(path).map_err(std::io::Error::other)?;
    let mut text: Vec<u16> = std::ffi::OsStr::new("\\??\\")
        .encode_wide()
        .chain(path.as_os_str().encode_wide())
        .collect();
    let length = u16::try_from(text.len() * 2).map_err(std::io::Error::other)?;
    let mut name = UnicodeString {
        length,
        maximum_length: length,
        buffer: text.as_mut_ptr(),
    };
    let attributes = ObjectAttributes {
        length: size_of::<ObjectAttributes>() as u32,
        root: std::ptr::null_mut(),
        name: &mut name,
        attributes: 0x40 | 0x1000,
        descriptor,
        qos: std::ptr::null_mut(),
    };
    let mut status = IoStatus {
        status: 0,
        information: 0,
    };
    let mut handle = std::ptr::null_mut();
    // SAFETY: all buffers/descriptors live through the synchronous call. The
    // resulting owned handle is transferred to File only after success.
    unsafe {
        result(NtCreateFile(
            &mut handle,
            access | 0x100000,
            &attributes,
            &mut status,
            std::ptr::null(),
            if options & 1 != 0 { 0x10 } else { 0x100 },
            share,
            disposition,
            options | 0x20 | 0x4000 | 0x200000,
            std::ptr::null(),
            0,
        ))?;
        Ok(File::from_raw_handle(handle))
    }
}
pub fn persist(
    file: &File,
    parent: &File,
    name: &std::ffi::OsStr,
    replace: bool,
) -> std::io::Result<()> {
    #[repr(C)]
    struct Rename {
        replace: u32,
        root: HANDLE,
        length: u32,
        name: [u16; 1],
    }
    let name: Vec<u16> = name.encode_wide().collect();
    let bytes = std::mem::offset_of!(Rename, name) + name.len() * 2;
    let mut buffer = vec![0usize; bytes.div_ceil(size_of::<usize>())];
    let rename = buffer.as_mut_ptr().cast::<Rename>();
    let mut status = IoStatus {
        status: 0,
        information: 0,
    };
    // SAFETY: aligned storage includes header and variable UTF-16 name; handles
    // remain live. A single component relative to a directory handle cannot
    // follow a changed ancestor or the parent's own reparse target.
    unsafe {
        (*rename).replace = u32::from(replace);
        (*rename).root = parent.as_raw_handle();
        (*rename).length = (name.len() * 2) as u32;
        std::ptr::copy_nonoverlapping(name.as_ptr(), (*rename).name.as_mut_ptr(), name.len());
        result(NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            rename.cast(),
            bytes as u32,
            10,
        ))
    }
}
pub fn delete_on_close(file: &File) {
    let delete = 1u8;
    let mut status = IoStatus {
        status: 0,
        information: 0,
    };
    // SAFETY: marks an owned temporary handle for deletion without resolving its path.
    unsafe {
        NtSetInformationFile(
            file.as_raw_handle(),
            &mut status,
            (&delete as *const u8).cast(),
            1,
            13,
        );
    }
}
