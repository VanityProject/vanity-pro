#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(windows)]
fn main() {
    if let Some(code) = vanity_pro::backend::calibration::worker_entry() {
        std::process::exit(code);
    }
    if let Err(error) = vanity_pro::gui::run() {
        use windows_sys::Win32::UI::WindowsAndMessaging::{MB_ICONERROR, MB_OK, MessageBoxW};
        let message: Vec<u16> = format!("Vanity Pro could not start:\n{error:#}")
            .encode_utf16()
            .chain(Some(0))
            .collect();
        let title: Vec<u16> = "Vanity Pro".encode_utf16().chain(Some(0)).collect();
        // SAFETY: valid NUL-terminated strings, no owner HWND; synchronous system dialog.
        unsafe {
            MessageBoxW(
                std::ptr::null_mut(),
                message.as_ptr(),
                title.as_ptr(),
                MB_OK | MB_ICONERROR,
            );
        }
    }
}
#[cfg(not(windows))]
fn main() {
    if let Some(code) = vanity_pro::backend::calibration::worker_entry() {
        std::process::exit(code);
    }
    eprintln!("VanityPro GUI targets Windows 11 x64. Use the vanity CLI on this platform.");
}
