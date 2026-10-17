pub mod backend;
pub mod chains;
pub mod coordinator;
pub mod crypto;
pub mod desktop;
#[cfg(all(windows, feature = "gui"))]
pub mod gui;
mod key_manager;
pub mod model;
pub mod split;
pub mod storage;
pub mod transforms;
#[cfg(windows)]
mod windows_acl;
#[cfg(windows)]
mod windows_native;
#[cfg(windows)]
mod windows_paths;
pub mod work;

pub use key_manager::{
    check_finalization, export_native, finalize, initialize, initialize_with_strategy,
    search_ed25519, validate_finalization_password, verify_wallet, wallet_profile,
};
