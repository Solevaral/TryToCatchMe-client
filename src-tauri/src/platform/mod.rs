//! Platform-specific integration behind a common surface.
//! Keep OS specifics isolated so other platforms can be added later.

#[cfg(windows)]
pub mod win;

/// Whether the current process has the privileges TUN mode needs.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    win::is_elevated()
}

/// Relaunch the app with elevated privileges (triggers a UAC prompt), then the
/// caller should exit the current, non-elevated instance.
#[cfg(windows)]
pub fn relaunch_elevated() -> Result<(), String> {
    win::relaunch_elevated()
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    // On non-Windows we don't gate TUN here yet.
    true
}

#[cfg(not(windows))]
pub fn relaunch_elevated() -> Result<(), String> {
    Ok(())
}
