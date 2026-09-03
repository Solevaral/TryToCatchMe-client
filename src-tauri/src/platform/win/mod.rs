//! Windows-specific integration.
//!
//! - Wintun (wintun.dll) is shipped next to the sing-box sidecar for TUN mode.
//! - Elevation check + relaunch for TUN (which needs administrator rights).

use std::process::Command;

/// True if the process is running with administrator rights.
pub fn is_elevated() -> bool {
    is_elevated::is_elevated()
}

/// Relaunch this executable elevated via a UAC prompt. The caller exits afterwards.
pub fn relaunch_elevated() -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| format!("current_exe: {e}"))?;
    let mut cmd = Command::new("powershell");
    cmd.args([
        "-NoProfile",
        "-WindowStyle",
        "Hidden",
        "-Command",
        &format!("Start-Process -FilePath '{}' -Verb RunAs", exe.display()),
    ]);
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    cmd.spawn()
        .map(|_| ())
        .map_err(|e| format!("relaunch elevated: {e}"))
}
