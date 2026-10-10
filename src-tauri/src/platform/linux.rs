//! Linux-specific integration.
//!
//! TUN needs CAP_NET_ADMIN. The GUI stays an ordinary user process; instead, on the
//! first TUN connect the bundled sing-box is installed once into a root-owned dir with
//! network capabilities (one polkit password prompt via pkexec), and later connects run
//! it from there without asking. Root-owned so no user process can swap the privileged
//! binary. A new app version with a different core re-installs it (one more prompt).

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

const DIR: &str = "/opt/trytocatchme";
const CORE: &str = "/opt/trytocatchme/sing-box";
const CAPS: &str = "cap_net_admin,cap_net_raw,cap_net_bind_service+ep";

fn is_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}

/// The file carries file capabilities (the `security.capability` xattr is set).
fn has_caps(path: &Path) -> bool {
    let Ok(p) = CString::new(path.as_os_str().as_bytes()) else { return false };
    let name = b"security.capability\0";
    let n = unsafe { libc::getxattr(p.as_ptr(), name.as_ptr().cast(), std::ptr::null_mut(), 0) };
    n > 0
}

/// The installed core is the bundled one and still has its capabilities.
fn installed_matches(bundled: &Path) -> bool {
    let core = Path::new(CORE);
    let same_size = match (fs::metadata(bundled), fs::metadata(core)) {
        (Ok(a), Ok(b)) => a.len() == b.len(),
        _ => false,
    };
    same_size
        && has_caps(core)
        && matches!((fs::read(bundled), fs::read(core)), (Ok(a), Ok(b)) if a == b)
}

/// The sing-box binary to run in TUN mode. Installs it with capabilities first if
/// needed — this blocks on the system password dialog, so call it off the UI thread.
pub fn tun_core(bundled: &Path) -> Result<PathBuf, String> {
    if is_root() {
        return Ok(bundled.to_path_buf());
    }
    if installed_matches(bundled) {
        return Ok(PathBuf::from(CORE));
    }

    // Root can't read the AppImage's FUSE mount: stage a copy it can read.
    let stage = std::env::temp_dir().join(format!("ttcm-sing-box-{}", std::process::id()));
    fs::copy(bundled, &stage).map_err(|e| format!("не удалось подготовить ядро: {e}"))?;
    let script = format!(
        "set -e; \
         command -v setcap >/dev/null || {{ echo 'не найдена утилита setcap (пакет libcap / libcap2-bin)' >&2; exit 3; }}; \
         install -d -m 755 {DIR}; \
         install -m 755 -o root -g root \"$1\" {CORE}; \
         setcap {CAPS} {CORE}"
    );
    let out = Command::new("pkexec")
        .args(["/bin/sh", "-c", &script, "sh"])
        .arg(&stage)
        .output();
    let _ = fs::remove_file(&stage);
    let out = out.map_err(|e| format!("не найден pkexec (polkit): {e}"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr).trim().to_string();
        return Err(match out.status.code() {
            // pkexec: 126 — dialog dismissed, 127 — not authorized / no polkit agent.
            Some(126) | Some(127) if err.is_empty() => "права не выданы (ввод пароля отменён)".to_string(),
            Some(126) | Some(127) => format!("права не выданы: {err}"),
            _ => format!("не удалось установить ядро в {DIR}: {err}"),
        });
    }
    if !installed_matches(bundled) {
        return Err(format!(
            "ядро установлено в {DIR}, но capabilities не применились (файловая система без xattr или nosuid?)"
        ));
    }
    Ok(PathBuf::from(CORE))
}
