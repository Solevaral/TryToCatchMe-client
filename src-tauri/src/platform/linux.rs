//! Linux-specific integration.
//!
//! TUN needs CAP_NET_ADMIN. The GUI stays an ordinary user process; instead, on the
//! first TUN connect one pkexec script (one polkit password prompt) does the one-time
//! setup, and later connects run without asking:
//! - installs the bundled sing-box into a root-owned dir with network capabilities
//!   (root-owned so no user process can swap the privileged binary);
//! - adds a polkit rule letting this (local, active) user change systemd-resolved DNS
//!   settings: sing-box configures the tun's DNS over D-Bus, and polkit checks the uid,
//!   not capabilities — without the rule every connect asked for the password again;
//! - allows inbound traffic on the tun interface in ufw / firewalld: the "mixed" stack
//!   hands TCP back through the tun as inbound packets, which a default-deny firewall drops;
//! - writes a setup version mark.
//! A new app version with a different core or a newer setup version re-runs the script
//! (one more prompt).

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

/// TUN interface name, the firewall rules are bound to it (set in the core config).
pub const IFACE: &str = ttcm_core::config::TUN_IFACE_LINUX;

const DIR: &str = "/opt/trytocatchme";
const CORE: &str = "/opt/trytocatchme/sing-box";
const CAPS: &str = "cap_net_admin,cap_net_raw,cap_net_bind_service+ep";
/// Bump when the setup script changes, so existing installs run it once more.
const SETUP_VERSION: &str = "2";
const SETUP_MARK: &str = "/opt/trytocatchme/setup-version";
const POLKIT_DIR: &str = "/etc/polkit-1/rules.d";
const POLKIT_RULE: &str = "/etc/polkit-1/rules.d/49-trytocatchme.rules";
/// `@USER@` is replaced by the script with the name of the user who ran pkexec.
const POLKIT_RULE_TEMPLATE: &str = r#"// TryToCatchMe: the VPN core may set the TUN interface's DNS in systemd-resolved
// without a password prompt. Remove this file to revoke.
polkit.addRule(function(action, subject) {
    if ((action.id.indexOf("org.freedesktop.resolve1.set-") == 0 ||
         action.id == "org.freedesktop.resolve1.revert") &&
        subject.user == "@USER@" && subject.local && subject.active) {
        return polkit.Result.YES;
    }
});
"#;

/// Upstream DNS servers for direct resolution in TUN mode (see `GenOptions::direct_dns`).
/// systemd-resolved lists its real upstreams in its own resolv.conf; without resolved,
/// /etc/resolv.conf already holds them. Empty when only a local stub is configured.
pub fn upstream_dns() -> Vec<String> {
    ["/run/systemd/resolve/resolv.conf", "/etc/resolv.conf"]
        .iter()
        .filter_map(|p| fs::read_to_string(p).ok())
        .map(|text| ttcm_core::config::upstream_nameservers(&text))
        .find(|servers| !servers.is_empty())
        .unwrap_or_default()
}

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

/// The installed core is the bundled one, still has its capabilities, and the setup
/// script that installed it is the current one.
fn installed_matches(bundled: &Path) -> bool {
    let core = Path::new(CORE);
    let same_size = match (fs::metadata(bundled), fs::metadata(core)) {
        (Ok(a), Ok(b)) => a.len() == b.len(),
        _ => false,
    };
    same_size
        && has_caps(core)
        && fs::read_to_string(SETUP_MARK).is_ok_and(|v| v.trim() == SETUP_VERSION)
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
    // $1 — staged core, $2 — polkit rule template. The user name is checked to be
    // plain before it goes into the rule (a JS string).
    let script = format!(
        "set -e; umask 022; \
         command -v setcap >/dev/null || {{ echo 'не найдена утилита setcap (пакет libcap / libcap2-bin)' >&2; exit 3; }}; \
         u=$(id -nu \"$PKEXEC_UID\") || {{ echo 'не удалось определить пользователя' >&2; exit 4; }}; \
         case \"$u\" in ''|*[!A-Za-z0-9._-]*) echo \"недопустимое имя пользователя: $u\" >&2; exit 4;; esac; \
         install -d -m 755 {DIR}; \
         install -m 755 -o root -g root \"$1\" {CORE}; \
         setcap {CAPS} {CORE}; \
         [ -d {POLKIT_DIR} ] || mkdir -p {POLKIT_DIR}; \
         printf '%s' \"${{2%%@USER@*}}$u${{2#*@USER@}}\" > {POLKIT_RULE}.tmp; \
         chmod 644 {POLKIT_RULE}.tmp; mv -f {POLKIT_RULE}.tmp {POLKIT_RULE}; \
         if command -v ufw >/dev/null; then ufw allow in on {IFACE} comment TryToCatchMe >/dev/null 2>&1 || true; fi; \
         if command -v firewall-cmd >/dev/null && firewall-cmd --state >/dev/null 2>&1; then \
           firewall-cmd --permanent --zone=trusted --add-interface={IFACE} >/dev/null 2>&1 || true; \
           firewall-cmd --reload >/dev/null 2>&1 || true; \
         fi; \
         echo {SETUP_VERSION} > {SETUP_MARK}"
    );
    let out = Command::new("pkexec")
        .args(["/bin/sh", "-c", &script, "sh"])
        .arg(&stage)
        .arg(POLKIT_RULE_TEMPLATE)
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
