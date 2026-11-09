//! The app owns the OS system proxy (never sing-box).
//!
//! On connect we snapshot the user's settings, persist that snapshot to disk and point
//! the system proxy at our local port. On disconnect we put the snapshot back — but only
//! if the proxy still points at us, so another app's settings (e.g. Hiddify) are never
//! clobbered. The on-disk backup lets the next launch clean up after a crash or a kill.

pub mod os;
pub mod pac_server;

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use os::{Snapshot, HOST};

#[derive(Serialize, Deserialize)]
struct Backup {
    port: u16,
    snapshot: Snapshot,
    #[serde(default)]
    restore_pending: bool,
}

#[derive(Default)]
pub struct SysProxyState {
    /// Port we pointed the system proxy at, while applied.
    applied: Mutex<Option<u16>>,
    /// Set once we've warned about an overwrite, until the proxy is ours again.
    overwrite_reported: AtomicBool,
    /// PAC URL currently set (Linux), so `reapply` restores the same mode.
    pac_url: Mutex<Option<String>>,
    pac: pac_server::PacServer,
}

#[derive(Serialize, Clone)]
pub struct SysProxyStatus {
    /// Our port while the app manages the system proxy (connected, not TUN).
    pub applied_port: Option<u16>,
    /// The system proxy currently points at our port.
    pub ours: bool,
    /// Human-readable current OS setting.
    pub current: String,
}

fn backup_path(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_config_dir().ok().map(|d| d.join("sysproxy-backup.json"))
}

fn read_backup(app: &AppHandle) -> Option<Backup> {
    let bytes = fs::read(backup_path(app)?).ok()?;
    serde_json::from_slice(&bytes).ok()
}

fn write_backup(app: &AppHandle, backup: &Backup) -> Result<(), String> {
    let path = backup_path(app).ok_or("нет папки настроек")?;
    crate::storage::save(&path, backup)
}

fn delete_backup(app: &AppHandle) -> Result<(), String> {
    // If deletion fails after a successful restore, never retry that restore later.
    if let Some(mut backup) = read_backup(app) {
        backup.restore_pending = false;
        write_backup(app, &backup)?;
    }
    let path = backup_path(app).ok_or("Нет папки настроек")?;
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(format!("Настройки восстановлены, но удалить резервную копию не удалось: {e}")),
    }
}

impl SysProxyState {
    /// Point the system proxy at `127.0.0.1:port`, remembering the previous settings.
    /// With a PAC script (Linux) the proxy becomes "automatic": only the hosts the
    /// script sends to the proxy reach it. Returns a note when the PAC couldn't be used.
    pub fn apply(&self, app: &AppHandle, port: u16, pac: Option<String>) -> Result<Option<String>, String> {
        // Reuse a leftover backup (previous crash): the live settings are then OUR stale
        // proxy, and restoring them would keep the machine pointed at a dead port.
        let snapshot = match read_backup(app) {
            Some(b) => b.snapshot,
            None if os::points_to(HOST, port) => os::disabled(),
            None => os::snapshot()?,
        };
        write_backup(app, &Backup { port, snapshot, restore_pending: false })?;
        let mut note = None;
        let pac_url = pac.and_then(|script| match self.pac.serve(ttcm_core::config::pac_port(port), script) {
            // A fresh query each connect: apps re-fetch the script when the URL changes.
            Ok(()) => Some(format!("{}?{}", os::pac_url_base(port), std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0))),
            Err(e) => {
                note = Some(format!("{e} — системный прокси включён целиком, без PAC"));
                None
            }
        });
        os::apply(HOST, port, pac_url.as_deref())?;
        *self.pac_url.lock() = pac_url;
        *self.applied.lock() = Some(port);
        self.overwrite_reported.store(false, Ordering::SeqCst);
        Ok(note)
    }

    /// Put the user's previous settings back (if the proxy still points at us).
    /// Returns a message for the log when something was restored or skipped.
    pub fn release(&self, app: &AppHandle) -> Option<String> {
        let port = (*self.applied.lock()).or_else(|| read_backup(app).map(|b| b.port))?;
        let mut attempted = false;
        let mut restored = false;
        self.pac.set_direct();
        *self.pac_url.lock() = None;
        let mut backup = read_backup(app);
        let msg = if should_restore_backup(os::points_to(HOST, port), backup.as_ref().is_some_and(|b| b.restore_pending)) {
            attempted = true;
            if let Some(b) = backup.as_mut() {
                b.restore_pending = true;
                if let Err(e) = write_backup(app, b) { return Some(e); }
            }
            let snap = backup.map(|b| b.snapshot).unwrap_or_else(os::disabled);
            match os::restore(&snap) {
                Ok(()) => { restored = true; "Системный прокси возвращён к прежним настройкам".to_string() },
                Err(e) => format!("Не удалось вернуть системный прокси: {e}. Отключите прокси вручную в настройках системы."),
            }
        } else {
            "Системный прокси уже изменён другой программой — не трогаю его".to_string()
        };
        if may_delete_backup(attempted, restored) {
            if let Err(e) = delete_backup(app) { return Some(e); }
        }
        if restored || !os::points_to(HOST, port) { *self.applied.lock() = None; }
        Some(msg)
    }

    /// On startup: clean up after a crash/kill that left the proxy pointing at us.
    pub fn recover(&self, app: &AppHandle, configured_port: u16) -> Option<String> {
        match read_backup(app) {
            Some(mut b) => {
                let mut restored = false;
                let mut attempted = false;
                let msg = if should_restore_backup(os::points_to(HOST, b.port), b.restore_pending) {
                    attempted = true;
                    b.restore_pending = true;
                    if let Err(e) = write_backup(app, &b) { return Some(e); }
                    match os::restore(&b.snapshot) {
                        Ok(()) => { restored = true; Some("Приложение в прошлый раз завершилось аварийно — системный прокси возвращён к прежним настройкам".to_string()) },
                        Err(e) => Some(format!("Не удалось вернуть системный прокси после аварийного завершения: {e}")),
                    }
                } else {
                    None
                };
                if may_delete_backup(attempted, restored) {
                    if let Err(e) = delete_backup(app) { return Some(e); }
                }
                msg
            }
            // No backup, but the proxy points at our port (e.g. left behind by an older
            // version that let sing-box manage it): nothing is listening there — turn it off.
            None if os::points_to(HOST, configured_port) => match os::restore(&os::disabled()) {
                Ok(()) => Some(format!("Системный прокси указывал на неработающий {HOST}:{configured_port} — отключён")),
                Err(e) => Some(format!("Системный прокси указывает на неработающий {HOST}:{configured_port}, отключить не удалось: {e}")),
            },
            None => None,
        }
    }

    /// Re-point the system proxy at us after another program overwrote it.
    pub fn reapply(&self) -> Result<(), String> {
        let port = (*self.applied.lock()).ok_or("VPN не подключён в режиме системного прокси")?;
        os::apply(HOST, port, self.pac_url.lock().as_deref())?;
        self.overwrite_reported.store(false, Ordering::SeqCst);
        Ok(())
    }

    pub fn status(&self) -> SysProxyStatus {
        let applied_port = *self.applied.lock();
        SysProxyStatus {
            applied_port,
            ours: applied_port.map(|p| os::matches_applied(HOST, p)).unwrap_or(false),
            current: os::describe(),
        }
    }

    /// For the watcher: `Some(current)` the first time we notice the proxy is no longer
    /// ours while applied; `None` otherwise.
    pub fn check_overwritten(&self) -> Option<String> {
        let port = (*self.applied.lock())?;
        if os::matches_applied(HOST, port) {
            self.overwrite_reported.store(false, Ordering::SeqCst);
            return None;
        }
        if self.overwrite_reported.swap(true, Ordering::SeqCst) {
            return None;
        }
        Some(os::describe())
    }
}

/// Convenience: the configured local proxy port.
pub fn configured_port(app: &AppHandle) -> u16 {
    app.state::<crate::settings::SettingsStore>().get().proxy_port
}

/// Keep the backup only when a restore was attempted and failed (retry later). A skipped
/// restore (another program owns the proxy now) must drop it, or the next connect would
/// reuse the stale snapshot and clobber that program's settings on disconnect.
fn may_delete_backup(attempted: bool, restored: bool) -> bool { restored || !attempted }

fn should_restore_backup(ours: bool, pending: bool) -> bool { ours || pending }

#[cfg(test)]
mod tests {
    #[test]
    fn backup_survives_failed_or_skipped_restore() {
        assert!(!super::may_delete_backup(true, false));
        assert!(super::may_delete_backup(true, true));
        assert!(super::may_delete_backup(false, false));
        assert!(super::should_restore_backup(false, true));
        assert!(super::should_restore_backup(true, false));
        assert!(!super::should_restore_backup(false, false));
    }
}
