//! The app owns the OS system proxy (never sing-box).
//!
//! On connect we snapshot the user's settings, persist that snapshot to disk and point
//! the system proxy at our local port. On disconnect we put the snapshot back — but only
//! if the proxy still points at us, so another app's settings (e.g. Hiddify) are never
//! clobbered. The on-disk backup lets the next launch clean up after a crash or a kill.

pub mod os;

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
}

#[derive(Default)]
pub struct SysProxyState {
    /// Port we pointed the system proxy at, while applied.
    applied: Mutex<Option<u16>>,
    /// Set once we've warned about an overwrite, until the proxy is ours again.
    overwrite_reported: AtomicBool,
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
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let json = serde_json::to_string_pretty(backup).map_err(|e| e.to_string())?;
    fs::write(path, json).map_err(|e| format!("не удалось сохранить резервную копию прокси: {e}"))
}

fn delete_backup(app: &AppHandle) {
    if let Some(p) = backup_path(app) {
        let _ = fs::remove_file(p);
    }
}

impl SysProxyState {
    /// Point the system proxy at `127.0.0.1:port`, remembering the previous settings.
    pub fn apply(&self, app: &AppHandle, port: u16) -> Result<(), String> {
        // Reuse a leftover backup (previous crash): the live settings are then OUR stale
        // proxy, and restoring them would keep the machine pointed at a dead port.
        let snapshot = match read_backup(app) {
            Some(b) => b.snapshot,
            None if os::points_to(HOST, port) => os::disabled(),
            None => os::snapshot()?,
        };
        write_backup(app, &Backup { port, snapshot })?;
        os::apply(HOST, port)?;
        *self.applied.lock() = Some(port);
        self.overwrite_reported.store(false, Ordering::SeqCst);
        Ok(())
    }

    /// Put the user's previous settings back (if the proxy still points at us).
    /// Returns a message for the log when something was restored or skipped.
    pub fn release(&self, app: &AppHandle) -> Option<String> {
        let port = self.applied.lock().take()?;
        let backup = read_backup(app);
        let msg = if os::points_to(HOST, port) {
            let snap = backup.map(|b| b.snapshot).unwrap_or_else(os::disabled);
            match os::restore(&snap) {
                Ok(()) => "Системный прокси возвращён к прежним настройкам".to_string(),
                Err(e) => format!("Не удалось вернуть системный прокси: {e}. Отключите прокси вручную в настройках системы."),
            }
        } else {
            "Системный прокси уже изменён другой программой — не трогаю его".to_string()
        };
        delete_backup(app);
        Some(msg)
    }

    /// On startup: clean up after a crash/kill that left the proxy pointing at us.
    pub fn recover(&self, app: &AppHandle, configured_port: u16) -> Option<String> {
        match read_backup(app) {
            Some(b) => {
                let msg = if os::points_to(HOST, b.port) {
                    match os::restore(&b.snapshot) {
                        Ok(()) => Some("Приложение в прошлый раз завершилось аварийно — системный прокси возвращён к прежним настройкам".to_string()),
                        Err(e) => Some(format!("Не удалось вернуть системный прокси после аварийного завершения: {e}")),
                    }
                } else {
                    None
                };
                delete_backup(app);
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
        os::apply(HOST, port)?;
        self.overwrite_reported.store(false, Ordering::SeqCst);
        Ok(())
    }

    pub fn status(&self) -> SysProxyStatus {
        let applied_port = *self.applied.lock();
        SysProxyStatus {
            applied_port,
            ours: applied_port.map(|p| os::points_to(HOST, p)).unwrap_or(false),
            current: os::describe(),
        }
    }

    /// For the watcher: `Some(current)` the first time we notice the proxy is no longer
    /// ours while applied; `None` otherwise.
    pub fn check_overwritten(&self) -> Option<String> {
        let port = (*self.applied.lock())?;
        if os::points_to(HOST, port) {
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
