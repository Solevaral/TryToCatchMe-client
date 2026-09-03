//! Persisted application settings (security toggles, auto-failover).

use std::fs;
use std::path::PathBuf;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

fn default_true() -> bool {
    true
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Settings {
    /// DNS-over-HTTPS through the tunnel (anti-leak).
    #[serde(default = "default_true")]
    pub dns_doh: bool,
    /// Block QUIC / UDP:443.
    #[serde(default)]
    pub block_quic: bool,
    /// Auto-switch to the next profile when the active one fails.
    #[serde(default)]
    pub auto_switch: bool,
    /// TUN capture mode (all system traffic via a virtual adapter; needs admin).
    #[serde(default)]
    pub capture_tun: bool,
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            dns_doh: true,
            block_quic: false,
            auto_switch: false,
            capture_tun: false,
        }
    }
}

#[derive(Default)]
pub struct SettingsStore {
    inner: Mutex<Settings>,
}

impl SettingsStore {
    fn file(app: &AppHandle) -> Result<PathBuf, String> {
        let dir = app
            .path()
            .app_config_dir()
            .map_err(|e| format!("no app config dir: {e}"))?;
        Ok(dir.join("settings.json"))
    }

    pub fn load(&self, app: &AppHandle) {
        if let Ok(path) = Self::file(app) {
            if let Ok(bytes) = fs::read(&path) {
                if let Ok(s) = serde_json::from_slice::<Settings>(&bytes) {
                    *self.inner.lock() = s;
                }
            }
        }
    }

    pub fn get(&self) -> Settings {
        self.inner.lock().clone()
    }

    pub fn set(&self, app: &AppHandle, s: Settings) {
        *self.inner.lock() = s;
        if let Ok(path) = Self::file(app) {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(&*self.inner.lock()) {
                let _ = fs::write(&path, json);
            }
        }
    }
}
