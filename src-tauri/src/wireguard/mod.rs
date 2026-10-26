//! Built-in WireGuard tunnels: the `wireguard.json` store and the Tauri commands.
//!
//! The tunnel itself runs inside sing-box (see `ttcm_core::wireguard`); this module only
//! keeps the tunnels and tells the core which one is active. Private keys are stored in
//! the app's config dir (user-only on Windows by the profile's ACL, 0600 on Linux) —
//! the project has no OS keychain integration yet, and the core needs the key in its
//! config.json anyway while connected.

use std::fs;
use std::path::PathBuf;

use parking_lot::Mutex;
use serde::Serialize;
use tauri::{AppHandle, Manager, State};
use ttcm_core::wireguard::{self as wg, Migration, WgStore, WgTunnel};

use crate::core::CoreState;
use crate::settings::SettingsStore;

#[derive(Default)]
pub struct WgState {
    inner: Mutex<WgStore>,
    /// The tunnel the running core was started with (`None`: no tunnel in the config).
    applied: Mutex<Option<String>>,
}

impl WgState {
    fn file(app: &AppHandle) -> Result<PathBuf, String> {
        let dir = app
            .path()
            .app_config_dir()
            .map_err(|e| format!("no app config dir: {e}"))?;
        Ok(dir.join("wireguard.json"))
    }

    pub fn load(&self, app: &AppHandle) {
        if let Ok(path) = Self::file(app) {
            if let Ok(bytes) = fs::read(&path) {
                if let Ok(s) = serde_json::from_slice::<WgStore>(&bytes) {
                    *self.inner.lock() = s;
                }
            }
        }
    }

    fn save(&self, app: &AppHandle) -> Result<(), String> {
        let path = Self::file(app)?;
        if let Some(parent) = path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let json = serde_json::to_string_pretty(&*self.inner.lock()).map_err(|e| e.to_string())?;
        fs::write(&path, json).map_err(|e| format!("не удалось сохранить wireguard.json: {e}"))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    pub fn get(&self) -> WgStore {
        self.inner.lock().clone()
    }

    pub fn active(&self) -> Option<WgTunnel> {
        self.inner.lock().active_tunnel().cloned()
    }

    /// Called by the core on start/stop: which tunnel (if any) it runs with.
    pub fn set_applied(&self, id: Option<String>) {
        *self.applied.lock() = id;
    }

    fn with<R>(&self, app: &AppHandle, f: impl FnOnce(&mut WgStore) -> Result<R, String>) -> Result<R, String> {
        let r = f(&mut self.inner.lock())?;
        self.save(app)?;
        Ok(r)
    }
}

/// The offer to move from the old "direct traffic through an interface" options.
pub fn migration_offer(app: &AppHandle) -> Option<Migration> {
    let s = app.state::<SettingsStore>().get();
    let legacy = wg::LegacyOptions {
        direct_interface: s.direct_interface,
        proxy_via_direct_interface: s.proxy_via_direct_interface,
        tun_bypass_addresses: s.tun_bypass_addresses,
    };
    wg::migration_offer(&legacy, !app.state::<WgState>().get().tunnels.is_empty())
}

// ---- commands ----

#[tauri::command]
pub fn wg_list(state: State<'_, WgState>) -> WgStore {
    state.get()
}

/// Import a `.conf` (pasted text or file contents) as a new tunnel.
#[tauri::command]
pub fn wg_import(app: AppHandle, state: State<'_, WgState>, text: String, name: String) -> Result<WgTunnel, String> {
    let (interface, peers) = wg::parse_conf(&text)?;
    state.with(&app, |s| {
        let base = wg::name_from_file(&name);
        let base = if base.is_empty() { "WireGuard".to_string() } else { base };
        // A free name: "home", "home (2)", …
        let mut candidate = base.clone();
        let mut n = 2;
        while wg::validate_name(&candidate, &s.tunnels, None).is_err() {
            candidate = format!("{base} ({n})");
            n += 1;
            if n > 1000 {
                return Err("не удалось подобрать имя туннеля".into());
            }
        }
        let t = WgTunnel { id: uuid::Uuid::new_v4().to_string(), name: candidate, interface, peers };
        s.tunnels.push(t.clone());
        Ok(t)
    })
}

/// Save an edited tunnel (structured fields from the form).
#[tauri::command]
pub fn wg_update(app: AppHandle, state: State<'_, WgState>, tunnel: WgTunnel) -> Result<(), String> {
    wg::validate(&tunnel.interface, &tunnel.peers)?;
    state.with(&app, |s| {
        let name = wg::validate_name(&tunnel.name, &s.tunnels, Some(&tunnel.id))?;
        let slot = s.tunnels.iter_mut().find(|t| t.id == tunnel.id).ok_or("туннель не найден")?;
        *slot = WgTunnel { name, ..tunnel };
        Ok(())
    })
}

/// Replace a tunnel's settings with an edited `.conf` text (name and id are kept).
#[tauri::command]
pub fn wg_update_conf(app: AppHandle, state: State<'_, WgState>, id: String, text: String) -> Result<WgTunnel, String> {
    let (interface, peers) = wg::parse_conf(&text)?;
    state.with(&app, |s| {
        let slot = s.tunnels.iter_mut().find(|t| t.id == id).ok_or("туннель не найден")?;
        slot.interface = interface;
        slot.peers = peers;
        Ok(slot.clone())
    })
}

#[tauri::command]
pub fn wg_export(state: State<'_, WgState>, id: String) -> Result<String, String> {
    let s = state.get();
    let t = s.tunnels.iter().find(|t| t.id == id).ok_or("туннель не найден")?;
    Ok(wg::to_conf(&t.interface, &t.peers))
}

#[tauri::command]
pub fn wg_remove(app: AppHandle, state: State<'_, WgState>, id: String) -> Result<(), String> {
    state.with(&app, |s| {
        s.tunnels.retain(|t| t.id != id);
        if s.active.as_deref() == Some(id.as_str()) {
            s.active = None;
        }
        Ok(())
    })
}

/// Choose the active tunnel (`None` = built-in WireGuard off). Takes effect on the next
/// connect; the UI restarts the core right away when it's running.
#[tauri::command]
pub fn wg_set_active(app: AppHandle, state: State<'_, WgState>, id: Option<String>) -> Result<(), String> {
    state.with(&app, |s| {
        if let Some(id) = &id {
            if !s.tunnels.iter().any(|t| &t.id == id) {
                return Err("туннель не найден".into());
            }
        }
        s.active = id;
        Ok(())
    })
}

#[derive(Serialize)]
pub struct WgStatus {
    /// The tunnel the running core uses (None: the core is off or runs without one).
    pub running: Option<String>,
    /// Its server, as configured.
    pub endpoint: Option<String>,
    /// Open connections through the tunnel and their traffic so far (sing-box exposes
    /// per-connection counters only — no handshake time, no interface totals).
    pub connections: u64,
    pub upload: u64,
    pub download: u64,
}

#[tauri::command]
pub async fn wg_status(app: AppHandle) -> WgStatus {
    let core_running = app.state::<CoreState>().status().running;
    let state = app.state::<WgState>();
    let running = if core_running { state.applied.lock().clone() } else { None };
    let endpoint = running.as_ref().and_then(|id| {
        let s = state.get();
        let t = s.tunnels.iter().find(|t| &t.id == id)?;
        t.peers.iter().find_map(|p| p.endpoint.clone())
    });
    let (mut connections, mut upload, mut download) = (0, 0, 0);
    if running.is_some() {
        let body = tauri::async_runtime::spawn_blocking(|| crate::diag::clash_get("/connections", 2000))
            .await
            .ok()
            .flatten();
        if let Some(v) = body.and_then(|b| serde_json::from_str::<serde_json::Value>(&b).ok()) {
            for c in v["connections"].as_array().into_iter().flatten() {
                let through = c["chains"].as_array().is_some_and(|ch| ch.iter().any(|t| t == wg::WG_TAG));
                if through {
                    connections += 1;
                    upload += c["upload"].as_u64().unwrap_or(0);
                    download += c["download"].as_u64().unwrap_or(0);
                }
            }
        }
    }
    WgStatus { running, endpoint, connections, upload, download }
}

/// Round-trip time of a request through the tunnel (proves the handshake works).
#[tauri::command]
pub async fn wg_check(app: AppHandle) -> Result<u64, String> {
    if app.state::<WgState>().applied.lock().is_none() || !app.state::<CoreState>().status().running {
        return Err("туннель не подключён".into());
    }
    tauri::async_runtime::spawn_blocking(|| {
        crate::diag::clash_delay_via(wg::WG_TAG, "http://www.gstatic.com/generate_204", 5000)
    })
    .await
    .ok()
    .flatten()
    .ok_or_else(|| "нет ответа через туннель (сервер недоступен, неверные ключи или Endpoint)".into())
}

#[tauri::command]
pub fn wg_migration_offer(app: AppHandle) -> Option<Migration> {
    migration_offer(&app)
}

/// Accept the migration: the built-in tunnel takes over from the old interface options.
#[tauri::command]
pub fn wg_migrate(app: AppHandle, store: State<'_, SettingsStore>) -> Result<(), String> {
    let m = migration_offer(&app).ok_or("нечего переносить")?;
    let mut s = store.get();
    s.wg_direct_via_tunnel = m.direct_via_tunnel;
    s.wg_vpn_over_tunnel = m.vpn_over_tunnel;
    for e in m.provider_list {
        if !s.provider_list.contains(&e) {
            s.provider_list.push(e);
        }
    }
    s.direct_interface = None;
    s.proxy_via_direct_interface = false;
    store.set(&app, s);
    Ok(())
}
