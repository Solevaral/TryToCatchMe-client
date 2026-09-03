//! Profile storage: persistence + active-profile selection.
//!
//! Profiles are kept as JSON in the per-user app config dir. The active profile's
//! outbound is injected into the sing-box config by `core` on connect.

use std::fs;
use std::path::PathBuf;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use tauri::{AppHandle, Manager};

use crate::links::{self, Profile};

#[derive(Serialize, Deserialize, Default, Clone)]
struct Persisted {
    profiles: Vec<Profile>,
    active: Option<String>,
}

#[derive(Default)]
pub struct ProfileStore {
    inner: Mutex<Persisted>,
}

#[derive(Serialize, Clone)]
pub struct ImportResult {
    pub added: Vec<Profile>,
    pub errors: Vec<String>,
}

impl ProfileStore {
    fn file(app: &AppHandle) -> Result<PathBuf, String> {
        let dir = app
            .path()
            .app_config_dir()
            .map_err(|e| format!("no app config dir: {e}"))?;
        Ok(dir.join("profiles.json"))
    }

    /// Load profiles from disk (called once at startup).
    pub fn load(&self, app: &AppHandle) {
        if let Ok(path) = Self::file(app) {
            if let Ok(bytes) = fs::read(&path) {
                if let Ok(p) = serde_json::from_slice::<Persisted>(&bytes) {
                    *self.inner.lock() = p;
                }
            }
        }
    }

    fn save(&self, app: &AppHandle) -> Result<(), String> {
        let path = Self::file(app)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create dir: {e}"))?;
        }
        let data = serde_json::to_string_pretty(&*self.inner.lock())
            .map_err(|e| format!("serialize: {e}"))?;
        fs::write(&path, data).map_err(|e| format!("write: {e}"))
    }

    pub fn list(&self) -> Vec<Profile> {
        self.inner.lock().profiles.clone()
    }

    pub fn active_id(&self) -> Option<String> {
        self.inner.lock().active.clone()
    }

    /// Parse text (links or subscription) and add the resulting profiles.
    pub fn import(&self, app: &AppHandle, text: &str) -> ImportResult {
        let (parsed, errors) = links::parse_many(text);
        {
            let mut g = self.inner.lock();
            for p in &parsed {
                g.profiles.push(p.clone());
            }
            // Auto-select the first profile if none is active yet.
            if g.active.is_none() {
                if let Some(first) = g.profiles.first() {
                    g.active = Some(first.id.clone());
                }
            }
        }
        let _ = self.save(app);
        ImportResult {
            added: parsed,
            errors,
        }
    }

    pub fn remove(&self, app: &AppHandle, id: &str) {
        {
            let mut g = self.inner.lock();
            g.profiles.retain(|p| p.id != id);
            if g.active.as_deref() == Some(id) {
                g.active = g.profiles.first().map(|p| p.id.clone());
            }
        }
        let _ = self.save(app);
    }

    pub fn set_active(&self, app: &AppHandle, id: Option<String>) {
        self.inner.lock().active = id;
        let _ = self.save(app);
    }

    /// The id of the profile after the active one (wrapping). None if < 2 profiles.
    pub fn next_active_id(&self) -> Option<String> {
        let g = self.inner.lock();
        if g.profiles.len() < 2 {
            return None;
        }
        let idx = g
            .active
            .as_ref()
            .and_then(|a| g.profiles.iter().position(|p| &p.id == a))
            .unwrap_or(0);
        Some(g.profiles[(idx + 1) % g.profiles.len()].id.clone())
    }

    pub fn name_of(&self, id: &str) -> Option<String> {
        let g = self.inner.lock();
        g.profiles.iter().find(|p| p.id == id).map(|p| p.name.clone())
    }

    /// A specific profile's server host + port (for latency tests).
    pub fn endpoint_of(&self, id: &str) -> Option<(String, u16)> {
        let g = self.inner.lock();
        let p = g.profiles.iter().find(|p| p.id == id)?;
        Some((p.server.clone(), p.port))
    }

    /// The active profile's server host + port (for diagnostics).
    pub fn active_endpoint(&self) -> Option<(String, u16)> {
        let g = self.inner.lock();
        let active = g.active.as_ref()?;
        let p = g.profiles.iter().find(|p| &p.id == active)?;
        Some((p.server.clone(), p.port))
    }

    /// The active profile's outbound with `tag: "proxy"` set, ready for the config.
    pub fn active_outbound(&self) -> Option<Value> {
        let g = self.inner.lock();
        let active = g.active.as_ref()?;
        let p = g.profiles.iter().find(|p| &p.id == active)?;
        let mut ob = p.outbound.clone();
        ob["tag"] = Value::from("proxy");
        Some(ob)
    }
}
