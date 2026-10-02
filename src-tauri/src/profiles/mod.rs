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
use crate::subscription::Fetched;
use ttcm_core::subscription::{self as sub, SubInfo};

#[derive(Serialize, Deserialize, Default, Clone)]
struct Persisted {
    profiles: Vec<Profile>,
    active: Option<String>,
    #[serde(default)]
    subscriptions: Vec<Subscription>,
}

/// A subscription URL whose servers are kept in sync with the provider's list.
#[derive(Serialize, Deserialize, Clone)]
pub struct Subscription {
    pub id: String,
    pub url: String,
    pub name: String,
    #[serde(default)]
    pub info: Option<SubInfo>,
    /// Unix seconds of the last successful update.
    #[serde(default)]
    pub updated_at: u64,
}

#[derive(Default)]
pub struct ProfileStore {
    inner: Mutex<Persisted>,
}

#[derive(Serialize, Clone)]
pub struct ImportResult {
    pub added: Vec<Profile>,
    pub errors: Vec<String>,
    /// The active profile's server changed or vanished — reconnect to apply.
    pub active_changed: bool,
}

impl ImportResult {
    pub fn error(e: String) -> Self {
        ImportResult { added: Vec::new(), errors: vec![e], active_changed: false }
    }
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

    /// The active profile's display name (no server details), for the host tile.
    pub fn active_name(&self) -> Option<String> {
        let g = self.inner.lock();
        let active = g.active.as_ref()?;
        g.profiles.iter().find(|p| &p.id == active).map(|p| p.name.clone())
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
            active_changed: false,
        }
    }

    pub fn subscriptions(&self) -> Vec<Subscription> {
        self.inner.lock().subscriptions.clone()
    }

    pub fn subscription_url(&self, id: &str) -> Option<String> {
        let g = self.inner.lock();
        g.subscriptions.iter().find(|s| s.id == id).map(|s| s.url.clone())
    }

    /// Add a downloaded subscription, or replace its servers if this URL is already
    /// added. Servers that are still in the list keep their profile id (so the active
    /// profile and services pinned to it survive the update). A download with no
    /// usable servers leaves the old ones in place.
    pub fn apply_subscription(&self, app: &AppHandle, url: &str, fetched: Fetched, auto_switch: bool) -> ImportResult {
        let (mut parsed, mut errors) = sub::parse_body(&fetched.body);
        if parsed.is_empty() {
            if errors.is_empty() {
                errors.push("в подписке нет ссылок подключения".into());
            }
            return ImportResult { added: Vec::new(), errors, active_changed: false };
        }

        let active_changed;
        {
            let mut g = self.inner.lock();
            let sub_id = match g.subscriptions.iter_mut().find(|s| s.url == url) {
                Some(s) => {
                    s.name = fetched.title;
                    s.info = fetched.info;
                    s.updated_at = now();
                    s.id.clone()
                }
                None => {
                    let s = Subscription {
                        id: uuid::Uuid::new_v4().to_string(),
                        url: url.to_string(),
                        name: fetched.title,
                        info: fetched.info,
                        updated_at: now(),
                    };
                    let id = s.id.clone();
                    g.subscriptions.push(s);
                    id
                }
            };

            let mut old: Vec<Profile> = g
                .profiles
                .iter()
                .filter(|p| p.subscription.as_deref() == Some(sub_id.as_str()))
                .cloned()
                .collect();
            for p in &mut parsed {
                p.subscription = Some(sub_id.clone());
                // Same link first, then same name (the key/params may have rotated).
                let reuse = old
                    .iter()
                    .position(|o| o.link.is_some() && o.link == p.link)
                    .or_else(|| old.iter().position(|o| o.name == p.name));
                if let Some(i) = reuse {
                    p.id = old.remove(i).id;
                }
            }

            let active_before = g
                .active
                .as_ref()
                .and_then(|a| g.profiles.iter().find(|p| &p.id == a))
                .map(|p| (p.outbound.clone(), p.name.clone()));
            // New servers take the place of the old ones in the list.
            let pos = g
                .profiles
                .iter()
                .position(|p| p.subscription.as_deref() == Some(sub_id.as_str()))
                .unwrap_or(g.profiles.len());
            g.profiles.retain(|p| p.subscription.as_deref() != Some(sub_id.as_str()));
            let pos = pos.min(g.profiles.len());
            g.profiles.splice(pos..pos, parsed.iter().cloned());

            let active_now = g.active.as_ref().and_then(|a| g.profiles.iter().find(|p| &p.id == a));
            active_changed = match (&active_before, active_now) {
                // Тот же сервер с новыми параметрами — переподключение применит их.
                (Some((before, _)), Some(now)) => before != &now.outbound,
                // Сервер пропал: переключение на другой — только с автопереключением
                // (экспериментальная функция). Иначе туннель работает со старыми
                // параметрами, пока пользователь не выберет сервер сам.
                (Some(_), None) => auto_switch,
                (None, _) => false,
            };
            if active_now.is_none() {
                if auto_switch || active_before.is_none() {
                    g.active = g.profiles.first().map(|p| p.id.clone());
                } else if let Some((_, name)) = &active_before {
                    g.active = None;
                    errors.push(format!("сервер «{name}», выбранный для подключения, пропал из подписки — выберите другой сервер"));
                }
            }
        }
        let _ = self.save(app);
        ImportResult { added: parsed, errors, active_changed }
    }

    /// Remove a subscription together with its servers.
    pub fn remove_subscription(&self, app: &AppHandle, id: &str) {
        {
            let mut g = self.inner.lock();
            g.subscriptions.retain(|s| s.id != id);
            g.profiles.retain(|p| p.subscription.as_deref() != Some(id));
            let active_ok = g.active.as_ref().is_some_and(|a| g.profiles.iter().any(|p| &p.id == a));
            if !active_ok {
                g.active = g.profiles.first().map(|p| p.id.clone());
            }
        }
        let _ = self.save(app);
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

    /// Human-readable one-liner for the active profile (no secrets), for the log.
    pub fn active_summary(&self) -> Option<String> {
        let g = self.inner.lock();
        let active = g.active.as_ref()?;
        let p = g.profiles.iter().find(|p| &p.id == active)?;
        let transport = p.outbound["transport"]["type"].as_str().unwrap_or("tcp");
        let security = if p.outbound["tls"]["reality"]["enabled"] == true {
            "reality"
        } else if p.outbound["tls"]["enabled"] == true {
            "tls"
        } else {
            "без TLS"
        };
        Some(format!(
            "«{}» — {} {}:{} ({}, {})",
            p.name, p.protocol, p.server, p.port, transport, security
        ))
    }

    /// The active profile's server host + port (for diagnostics).
    pub fn active_endpoint(&self) -> Option<(String, u16)> {
        let g = self.inner.lock();
        let active = g.active.as_ref()?;
        let p = g.profiles.iter().find(|p| &p.id == active)?;
        Some((p.server.clone(), p.port))
    }

    /// A specific profile's outbound with the given tag (for services pinned to it).
    pub fn outbound_of(&self, id: &str, tag: &str) -> Option<Value> {
        let g = self.inner.lock();
        let p = g.profiles.iter().find(|p| p.id == id)?;
        let mut ob = p.outbound.clone();
        ob["tag"] = Value::from(tag);
        Some(ob)
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

fn now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}
