//! Routing store: persists the routing config + editable service catalog.
//!
//! The service catalog is seeded from a bundled preset list and then editable by the
//! user (add/remove addresses, custom services, reset-to-default). The routing config
//! (mode, rules, enabled services, region) is translated to sing-box route rules by
//! `ttcm_core::routing` on connect.

use std::fs;
use std::path::PathBuf;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

use ttcm_core::routing::{build_route, RouteSpec, RoutingConfig, Service};

const DEFAULT_PRESETS: &str = include_str!("../../resources/service-presets.json");
const SERVICE_LIBRARY: &str = include_str!("../../resources/service-library.json");

/// The large read-only catalog users can pick services from.
pub fn library() -> Vec<Service> {
    serde_json::from_str(SERVICE_LIBRARY).unwrap_or_default()
}

#[derive(Serialize, Deserialize, Clone)]
struct Persisted {
    #[serde(default)]
    config: RoutingConfig,
    #[serde(default)]
    catalog: Vec<Service>,
}

#[derive(Default)]
pub struct RoutingStore {
    inner: Mutex<Option<Persisted>>,
}

/// Snapshot returned to the UI.
#[derive(Serialize, Clone)]
pub struct RoutingSnapshot {
    pub config: RoutingConfig,
    pub catalog: Vec<Service>,
}

fn default_catalog() -> Vec<Service> {
    serde_json::from_str(DEFAULT_PRESETS).unwrap_or_default()
}

impl RoutingStore {
    fn file(app: &AppHandle) -> Result<PathBuf, String> {
        let dir = app
            .path()
            .app_config_dir()
            .map_err(|e| format!("no app config dir: {e}"))?;
        Ok(dir.join("routing.json"))
    }

    pub fn load(&self, app: &AppHandle) {
        let mut data = None;
        if let Ok(path) = Self::file(app) {
            if let Ok(bytes) = fs::read(&path) {
                if let Ok(p) = serde_json::from_slice::<Persisted>(&bytes) {
                    data = Some(p);
                }
            }
        }
        let mut p = data.unwrap_or_else(|| Persisted {
            config: RoutingConfig::default(),
            catalog: Vec::new(),
        });
        if p.catalog.is_empty() {
            p.catalog = default_catalog();
        }
        *self.inner.lock() = Some(p);
    }

    fn with<R>(&self, f: impl FnOnce(&mut Persisted) -> R) -> R {
        let mut g = self.inner.lock();
        let p = g.get_or_insert_with(|| Persisted {
            config: RoutingConfig::default(),
            catalog: default_catalog(),
        });
        f(p)
    }

    fn save(&self, app: &AppHandle) -> Result<(), String> {
        let path = Self::file(app)?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| format!("create dir: {e}"))?;
        }
        let json = {
            let g = self.inner.lock();
            serde_json::to_string_pretty(&*g).map_err(|e| format!("serialize: {e}"))?
        };
        fs::write(&path, json).map_err(|e| format!("write: {e}"))
    }

    pub fn snapshot(&self) -> RoutingSnapshot {
        self.with(|p| RoutingSnapshot {
            config: p.config.clone(),
            catalog: p.catalog.clone(),
        })
    }

    pub fn set_config(&self, app: &AppHandle, config: RoutingConfig) {
        self.with(|p| p.config = config);
        let _ = self.save(app);
    }

    pub fn upsert_service(&self, app: &AppHandle, svc: Service) {
        self.with(|p| {
            if let Some(existing) = p.catalog.iter_mut().find(|s| s.id == svc.id) {
                *existing = svc;
            } else {
                p.catalog.push(svc);
            }
        });
        let _ = self.save(app);
    }

    pub fn remove_service(&self, app: &AppHandle, id: &str) {
        self.with(|p| {
            p.catalog.retain(|s| s.id != id);
            p.config.services.retain(|s| s.id != id);
        });
        let _ = self.save(app);
    }

    pub fn reset_services(&self, app: &AppHandle) {
        self.with(|p| p.catalog = default_catalog());
        let _ = self.save(app);
    }

    /// Materialize the sing-box route pieces for the current config + catalog.
    pub fn route_spec(&self) -> RouteSpec {
        self.with(|p| build_route(&p.config, &p.catalog))
    }
}
