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

use ttcm_core::routing::{build_route, geo_files, service_geo_file, GeoFile, GeoInput, RouteSpec, RoutingConfig, Service};

const DEFAULT_PRESETS: &str = include_str!("../../resources/service-presets.json");
const SERVICE_LIBRARY: &str = include_str!("../../resources/service-library.json");

/// The large read-only catalog users can pick services from — the built-in defaults
/// (so removed defaults like YouTube can be re-added) plus the extended library.
pub fn library() -> Vec<Service> {
    let mut out = default_catalog();
    let extra: Vec<Service> = serde_json::from_str(SERVICE_LIBRARY).unwrap_or_default();
    for s in extra {
        if !out.iter().any(|x| x.id == s.id) {
            out.push(s);
        }
    }
    out
}

/// Bump when built-in service domains change, so stored catalogs pick up additions.
const PRESETS_VERSION: u32 = 5;

#[derive(Serialize, Deserialize, Clone)]
struct Persisted {
    #[serde(default)]
    config: RoutingConfig,
    #[serde(default)]
    catalog: Vec<Service>,
    #[serde(default)]
    presets_version: u32,
}

/// v5: Gemini is no longer a separate service. Google decides the country for Gemini
/// from ALL its domains (accounts, www.google.com, googleapis), so Gemini on one server
/// and Google on another shows "not available in your country". Keeps the user's
/// custom Gemini domains and the server Gemini was pinned to.
fn merge_gemini_into_google(p: &mut Persisted) {
    let Some(gi) = p.catalog.iter().position(|s| s.id == "gemini") else {
        return;
    };
    let gemini = p.catalog.remove(gi);
    if !p.catalog.iter().any(|s| s.id == "google") {
        if let Some(b) = library().into_iter().find(|s| s.id == "google") {
            p.catalog.push(b);
        }
    }
    if let Some(google) = p.catalog.iter_mut().find(|s| s.id == "google") {
        if google.name == "Google" {
            google.name = "Google + Gemini".to_string();
        }
        for d in gemini.domains {
            let dn = d.trim().trim_start_matches('.').to_ascii_lowercase();
            let covered = google.domains.iter().any(|g| {
                let g = g.trim().trim_start_matches('.').to_ascii_lowercase();
                dn == g || dn.ends_with(&format!(".{g}"))
            });
            if !covered {
                google.domains.push(d);
            }
        }
    }
    let Some(si) = p.config.services.iter().position(|s| s.id == "gemini") else {
        return;
    };
    let mut gem = p.config.services.remove(si);
    match p.config.services.iter_mut().find(|s| s.id == "google") {
        Some(google) => {
            if gem.action == "proxy" {
                google.action = "proxy".to_string();
                if gem.profile.as_deref().is_some_and(|x| !x.is_empty()) {
                    google.profile = gem.profile;
                }
            }
        }
        None => {
            gem.id = "google".to_string();
            p.config.services.insert(si.min(p.config.services.len()), gem);
        }
    }
}

/// Bring a stored catalog up to date without discarding user edits: built-in services
/// gain any newly added domains/IPs, and enabled selections that point at services no
/// longer in the catalog are dropped. Returns true if anything changed.
fn migrate(p: &mut Persisted) -> bool {
    if p.presets_version >= PRESETS_VERSION {
        return false;
    }
    if p.presets_version < 5 {
        merge_gemini_into_google(p);
    }
    let builtin = library();
    for svc in p.catalog.iter_mut() {
        if let Some(b) = builtin.iter().find(|b| b.id == svc.id) {
            if svc.geosite.is_none() {
                svc.geosite = b.geosite.clone();
            }
            for d in &b.domains {
                if !svc.domains.contains(d) {
                    svc.domains.push(d.clone());
                }
            }
            for ip in &b.ip_cidrs {
                if !svc.ip_cidrs.contains(ip) {
                    svc.ip_cidrs.push(ip.clone());
                }
            }
        }
    }
    let ids: Vec<String> = p.catalog.iter().map(|s| s.id.clone()).collect();
    p.config.services.retain(|s| ids.contains(&s.id));
    p.presets_version = PRESETS_VERSION;
    true
}

/// Extra resources the routing needs (see `RoutingStore::plan`).
#[derive(Default, Clone)]
pub struct RoutePlan {
    pub region: Option<String>,
    /// Geosite lists backing enabled (non-direct) services, e.g. "google".
    pub service_geosites: Vec<String>,
    /// Profile ids that services are pinned to.
    pub pinned_profiles: Vec<String>,
}

impl RoutePlan {
    pub fn region_files(&self) -> Vec<GeoFile> {
        self.region.as_deref().map(|r| geo_files(r).to_vec()).unwrap_or_default()
    }

    /// Every geo file the routing needs.
    pub fn files(&self) -> Vec<GeoFile> {
        let mut files = self.region_files();
        files.extend(self.service_geosites.iter().map(|n| service_geo_file(n)));
        files
    }
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
            presets_version: PRESETS_VERSION,
        });
        if p.catalog.is_empty() {
            p.catalog = default_catalog();
        }
        let changed = migrate(&mut p);
        *self.inner.lock() = Some(p);
        if changed {
            let _ = self.save(app);
        }
    }

    fn with<R>(&self, f: impl FnOnce(&mut Persisted) -> R) -> R {
        let mut g = self.inner.lock();
        let p = g.get_or_insert_with(|| Persisted {
            config: RoutingConfig::default(),
            catalog: default_catalog(),
            presets_version: PRESETS_VERSION,
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

    /// Materialize route rules. `geo` = which downloaded lists exist (missing ones are
    /// left out).
    pub fn route_spec(&self, geo: Option<&GeoInput>) -> RouteSpec {
        self.with(|p| build_route(&p.config, &p.catalog, geo))
    }

    /// What the current routing needs beyond the active profile: geo lists to download
    /// and profiles that some services are pinned to (rule mode only).
    pub fn plan(&self) -> RoutePlan {
        self.with(|p| {
            if p.config.mode != "rule" {
                return RoutePlan::default();
            }
            let mut plan = RoutePlan {
                region: p.config.region.clone().filter(|r| !r.is_empty()),
                ..Default::default()
            };
            for sel in &p.config.services {
                let Some(svc) = p.catalog.iter().find(|s| s.id == sel.id) else { continue };
                if let Some(g) = &svc.geosite {
                    if sel.action != "direct" && !plan.service_geosites.contains(g) {
                        plan.service_geosites.push(g.clone());
                    }
                }
                if let Some(pid) = sel.profile.as_ref().filter(|pid| !pid.is_empty()) {
                    if sel.action == "proxy" && !plan.pinned_profiles.contains(pid) {
                        plan.pinned_profiles.push(pid.clone());
                    }
                }
            }
            plan
        })
    }

}
