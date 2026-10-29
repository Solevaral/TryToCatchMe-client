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

use ttcm_core::routing::{antifilter_files, build_route, geo_files, service_geo_file, GeoFile, GeoInput, RouteSpec, RoutingConfig, Service};

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

/// The library with the copy downloaded from GitHub on top: its entries replace
/// built-in ones with the same id, new ones are appended (see `crate::library`).
pub fn library_with_updates(app: &AppHandle) -> Vec<Service> {
    let mut out = library();
    for s in crate::library::cached(app) {
        match out.iter_mut().find(|x| x.id == s.id) {
            Some(existing) => *existing = s,
            None => out.push(s),
        }
    }
    out
}

/// Bump when built-in service domains change, so stored catalogs pick up additions.
const PRESETS_VERSION: u32 = 7;

#[derive(Serialize, Deserialize, Clone)]
struct Persisted {
    #[serde(default)]
    config: RoutingConfig,
    #[serde(default)]
    catalog: Vec<Service>,
    #[serde(default)]
    presets_version: u32,
    /// Library services as last synced from GitHub: tells the maintainer's changes
    /// apart from the user's own edits on the next sync (see `sync_service`).
    #[serde(default)]
    library_base: Vec<Service>,
}

/// What a sync with the downloaded library changed in the user's services.
#[derive(Default, Debug, PartialEq)]
pub struct SyncReport {
    pub updated: Vec<String>,
    pub removed: Vec<String>,
}

/// Three-way merge of a list: the library's new version, minus what the user removed,
/// plus what the user added since `base`.
fn merge_list(base: &[String], cur: &[String], new: &[String]) -> Vec<String> {
    let mut out: Vec<String> = new
        .iter()
        .filter(|x| cur.contains(x) || !base.contains(x))
        .cloned()
        .collect();
    for x in cur {
        if !base.contains(x) && !out.contains(x) {
            out.push(x.clone());
        }
    }
    out
}

/// A field the user changed keeps the user's value, otherwise it follows the library.
fn merge_field<T: PartialEq + Clone>(base: &T, cur: &T, new: &T) -> T {
    if cur == base { new.clone() } else { cur.clone() }
}

/// Apply the library's version of a service on top of the user's copy.
fn sync_service(base: &Service, cur: &Service, new: &Service) -> Service {
    Service {
        id: cur.id.clone(),
        name: merge_field(&base.name, &cur.name, &new.name),
        icon: merge_field(&base.icon, &cur.icon, &new.icon),
        domains: merge_list(&base.domains, &cur.domains, &new.domains),
        ip_cidrs: merge_list(&base.ip_cidrs, &cur.ip_cidrs, &new.ip_cidrs),
        geosite: merge_field(&base.geosite, &cur.geosite, &new.geosite),
    }
}

/// Bring the user's services in line with the library downloaded from GitHub:
/// services from it get its changes (user edits stay), services the library no longer
/// has are removed. The user's own services and built-in ones the library doesn't
/// list are left alone.
fn sync_with_library(p: &mut Persisted, remote: &[Service]) -> SyncReport {
    let builtin = library();
    let bundled: Vec<Service> = serde_json::from_str(SERVICE_LIBRARY).unwrap_or_default();
    let mut report = SyncReport::default();
    for svc in p.catalog.iter_mut() {
        let Some(new) = remote.iter().find(|r| r.id == svc.id) else { continue };
        let base = p
            .library_base
            .iter()
            .chain(builtin.iter())
            .find(|b| b.id == svc.id)
            .cloned()
            .unwrap_or_else(|| svc.clone());
        let merged = sync_service(&base, svc, new);
        if merged != *svc {
            report.updated.push(merged.name.clone());
            *svc = merged;
        }
    }
    let gone: Vec<String> = p
        .catalog
        .iter()
        .filter(|s| !remote.iter().any(|r| r.id == s.id))
        .filter(|s| p.library_base.iter().chain(bundled.iter()).any(|b| b.id == s.id))
        .map(|s| s.id.clone())
        .collect();
    for id in &gone {
        if let Some(s) = p.catalog.iter().find(|s| &s.id == id) {
            report.removed.push(s.name.clone());
        }
    }
    p.catalog.retain(|s| !gone.contains(&s.id));
    p.config.services.retain(|s| !gone.contains(&s.id));
    p.library_base = remote
        .iter()
        .filter(|r| p.catalog.iter().any(|s| s.id == r.id))
        .cloned()
        .collect();
    report
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

/// v6: Steam is no longer a built-in service (it isn't blocked anywhere yet). Removed from
/// stored catalogs unless the user routes it; it can be re-added from the library later.
fn drop_unused_steam(p: &mut Persisted) {
    if !p.config.services.iter().any(|s| s.id == "steam") {
        p.catalog.retain(|s| s.id != "steam");
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
    if p.presets_version < 6 {
        drop_unused_steam(p);
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
    /// Antifilter mode with the lists on.
    pub antifilter: bool,
}

impl RoutePlan {
    pub fn region_files(&self) -> Vec<GeoFile> {
        self.region.as_deref().map(|r| geo_files(r).to_vec()).unwrap_or_default()
    }

    /// Every geo file the routing needs.
    pub fn files(&self) -> Vec<GeoFile> {
        let mut files = self.region_files();
        files.extend(self.service_geosites.iter().map(|n| service_geo_file(n)));
        if self.antifilter {
            files.extend(antifilter_files());
        }
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
            library_base: Vec::new(),
        });
        if p.catalog.is_empty() {
            p.catalog = default_catalog();
        }
        let changed = migrate(&mut p) | p.config.migrate_antifilter_mode();
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
            library_base: Vec::new(),
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
                antifilter: p.config.antifilter,
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

    /// Apply the library downloaded from GitHub to the user's services (see
    /// `sync_with_library`). Saved only when something changed.
    pub fn sync_library(&self, app: &AppHandle, remote: &[Service]) -> SyncReport {
        let (report, changed) = self.with(|p| {
            let before = p.library_base.clone();
            let report = sync_with_library(p, remote);
            let changed = !report.updated.is_empty() || !report.removed.is_empty() || before != p.library_base;
            (report, changed)
        });
        if changed {
            let _ = self.save(app);
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn svc(id: &str, name: &str, domains: &[&str]) -> Service {
        Service {
            id: id.into(),
            name: name.into(),
            icon: "🎵".into(),
            domains: domains.iter().map(|d| d.to_string()).collect(),
            ip_cidrs: Vec::new(),
            geosite: None,
        }
    }

    fn persisted(catalog: Vec<Service>, base: Vec<Service>) -> Persisted {
        let mut config = RoutingConfig::default();
        config.services = catalog
            .iter()
            .map(|s| ttcm_core::routing::ServiceSel { id: s.id.clone(), action: "proxy".into(), profile: None })
            .collect();
        Persisted { config, catalog, presets_version: PRESETS_VERSION, library_base: base }
    }

    #[test]
    fn library_changes_apply_and_user_edits_stay() {
        let base = svc("tiktok", "TikTok", &["tiktok.com", "old.com", "user-removed.com"]);
        let cur = svc("tiktok", "TikTok", &["tiktok.com", "user-removed.com", "mine.com"]);
        let cur = Service { domains: cur.domains.into_iter().filter(|d| d != "user-removed.com").collect(), ..cur };
        let new = svc("tiktok", "TikTok!", &["tiktok.com", "ttwstatic.com", "user-removed.com"]);
        let mut p = persisted(vec![cur], vec![base]);
        let r = sync_with_library(&mut p, &[new.clone()]);
        assert_eq!(r.updated, vec!["TikTok!".to_string()]);
        assert_eq!(p.catalog[0].domains, vec!["tiktok.com", "ttwstatic.com", "mine.com"]);
        assert_eq!(p.library_base, vec![new]);
    }

    #[test]
    fn removed_library_services_go_custom_ones_stay() {
        let lib = svc("dropped", "Dropped", &["a.com"]);
        let custom = svc("custom-1", "Мой", &["b.com"]);
        let builtin = svc("youtube", "YouTube", &["youtube.com"]);
        let mut p = persisted(vec![lib.clone(), custom, builtin], vec![lib]);
        let r = sync_with_library(&mut p, &[svc("other", "Other", &["c.com"])]);
        assert_eq!(r.removed, vec!["Dropped".to_string()]);
        let ids: Vec<_> = p.catalog.iter().map(|s| s.id.as_str()).collect();
        assert_eq!(ids, vec!["custom-1", "youtube"]);
        assert!(!p.config.services.iter().any(|s| s.id == "dropped"));
    }

    #[test]
    fn unchanged_library_is_a_no_op() {
        let s = svc("tiktok", "TikTok", &["tiktok.com"]);
        let mut p = persisted(vec![s.clone()], vec![s.clone()]);
        assert_eq!(sync_with_library(&mut p, &[s]), SyncReport::default());
    }
}
