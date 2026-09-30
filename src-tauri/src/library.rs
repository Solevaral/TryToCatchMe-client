//! Service library updates without a new release.
//!
//! The library the user picks services from ships inside the app
//! (`resources/service-library.json`) and is also fetched from the repository's main
//! branch. The fetched copy is cached in `<app config>/service-library.json` and
//! overrides built-in entries with the same id, so a new service or corrected domains
//! reach users as soon as the file on GitHub changes. A failed or invalid download keeps
//! the cached (or built-in) library.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tauri::{AppHandle, Emitter, Manager};
use ttcm_core::config::{geo_port, MIXED_LISTEN};
use ttcm_core::routing::Service;

pub const URL: &str =
    "https://raw.githubusercontent.com/Solevaral/TryToCatchMe-client/main/src-tauri/resources/service-library.json";

/// Refresh the cached library when it is older than this.
const MAX_AGE: Duration = Duration::from_secs(6 * 3600);

/// A shorter list is treated as broken (truncated file, provider block page parsed as JSON).
const MIN_SERVICES: usize = 10;

static BUSY: AtomicBool = AtomicBool::new(false);

fn cache_path(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_config_dir().ok().map(|d| d.join("service-library.json"))
}

/// The downloaded library, if a valid one is cached.
pub fn cached(app: &AppHandle) -> Vec<Service> {
    cache_path(app)
        .and_then(|p| fs::read_to_string(p).ok())
        .and_then(|s| parse(&s).ok())
        .unwrap_or_default()
}

/// Parse and sanity-check a library file.
pub fn parse(json: &str) -> Result<Vec<Service>, String> {
    let list: Vec<Service> = serde_json::from_str(json).map_err(|e| format!("не JSON библиотеки: {e}"))?;
    if list.len() < MIN_SERVICES {
        return Err(format!("в списке только {} сервисов", list.len()));
    }
    for s in &list {
        let valid_id = !s.id.is_empty()
            && s.id.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
        if !valid_id || s.name.trim().is_empty() {
            return Err(format!("некорректная запись «{}»", s.id));
        }
        if s.domains.is_empty() && s.ip_cidrs.is_empty() && s.geosite.is_none() {
            return Err(format!("у сервиса «{}» нет ни доменов, ни адресов", s.id));
        }
    }
    Ok(list)
}

fn is_fresh(app: &AppHandle) -> bool {
    cache_path(app)
        .and_then(|p| fs::metadata(p).ok())
        .and_then(|m| m.modified().ok())
        .and_then(|t| t.elapsed().ok())
        .map(|age| age < MAX_AGE)
        .unwrap_or(false)
}

async fn fetch(proxy: Option<&str>) -> Result<String, String> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30));
    builder = match proxy {
        Some(p) => builder.proxy(reqwest::Proxy::all(p).map_err(|e| e.to_string())?),
        None => builder.no_proxy(),
    };
    let client = builder.build().map_err(|e| e.to_string())?;
    let resp = client.get(URL).send().await.map_err(|e| crate::geo::describe_reqwest(&e))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("сервер ответил {status}"));
    }
    resp.text().await.map_err(|e| crate::geo::describe_reqwest(&e))
}

/// Download the library (through the VPN first when connected) and cache it.
/// Returns the number of services, or why nothing changed.
async fn update(app: &AppHandle, vpn_port: Option<u16>) -> Result<usize, String> {
    let mut attempts: Vec<Option<String>> = Vec::new();
    if let Some(port) = vpn_port {
        attempts.push(Some(format!("http://{MIXED_LISTEN}:{}", geo_port(port))));
    }
    attempts.push(None);

    let mut last_error = String::new();
    for proxy in attempts {
        match fetch(proxy.as_deref()).await.and_then(|body| parse(&body).map(|list| (body, list))) {
            Ok((body, list)) => {
                let path = cache_path(app).ok_or("нет папки настроек")?;
                if let Some(dir) = path.parent() {
                    let _ = fs::create_dir_all(dir);
                }
                let tmp = path.with_extension("json.tmp");
                fs::write(&tmp, body).map_err(|e| format!("не удалось записать: {e}"))?;
                fs::rename(&tmp, &path).map_err(|e| format!("не удалось записать: {e}"))?;
                return Ok(list.len());
            }
            Err(e) => last_error = e,
        }
    }
    Err(last_error)
}

/// Refresh in the background when the cached copy is missing or stale.
/// `vpn_port` — the local proxy port while connected (download goes through the VPN).
pub fn schedule(app: &AppHandle, vpn_port: Option<u16>) {
    if is_fresh(app) || BUSY.swap(true, Ordering::SeqCst) {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        // В консоль журнала приложения: ошибка здесь не мешает работе, поэтому не app://error.
        let msg = match update(&app, vpn_port).await {
            Ok(n) => format!("Библиотека сервисов обновлена: {n} шт."),
            Err(e) => format!("Библиотека сервисов не обновлена ({e}), использую сохранённую"),
        };
        let _ = app.emit("app://log", msg);
        BUSY.store(false, Ordering::SeqCst);
    });
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn bundled_library_is_valid() {
        let list = parse(include_str!("../resources/service-library.json")).expect("bundled library");
        let mut ids: Vec<_> = list.iter().map(|s| s.id.as_str()).collect();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), list.len(), "duplicate ids");
    }

    #[test]
    fn rejects_short_or_broken_lists() {
        assert!(parse("[]").is_err());
        assert!(parse("<html>blocked</html>").is_err());
    }
}
