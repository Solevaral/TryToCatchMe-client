//! Geo rule-set (geosite/geoip) downloads, done by the app — not by sing-box.
//!
//! Files live in `<app config>/rules/` and are referenced as LOCAL rule-sets, so a failed
//! download can never abort the core. A download tries through the VPN first (the ISP
//! often blocks raw.githubusercontent.com) and falls back to a direct connection. New
//! files replace the old ones only when every file downloaded and validated, so a failed
//! refresh keeps the previous lists.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use tauri::{AppHandle, Manager};
use ttcm_core::config::{geo_port, MIXED_LISTEN};
use ttcm_core::routing::geo_files;

/// sing-box binary rule-set magic: "SRS" + format version.
const SRS_MAGIC: &[u8] = b"SRS";
/// Refresh lists older than this in the background after connecting.
pub const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

static BUSY: AtomicBool = AtomicBool::new(false);

pub fn dir(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_config_dir().ok().map(|d| d.join("rules"))
}

/// The rules folder if every file for `region` is present (usable by the core).
pub fn ready_dir(app: &AppHandle, region: &str) -> Option<String> {
    let d = dir(app)?;
    let all = geo_files(region).iter().all(|f| {
        fs::metadata(d.join(&f.file_name)).map(|m| m.len() > 0).unwrap_or(false)
    });
    all.then(|| d.to_string_lossy().to_string())
}

/// Age of the oldest file for `region`, if all are present.
pub fn age(app: &AppHandle, region: &str) -> Option<Duration> {
    let d = dir(app)?;
    geo_files(region)
        .iter()
        .map(|f| fs::metadata(d.join(&f.file_name)).ok()?.modified().ok()?.elapsed().ok())
        .collect::<Option<Vec<_>>>()?
        .into_iter()
        .max()
}

/// Remove the region's files (e.g. when sing-box reports them as corrupt).
pub fn remove(app: &AppHandle, region: &str) {
    if let Some(d) = dir(app) {
        for f in geo_files(region) {
            let _ = fs::remove_file(d.join(f.file_name));
        }
    }
}

async fn fetch(url: &str, proxy: Option<&str>) -> Result<Vec<u8>, String> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(60));
    builder = match proxy {
        Some(p) => builder.proxy(reqwest::Proxy::all(p).map_err(|e| e.to_string())?),
        None => builder.no_proxy(),
    };
    let client = builder.build().map_err(|e| e.to_string())?;
    let resp = client.get(url).send().await.map_err(|e| describe_reqwest(&e))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("сервер ответил {status}"));
    }
    let body = resp.bytes().await.map_err(|e| describe_reqwest(&e))?;
    if !body.starts_with(SRS_MAGIC) {
        return Err("получен не файл списка (возможно, страница блокировки провайдера)".into());
    }
    Ok(body.to_vec())
}

fn describe_reqwest(e: &reqwest::Error) -> String {
    if e.is_timeout() {
        "таймаут".into()
    } else if e.is_connect() {
        "не удалось подключиться".into()
    } else {
        // Include the source chain: the top-level message alone is often vague.
        let mut msg = e.to_string();
        let mut src = std::error::Error::source(e);
        while let Some(s) = src {
            msg.push_str(": ");
            msg.push_str(&s.to_string());
            src = s.source();
        }
        msg
    }
}

/// Download all files for `region`. `vpn_port` = the local proxy port while connected
/// (downloads then go through the VPN first). Returns how it was downloaded.
pub async fn download(app: &AppHandle, region: &str, vpn_port: Option<u16>) -> Result<String, String> {
    if BUSY.swap(true, Ordering::SeqCst) {
        return Err("списки уже скачиваются".into());
    }
    let result = download_inner(app, region, vpn_port).await;
    BUSY.store(false, Ordering::SeqCst);
    result
}

async fn download_inner(app: &AppHandle, region: &str, vpn_port: Option<u16>) -> Result<String, String> {
    let dir = dir(app).ok_or("нет папки настроек")?;
    fs::create_dir_all(&dir).map_err(|e| format!("не удалось создать папку списков: {e}"))?;
    let files = geo_files(region);

    let mut attempts: Vec<(&str, Option<String>)> = Vec::new();
    if let Some(port) = vpn_port {
        attempts.push(("через VPN", Some(format!("http://{MIXED_LISTEN}:{}", geo_port(port)))));
    }
    attempts.push(("напрямую", None));

    let mut errors = Vec::new();
    'attempt: for (label, proxy) in attempts {
        let mut fetched = Vec::new();
        for f in &files {
            match fetch(&f.url, proxy.as_deref()).await {
                Ok(bytes) => fetched.push((f, bytes)),
                Err(e) => {
                    errors.push(format!("{label}: {} — {e}", f.file_name));
                    continue 'attempt;
                }
            }
        }
        // Everything downloaded: write temp files, then swap them in.
        for (f, bytes) in &fetched {
            let tmp = dir.join(format!("{}.tmp", f.file_name));
            fs::write(&tmp, bytes).map_err(|e| format!("не удалось записать {}: {e}", f.file_name))?;
        }
        for (f, _) in &fetched {
            let tmp = dir.join(format!("{}.tmp", f.file_name));
            fs::rename(&tmp, dir.join(&f.file_name))
                .map_err(|e| format!("не удалось сохранить {}: {e}", f.file_name))?;
        }
        return Ok(label.to_string());
    }
    Err(errors.join("; "))
}
