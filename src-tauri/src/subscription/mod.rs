//! Subscription downloads (https://… links from a VPN provider's panel).
//!
//! Panels like Remnawave answer an unknown device with a stub ("App not supported")
//! unless the request carries an `x-hwid` device id, so we send a stable random one
//! (kept in the app config dir) plus the usual device headers.

use std::fs;
use std::time::Duration;

use tauri::{AppHandle, Manager};
use ttcm_core::config::{geo_port, MIXED_LISTEN};
use ttcm_core::subscription::{self, SubInfo};

pub struct Fetched {
    pub body: String,
    pub title: String,
    pub info: Option<SubInfo>,
}

/// A stable per-install device id for `x-hwid` (random, not derived from hardware).
fn hwid(app: &AppHandle) -> String {
    let path = app.path().app_config_dir().ok().map(|d| d.join("hwid"));
    if let Some(id) = path.as_ref().and_then(|p| fs::read_to_string(p).ok()) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }
    let id = uuid::Uuid::new_v4().simple().to_string();
    if let Some(p) = path {
        if let Some(dir) = p.parent() {
            let _ = fs::create_dir_all(dir);
        }
        let _ = fs::write(p, &id);
    }
    id
}

fn os_name() -> &'static str {
    match std::env::consts::OS {
        "windows" => "Windows",
        "linux" => "Linux",
        "macos" => "macOS",
        other => other,
    }
}

async fn fetch_once(app: &AppHandle, url: &str, proxy: Option<&str>) -> Result<Fetched, String> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(Duration::from_secs(10))
        .timeout(Duration::from_secs(30));
    builder = match proxy {
        Some(p) => builder.proxy(reqwest::Proxy::all(p).map_err(|e| e.to_string())?),
        None => builder.no_proxy(),
    };
    let client = builder.build().map_err(|e| e.to_string())?;
    let resp = client
        .get(url)
        .header("User-Agent", format!("TryToCatchMe/{}", env!("CARGO_PKG_VERSION")))
        .header("Accept", "*/*")
        .header("x-hwid", hwid(app))
        .header("x-device-os", os_name())
        .header("x-device-model", "TryToCatchMe")
        .send()
        .await
        .map_err(|e| crate::geo::describe_reqwest(&e))?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("сервер ответил {status}"));
    }
    let header = |name: &str| {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    };
    let title = subscription::title(header("profile-title").as_deref(), url);
    let info = header("subscription-userinfo").and_then(|h| subscription::parse_userinfo(&h));
    let body = resp.text().await.map_err(|e| crate::geo::describe_reqwest(&e))?;
    Ok(Fetched { body, title, info })
}

/// Download a subscription. `vpn_port` = the local proxy port while connected: the
/// panel's domain may be blocked, so it goes through the VPN first, then directly.
pub async fn fetch(app: &AppHandle, url: &str, vpn_port: Option<u16>) -> Result<Fetched, String> {
    if let Some(port) = vpn_port {
        // The geo-download inbound always goes through the proxy, whatever the routing.
        let proxy = format!("http://{MIXED_LISTEN}:{}", geo_port(port));
        match fetch_once(app, url, Some(&proxy)).await {
            Ok(f) => return Ok(f),
            Err(via_vpn) => {
                return fetch_once(app, url, None)
                    .await
                    .map_err(|direct| format!("через VPN: {via_vpn}; напрямую: {direct}"));
            }
        }
    }
    fetch_once(app, url, None).await
}
