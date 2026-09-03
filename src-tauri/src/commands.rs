//! Tauri command surface exposed to the React frontend.
//! Keep these thin: delegate to the layered modules.

use crate::clash::ClashStreams;
use crate::core::{CoreState, CoreStatus};
use crate::diag::{self, DiagInput, DiagReport};
use crate::links::Profile;
use crate::profiles::{ImportResult, ProfileStore};
use crate::routing::{RoutingSnapshot, RoutingStore};
use crate::settings::{Settings, SettingsStore};
use tauri::{AppHandle, Manager, State};
use ttcm_core::routing::{RoutingConfig, Service};

#[tauri::command]
pub fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ---- core ----

#[tauri::command]
pub async fn core_start(app: AppHandle) -> Result<(), String> {
    // Run the blocking spawn/wait off the UI thread so the window never freezes.
    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || app2.state::<CoreState>().start(&app2))
        .await
        .map_err(|e| e.to_string())??;
    // Core is up (Clash API ready) — start live traffic/log streams + failover monitor.
    app.state::<ClashStreams>().start(app.clone());
    app.state::<crate::monitor::Monitor>().start(app.clone());
    Ok(())
}

#[tauri::command]
pub fn core_stop(
    state: State<'_, CoreState>,
    clash: State<'_, ClashStreams>,
    monitor: State<'_, crate::monitor::Monitor>,
) -> Result<(), String> {
    monitor.stop();
    clash.stop();
    state.stop()
}

#[tauri::command]
pub async fn core_restart(app: AppHandle) -> Result<(), String> {
    app.state::<ClashStreams>().stop();
    let app2 = app.clone();
    tauri::async_runtime::spawn_blocking(move || app2.state::<CoreState>().restart(&app2))
        .await
        .map_err(|e| e.to_string())??;
    app.state::<ClashStreams>().start(app.clone());
    Ok(())
}

#[tauri::command]
pub fn core_status(state: State<'_, CoreState>) -> CoreStatus {
    state.status()
}

/// Update the tray icon state: "connected" | "error" | "idle".
#[tauri::command]
pub fn tray_set_state(app: AppHandle, state: String) {
    crate::tray::set_state(&app, &state);
}

// ---- profiles ----

#[tauri::command]
pub fn profiles_list(store: State<'_, ProfileStore>) -> Vec<Profile> {
    store.list()
}

#[tauri::command]
pub fn profiles_active(store: State<'_, ProfileStore>) -> Option<String> {
    store.active_id()
}

#[tauri::command]
pub fn profiles_import(
    app: AppHandle,
    store: State<'_, ProfileStore>,
    text: String,
) -> ImportResult {
    store.import(&app, &text)
}

#[tauri::command]
pub fn profiles_remove(app: AppHandle, store: State<'_, ProfileStore>, id: String) {
    store.remove(&app, &id);
}

/// TCP-connect latency to a profile's server (ms), or null if unreachable.
#[tauri::command]
pub async fn profile_ping(app: AppHandle, id: String) -> Option<u64> {
    let ep = app.state::<ProfileStore>().endpoint_of(&id)?;
    let addr = format!("{}:{}", ep.0, ep.1);
    tauri::async_runtime::spawn_blocking(move || diag::tcp_connect(&addr, 4000))
        .await
        .ok()
        .flatten()
}

#[tauri::command]
pub fn profiles_set_active(
    app: AppHandle,
    store: State<'_, ProfileStore>,
    id: Option<String>,
) {
    store.set_active(&app, id);
}

// ---- routing ----

#[tauri::command]
pub fn routing_get(store: State<'_, RoutingStore>) -> RoutingSnapshot {
    store.snapshot()
}

#[tauri::command]
pub fn routing_set_config(
    app: AppHandle,
    store: State<'_, RoutingStore>,
    config: RoutingConfig,
) {
    store.set_config(&app, config);
}

#[tauri::command]
pub fn service_upsert(app: AppHandle, store: State<'_, RoutingStore>, service: Service) {
    store.upsert_service(&app, service);
}

#[tauri::command]
pub fn service_remove(app: AppHandle, store: State<'_, RoutingStore>, id: String) {
    store.remove_service(&app, &id);
}

#[tauri::command]
pub fn services_reset(app: AppHandle, store: State<'_, RoutingStore>) {
    store.reset_services(&app);
}

/// The large read-only service library the user can add presets from.
#[tauri::command]
pub fn services_library() -> Vec<Service> {
    crate::routing::library()
}

/// Clear the cached geo rule-sets and (if connected) reconnect so they re-download.
#[tauri::command]
pub async fn geo_refresh(app: AppHandle) -> Result<(), String> {
    if let Ok(dir) = app.path().app_config_dir() {
        let _ = std::fs::remove_file(dir.join("cache.db"));
    }
    if app.state::<CoreState>().status().running {
        app.state::<ClashStreams>().stop();
        let app2 = app.clone();
        tauri::async_runtime::spawn_blocking(move || app2.state::<CoreState>().restart(&app2))
            .await
            .map_err(|e| e.to_string())??;
        app.state::<ClashStreams>().start(app.clone());
    }
    Ok(())
}

// ---- settings ----

#[tauri::command]
pub fn settings_get(store: State<'_, SettingsStore>) -> Settings {
    store.get()
}

#[tauri::command]
pub fn settings_set(app: AppHandle, store: State<'_, SettingsStore>, settings: Settings) {
    store.set(&app, settings);
}

/// Whether the app currently runs with administrator rights (needed for TUN).
#[tauri::command]
pub fn is_admin() -> bool {
    crate::platform::is_elevated()
}

/// Relaunch the app elevated (UAC), then exit this instance.
#[tauri::command]
pub fn relaunch_admin(app: AppHandle) {
    if crate::platform::relaunch_elevated().is_ok() {
        app.exit(0);
    }
}

// ---- diagnostics ----

#[tauri::command]
pub async fn diag_run(app: AppHandle, targets: Option<Vec<String>>) -> DiagReport {
    let server = app.state::<ProfileStore>().active_endpoint();
    let core_running = app.state::<CoreState>().status().running;
    let mut targets: Vec<String> = targets
        .unwrap_or_default()
        .into_iter()
        .map(|t| t.trim().to_string())
        .filter(|t| !t.is_empty())
        .collect();
    if targets.is_empty() {
        targets.push("www.google.com".to_string());
    }
    let input = DiagInput {
        server,
        core_running,
        targets,
    };
    tauri::async_runtime::spawn_blocking(move || diag::run(input))
        .await
        .unwrap_or(DiagReport {
            steps: vec![],
            verdict: "Не удалось запустить диагностику".to_string(),
        })
}
