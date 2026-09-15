//! Tauri command surface exposed to the React frontend.
//! Keep these thin: delegate to the layered modules.

use crate::clash::ClashStreams;
use crate::core::{CoreState, CoreStatus};
use crate::diag::{self, DiagInput, DiagReport};
use crate::links::Profile;
use crate::profiles::{ImportResult, ProfileStore};
use crate::routing::{RoutingSnapshot, RoutingStore};
use crate::settings::{Settings, SettingsStore};
use tauri::{AppHandle, Emitter, Manager, State};
use ttcm_core::routing::{RoutingConfig, Service};

#[tauri::command]
pub fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ---- core ----

/// Run a blocking core operation off the UI thread; any failure is also written to
/// the log console so the user always sees WHY, not just "Ошибка".
async fn run_core<F>(app: &AppHandle, op: F) -> Result<(), String>
where
    F: FnOnce(&AppHandle) -> Result<(), String> + Send + 'static,
{
    let app2 = app.clone();
    let result = tauri::async_runtime::spawn_blocking(move || op(&app2))
        .await
        .map_err(|e| format!("внутренняя ошибка: {e}"))
        .and_then(|r| r);
    if let Err(e) = &result {
        let _ = app.emit("app://error", format!("Не удалось подключиться: {e}"));
    }
    result
}

#[tauri::command]
pub async fn core_start(app: AppHandle) -> Result<(), String> {
    run_core(&app, |a| a.state::<CoreState>().start(a)).await?;
    // Core is up (Clash API ready) — start live traffic/log streams + failover monitor.
    app.state::<ClashStreams>().start(app.clone());
    app.state::<crate::monitor::Monitor>().start(app.clone());
    Ok(())
}

#[tauri::command]
pub fn core_stop(
    app: AppHandle,
    state: State<'_, CoreState>,
    clash: State<'_, ClashStreams>,
    monitor: State<'_, crate::monitor::Monitor>,
) -> Result<(), String> {
    monitor.stop();
    clash.stop();
    state.stop(&app)
}

#[tauri::command]
pub async fn core_restart(app: AppHandle) -> Result<(), String> {
    app.state::<ClashStreams>().stop();
    run_core(&app, |a| a.state::<CoreState>().restart(a)).await?;
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

#[derive(serde::Serialize)]
pub struct GeoRefreshResult {
    pub ok: bool,
    pub message: String,
}

/// Re-download geo lists and report what really happened. Downloads go through the VPN
/// when connected, falling back to direct; the old lists stay if the download fails.
#[tauri::command]
pub async fn geo_refresh(app: AppHandle) -> GeoRefreshResult {
    let result = |ok: bool, message: String| {
        let _ = app.emit(if ok { "app://log" } else { "app://error" }, message.clone());
        GeoRefreshResult { ok, message }
    };
    let files = app.state::<RoutingStore>().plan().files();
    if files.is_empty() {
        return result(
            false,
            "Нечего обновлять: нет выбранного региона и включённых сервисов с полным списком доменов (нужен режим «Rule»)".into(),
        );
    }
    let running = app.state::<CoreState>().status().running;
    let has_proxy = app.state::<ProfileStore>().active_outbound().is_some();
    let vpn_port = (running && has_proxy).then(|| app.state::<SettingsStore>().get().proxy_port);
    let had_old = crate::geo::all_present(&app, &files);

    match crate::geo::download(&app, &files, vpn_port).await {
        Ok(how) if running => {
            let how = format!("{} шт., {how}", files.len());
            app.state::<ClashStreams>().stop();
            match run_core(&app, |a| a.state::<CoreState>().restart(a)).await {
                Ok(()) => {
                    app.state::<ClashStreams>().start(app.clone());
                    result(true, format!("Списки скачаны ({how}) и применены"))
                }
                Err(e) => result(false, format!("Списки скачаны ({how}), но перезапустить туннель не удалось: {e}")),
            }
        }
        Ok(how) => result(true, format!("Списки скачаны ({} шт., {how}) — применятся при подключении", files.len())),
        Err(e) => {
            let mut msg = format!("Не удалось скачать списки: {e}.");
            if had_old {
                msg.push_str(" Сохранённые списки оставлены.");
            }
            if vpn_port.is_none() {
                msg.push_str(" Подключите VPN и повторите — GitHub может быть недоступен напрямую.");
            }
            result(false, msg)
        }
    }
}

// ---- system proxy ----

#[tauri::command]
pub fn sysproxy_status(state: State<'_, crate::sysproxy::SysProxyState>) -> crate::sysproxy::SysProxyStatus {
    state.status()
}

/// Point the system proxy back at us after another program overwrote it.
#[tauri::command]
pub fn sysproxy_reapply(app: AppHandle, state: State<'_, crate::sysproxy::SysProxyState>) -> Result<(), String> {
    state.reapply()?;
    let _ = app.emit("app://log", "Системный прокси снова указывает на TryToCatchMe".to_string());
    Ok(())
}

// ---- settings ----

#[tauri::command]
pub fn settings_get(store: State<'_, SettingsStore>) -> Settings {
    store.get()
}

#[tauri::command]
pub fn settings_set(app: AppHandle, store: State<'_, SettingsStore>, settings: Settings) -> Result<(), String> {
    // The geo-download inbound uses port + 1, so the top port is reserved.
    if !(1024..=65534).contains(&settings.proxy_port) {
        return Err("Порт прокси должен быть от 1024 до 65534".into());
    }
    store.set(&app, settings);
    Ok(())
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
    let mut report = tauri::async_runtime::spawn_blocking(move || diag::run(input))
        .await
        .unwrap_or(DiagReport {
            steps: vec![],
            verdict: "Не удалось запустить диагностику".to_string(),
        });
    // Through the active profile: exit IP, the country Google sees, AI service regions.
    if core_running && app.state::<ProfileStore>().active_outbound().is_some() {
        let port = app.state::<SettingsStore>().get().proxy_port;
        let extra = diag::service_checks(port).await;
        if report.verdict == "Всё в порядке" {
            if let Some(bad) = extra.iter().find(|s| s.status == "fail") {
                report.verdict = format!("Туннель работает, но: {} — {}", bad.label, bad.detail);
            }
        }
        report.steps.extend(extra);
    }
    report
}
