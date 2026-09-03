//! TryToCatchMe VPN client — Rust backend (Tauri v2).
//!
//! Modules:
//!   core     — sing-box sidecar lifecycle
//!   config   — profiles + rules -> sing-box config.json
//!   links    — vless/vmess/ss/trojan/subscription parsers
//!   clash    — Clash API client for traffic/logs
//!   routing  — routing model + service presets
//!   diag     — network chain diagnostics
//!   monitor  — auto-failover between profiles
//!   platform — OS-specific bits (elevation, wintun)

pub mod clash;
pub mod commands;
pub mod core;
pub mod diag;
pub mod platform;
pub mod monitor;
pub mod profiles;
pub mod routing;
pub mod settings;
pub mod tray;

// Pure, platform-independent logic lives in the ttcm-core crate; re-export it under
// the familiar `crate::config` / `crate::links` paths.
pub use ttcm_core::{config, links};

use clash::ClashStreams;
use core::CoreState;
use profiles::ProfileStore;
use routing::RoutingStore;
use tauri::Manager;

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .plugin(tauri_plugin_clipboard_manager::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            Some(vec!["--minimized"]),
        ))
        .manage(CoreState::default())
        .manage(ProfileStore::default())
        .manage(ClashStreams::default())
        .manage(RoutingStore::default())
        .manage(settings::SettingsStore::default())
        .manage(monitor::Monitor::default())
        .manage(tray::TrayMenu::default())
        .setup(|app| {
            // Load saved profiles + routing + settings from disk at startup.
            let store = app.state::<ProfileStore>();
            store.load(app.handle());
            app.state::<RoutingStore>().load(app.handle());
            app.state::<settings::SettingsStore>().load(app.handle());
            // System tray (starts in the idle/blue state).
            tray::build(app.handle())?;
            Ok(())
        })
        .on_window_event(|window, event| {
            // Close-to-tray: hide the window instead of quitting; exit via the tray menu.
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                let _ = window.hide();
                api.prevent_close();
            }
        })
        .invoke_handler(tauri::generate_handler![
            commands::app_version,
            commands::core_start,
            commands::core_stop,
            commands::core_restart,
            commands::core_status,
            commands::tray_set_state,
            commands::profiles_list,
            commands::profiles_active,
            commands::profiles_import,
            commands::profiles_remove,
            commands::profiles_set_active,
            commands::routing_get,
            commands::routing_set_config,
            commands::service_upsert,
            commands::service_remove,
            commands::services_reset,
            commands::services_library,
            commands::geo_refresh,
            commands::settings_get,
            commands::settings_set,
            commands::is_admin,
            commands::relaunch_admin,
            commands::diag_run,
            commands::profile_ping,
        ])
        .build(tauri::generate_context!())
        .expect("error while building TryToCatchMe application")
        .run(|app, event| {
            // Safety net: whatever triggers exit, stop the core so the OS system
            // proxy is reverted and no sing-box process is left running.
            if let tauri::RunEvent::Exit = event {
                app.state::<monitor::Monitor>().stop();
                app.state::<ClashStreams>().stop();
                let _ = app.state::<CoreState>().stop();
            }
        });
}
