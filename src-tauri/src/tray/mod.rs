//! System tray icon with connection-state colors + right-click actions.
//!
//! Icon states: connected (green up), error (red down), idle (blue right).
//! Right-click menu:
//!   • Подключить / Отключить — toggles the VPN depending on current state
//!   • Диагностика — shows the window and asks the UI to run diagnostics
//!   • Выйти — stops the core first (reverts the OS system proxy) then exits,
//!     so no dead proxy fallback is left behind.

use parking_lot::Mutex;
use tauri::menu::{Menu, MenuItem, PredefinedMenuItem};
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{AppHandle, Emitter, Manager, Wry};

use crate::clash::ClashStreams;
use crate::core::CoreState;

pub const TRAY_ID: &str = "main";

/// Holds the dynamic "toggle" menu item so its label can track the VPN state.
#[derive(Default)]
pub struct TrayMenu {
    toggle: Mutex<Option<MenuItem<Wry>>>,
}

pub fn build(app: &AppHandle) -> tauri::Result<()> {
    let toggle = MenuItem::with_id(app, "toggle", "Подключить", true, None::<&str>)?;
    let diag = MenuItem::with_id(app, "diag", "Диагностика", true, None::<&str>)?;
    let quit = MenuItem::with_id(app, "quit", "Выйти", true, None::<&str>)?;
    let sep = PredefinedMenuItem::separator(app)?;
    let menu = Menu::with_items(app, &[&toggle, &sep, &diag, &quit])?;

    app.state::<TrayMenu>().toggle.lock().replace(toggle);

    TrayIconBuilder::with_id(TRAY_ID)
        .icon(icon_for("idle"))
        .tooltip("TryToCatchMe — готово")
        .menu(&menu)
        .show_menu_on_left_click(false)
        .on_menu_event(|app, event| match event.id.as_ref() {
            "toggle" => toggle_vpn(app),
            "diag" => {
                show_main(app);
                let _ = app.emit("app://run-diagnostics", ());
            }
            "quit" => quit_app(app),
            _ => {}
        })
        .on_tray_icon_event(|tray, event| {
            if let TrayIconEvent::Click {
                button: MouseButton::Left,
                button_state: MouseButtonState::Up,
                ..
            } = event
            {
                show_main(tray.app_handle());
            }
        })
        .build(app)?;
    Ok(())
}

/// Update the tray icon, tooltip, and toggle label for the given state.
pub fn set_state(app: &AppHandle, state: &str) {
    if let Some(tray) = app.tray_by_id(TRAY_ID) {
        let _ = tray.set_icon(Some(icon_for(state)));
        let tip = match state {
            "connected" => "TryToCatchMe — подключено",
            "error" => "TryToCatchMe — потеря соединения",
            _ => "TryToCatchMe — готово",
        };
        let _ = tray.set_tooltip(Some(tip));
    }
    if let Some(item) = app.state::<TrayMenu>().toggle.lock().as_ref() {
        let label = if state == "idle" { "Подключить" } else { "Отключить" };
        let _ = item.set_text(label);
    }
}

/// Toggle the VPN from the tray, mirroring the UI's connect/disconnect flow.
fn toggle_vpn(app: &AppHandle) {
    let core = app.state::<CoreState>();
    let clash = app.state::<ClashStreams>();
    if core.status().running {
        clash.stop();
        let _ = core.stop();
        set_state(app, "idle");
        let _ = app.emit("vpn://state", "idle");
    } else {
        match core.start(app) {
            Ok(()) => {
                clash.start(app.clone());
                set_state(app, "connected");
                let _ = app.emit("vpn://state", "connected");
            }
            Err(e) => {
                set_state(app, "error");
                let _ = app.emit("vpn://state", "error");
                let _ = app.emit("app://error", e);
            }
        }
    }
}

/// Stop the core (reverts the OS system proxy) then exit — no dead fallback.
fn quit_app(app: &AppHandle) {
    let clash = app.state::<ClashStreams>();
    clash.stop();
    let core = app.state::<CoreState>();
    let _ = core.stop();
    app.exit(0);
}

fn show_main(app: &AppHandle) {
    if let Some(w) = app.get_webview_window("main") {
        let _ = w.show();
        let _ = w.unminimize();
        let _ = w.set_focus();
    }
}

fn icon_for(state: &str) -> tauri::image::Image<'static> {
    let bytes: &[u8] = match state {
        "connected" => include_bytes!("../../icons/tray/connected.png"),
        "error" => include_bytes!("../../icons/tray/error.png"),
        _ => include_bytes!("../../icons/tray/idle.png"),
    };
    tauri::image::Image::from_bytes(bytes).expect("bundled tray png is valid")
}
