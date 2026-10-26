//! System tray icon with connection-state colors + right-click actions.
//!
//! Icon states: connected (green up), error (red down), idle (blue right).
//! Right-click menu:
//!   • Подключить / Отключить — toggles the VPN depending on current state
//!   • Диагностика — shows the window and asks the UI to run diagnostics
//!   • Выйти — stops the core first (reverts the OS system proxy) then exits,
//!     so no dead proxy fallback is left behind.
//!
//! Under the All in One host (`--hosted`) the tray stays; the host also drives the same
//! connect / disconnect / quit functions over `hostlink`.

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
    crate::hostlink::notify_state(app);
}

/// Toggle the VPN from the tray, mirroring the UI's connect/disconnect flow.
fn toggle_vpn(app: &AppHandle) {
    if app.state::<CoreState>().vpn_connected() {
        disconnect(app);
    } else {
        connect(app);
    }
}

/// Connect with the active profile. Starting blocks until the core is up — do it off the
/// event-loop thread so the window and tray stay responsive.
pub(crate) fn connect(app: &AppHandle) {
    if app.state::<CoreState>().vpn_connected() {
        return;
    }
    let app = app.clone();
    let _ = app.emit("vpn://state", "connecting");
    app.state::<CoreState>().set_vpn(true);
    std::thread::spawn(move || match crate::core::apply(&app) {
        Ok(()) => {
            set_state(&app, "connected");
            let _ = app.emit("vpn://state", "connected");
        }
        Err(e) => {
            app.state::<CoreState>().set_vpn(false);
            set_state(&app, "error");
            let _ = app.emit("vpn://state", "error");
            let _ = app.emit("app://error", format!("Не удалось подключиться: {e}"));
        }
    });
}

/// Disconnect the VPN (a built-in WireGuard tunnel that's on keeps running; with none,
/// the core stops and the OS system proxy is reverted).
pub(crate) fn disconnect(app: &AppHandle) {
    app.state::<CoreState>().set_vpn(false);
    set_state(app, "idle");
    let _ = app.emit("vpn://state", "idle");
    let app = app.clone();
    std::thread::spawn(move || {
        if let Err(e) = crate::core::apply(&app) {
            let _ = app.emit("app://error", e);
        }
    });
}

/// Stop the core (reverts the OS system proxy) then exit — no dead fallback.
pub(crate) fn quit_app(app: &AppHandle) {
    let clash = app.state::<ClashStreams>();
    clash.stop();
    app.state::<crate::monitor::Monitor>().stop();
    let core = app.state::<CoreState>();
    let _ = core.stop(app);
    app.exit(0);
}

pub(crate) fn show_main(app: &AppHandle) {
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
