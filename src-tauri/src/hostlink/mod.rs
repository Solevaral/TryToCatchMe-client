//! Channel to the All in One host (`--hosted` mode): protocol HostLink v1 over a named pipe.
//!
//! The app is the pipe server, the host is the client — so the VPN keeps running when the
//! host restarts (e.g. after a self-update) and the host simply reconnects.
//! Messages are JSON lines:
//!   request  {"id":1,"method":"getStatus","params":{}}
//!   response {"id":1,"result":{...}}  or  {"id":1,"error":{"code":"...","message":"..."}}
//!   event    {"event":"statusChanged","data":{...}}
//!
//! `shutdown` goes through the same path as "Выйти" in the tray: stop the core (reverts the
//! OS system proxy, no sing-box left behind), then exit.

use std::sync::atomic::{AtomicBool, Ordering};

use parking_lot::Mutex;
use serde_json::{json, Value};
use tauri::{AppHandle, Emitter, Manager};
use tokio::sync::mpsc;

use crate::core::CoreState;
use crate::profiles::ProfileStore;
use crate::settings::SettingsStore;

pub const PROTOCOL_VERSION: i64 = 1;

/// Command-line switches: `--hosted --pipe <name>` from the host, `--minimized` from autostart.
pub struct HostArgs {
    pub hosted: bool,
    pub pipe: String,
    pub minimized: bool,
}

pub fn parse_args() -> HostArgs {
    let args: Vec<String> = std::env::args().collect();
    let has = |flag: &str| args.iter().any(|a| a.eq_ignore_ascii_case(flag));
    let pipe = args
        .iter()
        .position(|a| a.eq_ignore_ascii_case("--pipe"))
        .and_then(|i| args.get(i + 1).cloned())
        .unwrap_or_else(|| "AllInOne.trytocatchme".to_string());
    HostArgs {
        hosted: has("--hosted"),
        pipe,
        minimized: has("--minimized"),
    }
}

/// Shared state: whether we run under the host and where to send events.
#[derive(Default)]
pub struct HostLink {
    hosted: AtomicBool,
    events: Mutex<Option<mpsc::UnboundedSender<String>>>,
}

impl HostLink {
    pub fn is_hosted(&self) -> bool {
        self.hosted.load(Ordering::Relaxed)
    }

    /// Send an event to the host; silently dropped while it is not connected.
    pub fn publish(&self, event: &str, data: Value) {
        if let Some(tx) = self.events.lock().as_ref() {
            let _ = tx.send(json!({ "event": event, "data": data }).to_string());
        }
    }
}

/// Status line for the host tile: "Подключено: <profile>" / "Не подключено".
pub fn status(app: &AppHandle) -> Value {
    let connected = app.state::<CoreState>().status().running;
    let settings = app.state::<SettingsStore>().get();
    let profile = app.state::<ProfileStore>().active_name();
    let mode = if settings.capture_tun { "TUN" } else { "системный прокси" };
    let summary = match (connected, &profile) {
        (true, Some(name)) => format!("Подключено: {name}"),
        (true, None) => "Подключено".to_string(),
        (false, _) => "Не подключено".to_string(),
    };
    json!({
        "state": "running",
        "summary": summary,
        "detail": format!("Режим: {mode}"),
        "connected": connected,
        "tun": settings.capture_tun,
        "profile": profile,
    })
}

/// Tell the host the state changed (called from `tray::set_state`).
pub fn notify_state(app: &AppHandle) {
    let link = app.state::<HostLink>();
    if link.is_hosted() {
        link.publish("statusChanged", status(app));
    }
}

/// Start serving the pipe in the background.
pub fn start(app: AppHandle, pipe: String) {
    app.state::<HostLink>().hosted.store(true, Ordering::Relaxed);
    #[cfg(windows)]
    tauri::async_runtime::spawn(serve(app, pipe));
    #[cfg(not(windows))]
    let _ = (app, pipe);
}

#[cfg(windows)]
async fn serve(app: AppHandle, pipe: String) {
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::windows::named_pipe::ServerOptions;

    let name = format!(r"\\.\pipe\{pipe}");
    loop {
        // first_pipe_instance: refuse to share the name with a pipe some other process created.
        let server = match ServerOptions::new().first_pipe_instance(true).create(&name) {
            Ok(s) => s,
            Err(_) => {
                // The previous instance is still being torn down (or the name is taken) — retry.
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
                continue;
            }
        };
        if server.connect().await.is_err() {
            continue;
        }

        let (reader, mut writer) = tokio::io::split(server);
        let (tx, mut rx) = mpsc::unbounded_channel::<String>();
        *app.state::<HostLink>().events.lock() = Some(tx.clone());

        let writer_task = tauri::async_runtime::spawn(async move {
            while let Some(line) = rx.recv().await {
                if writer.write_all(line.as_bytes()).await.is_err()
                    || writer.write_all(b"\n").await.is_err()
                    || writer.flush().await.is_err()
                {
                    break;
                }
            }
        });

        let mut lines = BufReader::new(reader).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            if line.trim().is_empty() {
                continue;
            }
            if let Some(response) = handle(&app, &line) {
                let _ = tx.send(response);
            }
        }

        // Host disconnected (or restarted) — wait for the next connection.
        *app.state::<HostLink>().events.lock() = None;
        drop(tx);
        writer_task.abort();
    }
}

fn handle(app: &AppHandle, line: &str) -> Option<String> {
    let request: Value = serde_json::from_str(line).ok()?;
    let id = request.get("id")?.as_i64()?;
    let method = request.get("method")?.as_str()?.to_string();
    let params = request.get("params").cloned().unwrap_or(Value::Null);

    let result: Result<Value, (&str, String)> = match method.as_str() {
        "hello" => Ok(json!({
            "protocol": PROTOCOL_VERSION,
            "appVersion": env!("CARGO_PKG_VERSION"),
            "processId": std::process::id(),
            "capabilities": { "actions": [
                { "id": "connect", "title": "Подключить" },
                { "id": "disconnect", "title": "Отключить" },
                { "id": "diag", "title": "Диагностика" },
            ]},
        })),
        "getStatus" => Ok(status(app)),
        "showWindow" => {
            crate::tray::show_main(app);
            Ok(status(app))
        }
        "invoke" => match params.get("action").and_then(Value::as_str) {
            Some("connect") => {
                crate::tray::connect(app);
                Ok(status(app))
            }
            Some("disconnect") => {
                crate::tray::disconnect(app);
                Ok(status(app))
            }
            Some("diag") => {
                crate::tray::show_main(app);
                let _ = app.emit("app://run-diagnostics", ());
                Ok(status(app))
            }
            _ => Err(("unknownAction", "Неизвестное действие".to_string())),
        },
        "shutdown" => {
            // Reply first, then stop the core and exit (same as "Выйти" in the tray).
            let app = app.clone();
            std::thread::spawn(move || {
                std::thread::sleep(std::time::Duration::from_millis(150));
                crate::tray::quit_app(&app);
            });
            Ok(json!({ "accepted": true }))
        }
        other => Err(("unknownMethod", format!("Метод {other} не поддерживается"))),
    };

    let response = match result {
        Ok(value) => json!({ "id": id, "result": value }),
        Err((code, message)) => json!({ "id": id, "error": { "code": code, "message": message } }),
    };
    Some(response.to_string())
}
