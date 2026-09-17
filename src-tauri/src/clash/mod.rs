//! Clash API client.
//!
//! sing-box exposes a Clash-compatible controller (experimental.clash_api). We open
//! WebSocket streams to /traffic and /logs and forward each message to the UI via
//! Tauri events: `clash://traffic` ({up,down} bytes/s) and `clash://log`
//! ({type,payload}). Streams reconnect while the core is up; `stop` aborts them.

use futures_util::StreamExt;
use parking_lot::Mutex;
use tauri::{AppHandle, Emitter, Manager};
use tokio_tungstenite::tungstenite::Message;

use crate::config::CLASH_CONTROLLER;

pub const EVENT_TRAFFIC: &str = "clash://traffic";
pub const EVENT_LOG: &str = "clash://log";

#[derive(Default)]
pub struct ClashStreams {
    handles: Mutex<Vec<tauri::async_runtime::JoinHandle<()>>>,
}

impl ClashStreams {
    /// Start (or restart) the traffic + log streams. The log level follows the
    /// "verbose logs" setting: without it the core only reports warnings and errors.
    pub fn start(&self, app: AppHandle) {
        self.stop();
        let level = if app.state::<crate::settings::SettingsStore>().get().verbose_logs {
            "info"
        } else {
            "warning"
        };
        let mut g = self.handles.lock();
        g.push(tauri::async_runtime::spawn(stream(
            app.clone(),
            format!("ws://{CLASH_CONTROLLER}/traffic"),
            EVENT_TRAFFIC,
        )));
        g.push(tauri::async_runtime::spawn(stream(
            app,
            format!("ws://{CLASH_CONTROLLER}/logs?level={level}"),
            EVENT_LOG,
        )));
    }

    pub fn stop(&self) {
        let mut g = self.handles.lock();
        for h in g.drain(..) {
            h.abort();
        }
    }
}

/// Connect to a Clash WS endpoint and forward text frames as a Tauri event,
/// reconnecting after a short delay until the task is aborted.
async fn stream(app: AppHandle, url: String, event: &'static str) {
    loop {
        match tokio_tungstenite::connect_async(&url).await {
            Ok((ws, _)) => {
                let (_, mut read) = ws.split();
                if event == EVENT_LOG {
                    pump_logs(&app, &mut read).await;
                } else {
                    while let Some(msg) = read.next().await {
                        match msg {
                            Ok(Message::Text(text)) => {
                                let _ = app.emit(event, text.to_string());
                            }
                            Ok(Message::Close(_)) | Err(_) => break,
                            _ => {}
                        }
                    }
                }
            }
            Err(_) => {}
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}

/// How often batched log lines are handed to the UI, and how many lines one batch
/// may carry. sing-box logs every connection — in TUN mode that is thousands of lines
/// per second, and one event per line floods the webview (gigabytes of garbage).
const LOG_FLUSH: std::time::Duration = std::time::Duration::from_millis(300);
const LOG_BATCH_MAX: usize = 150;

/// Forward log frames in batches: at most one event per `LOG_FLUSH`, carrying at most
/// `LOG_BATCH_MAX` lines. Anything over that is dropped, with a line saying how much.
async fn pump_logs<S>(app: &AppHandle, read: &mut S)
where
    S: futures_util::Stream<Item = Result<Message, tokio_tungstenite::tungstenite::Error>>
        + Unpin,
{
    let mut batch: Vec<String> = Vec::new();
    let mut dropped = 0usize;
    let mut tick = tokio::time::interval(LOG_FLUSH);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            msg = read.next() => match msg {
                Some(Ok(Message::Text(text))) => {
                    if batch.len() < LOG_BATCH_MAX {
                        batch.push(text.to_string());
                    } else {
                        dropped += 1;
                    }
                }
                Some(Ok(_)) => {}
                Some(Err(_)) | None => break,
            },
            _ = tick.tick() => {
                if batch.is_empty() && dropped == 0 {
                    continue;
                }
                if dropped > 0 {
                    batch.push(
                        serde_json::json!({
                            "type": "warning",
                            "payload": format!("…пропущено строк лога: {dropped} (слишком быстрый поток)")
                        })
                        .to_string(),
                    );
                    dropped = 0;
                }
                let _ = app.emit(EVENT_LOG, format!("[{}]", batch.join(",")));
                batch.clear();
            }
        }
    }
}
