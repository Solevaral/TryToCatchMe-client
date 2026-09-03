//! Clash API client.
//!
//! sing-box exposes a Clash-compatible controller (experimental.clash_api). We open
//! WebSocket streams to /traffic and /logs and forward each message to the UI via
//! Tauri events: `clash://traffic` ({up,down} bytes/s) and `clash://log`
//! ({type,payload}). Streams reconnect while the core is up; `stop` aborts them.

use futures_util::StreamExt;
use parking_lot::Mutex;
use tauri::{AppHandle, Emitter};
use tokio_tungstenite::tungstenite::Message;

use crate::config::CLASH_CONTROLLER;

pub const EVENT_TRAFFIC: &str = "clash://traffic";
pub const EVENT_LOG: &str = "clash://log";

#[derive(Default)]
pub struct ClashStreams {
    handles: Mutex<Vec<tauri::async_runtime::JoinHandle<()>>>,
}

impl ClashStreams {
    /// Start (or restart) the traffic + log streams.
    pub fn start(&self, app: AppHandle) {
        self.stop();
        let mut g = self.handles.lock();
        g.push(tauri::async_runtime::spawn(stream(
            app.clone(),
            format!("ws://{CLASH_CONTROLLER}/traffic"),
            EVENT_TRAFFIC,
        )));
        g.push(tauri::async_runtime::spawn(stream(
            app,
            format!("ws://{CLASH_CONTROLLER}/logs?level=info"),
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
            Err(_) => {}
        }
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
    }
}
