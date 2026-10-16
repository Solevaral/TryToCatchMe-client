//! Tiny local HTTP server that hands out the PAC script (see `ttcm_core::pac`).
//!
//! Browsers and the desktop fetch the system proxy's PAC from a URL; Chromium-based
//! apps don't take `file://` PAC URLs, so it is served over HTTP on 127.0.0.1. The
//! listener lives for the app's lifetime; disconnecting swaps in a direct-only script.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

use parking_lot::{Mutex, RwLock};

use super::os::HOST;

#[derive(Default)]
pub struct PacServer {
    body: Arc<RwLock<String>>,
    port: Mutex<Option<u16>>,
}

impl PacServer {
    /// Serve `body` on `port` (bound once; later calls just swap the script).
    pub fn serve(&self, port: u16, body: String) -> Result<(), String> {
        *self.body.write() = body;
        let mut bound = self.port.lock();
        if *bound == Some(port) {
            return Ok(());
        }
        let listener = TcpListener::bind((HOST, port))
            .map_err(|e| format!("порт {HOST}:{port} для PAC занят: {e}"))?;
        let body = self.body.clone();
        std::thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let script = body.read().clone();
                let _ = respond(stream, &script);
            }
        });
        *bound = Some(port);
        Ok(())
    }

    /// Disconnected: anyone still holding the PAC URL goes direct.
    pub fn set_direct(&self) {
        *self.body.write() = ttcm_core::pac::direct_only();
    }
}

fn respond(mut s: TcpStream, script: &str) -> std::io::Result<()> {
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    let mut buf = [0u8; 4096];
    let _ = s.read(&mut buf);
    write!(
        s,
        "HTTP/1.1 200 OK\r\nContent-Type: application/x-ns-proxy-autoconfig\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        script.len()
    )?;
    s.write_all(script.as_bytes())
}
