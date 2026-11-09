//! «Пинг» on the Profiles page: every profile tested for real, through its own server.
//!
//! A TCP connect to the server (the old ping) says nothing about the VPN working — and
//! in TUN mode it went through the active VPN itself. Instead a short-lived second
//! sing-box gets every profile as an outbound, all bound to the physical network adapter
//! (so neither the running core's TUN nor its proxy is in the path), and times a request
//! through each one via its own Clash API: Google (what most blocks break) and
//! Cloudflare (to tell "server dead" from "server up, Google unreachable through it").
//! The user's running core is never touched.

use std::collections::HashMap;
use std::io::Read;
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use tauri::{AppHandle, Manager};
use ttcm_core::pingall::{self, PingResult};

use crate::profiles::ProfileStore;

const GOOGLE: &str = "http://www.gstatic.com/generate_204";
const CLOUDFLARE: &str = "http://cp.cloudflare.com/generate_204";
const TEST_TIMEOUT_MS: u64 = 6000;
const START_TIMEOUT: Duration = Duration::from_secs(8);

static BUSY: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// The test core: killed (by its own handle — never by name) and its config removed
/// when dropped, whatever happens.
struct TestCore {
    child: Child,
    config: std::path::PathBuf,
}

impl Drop for TestCore {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_file(&self.config);
    }
}

fn free_port() -> Result<u16, String> {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|l| l.local_addr())
        .map(|a| a.port())
        .map_err(|e| format!("нет свободного порта: {e}"))
}

#[tauri::command]
pub async fn profiles_ping_all(app: AppHandle) -> Result<HashMap<String, PingResult>, String> {
    if BUSY.swap(true, std::sync::atomic::Ordering::SeqCst) {
        return Err("проверка уже идёт".into());
    }
    let r = tauri::async_runtime::spawn_blocking(move || run(&app))
        .await
        .map_err(|e| format!("внутренняя ошибка: {e}"))
        .and_then(|r| r);
    BUSY.store(false, std::sync::atomic::Ordering::SeqCst);
    r
}

fn run(app: &AppHandle) -> Result<HashMap<String, PingResult>, String> {
    let profiles = app.state::<ProfileStore>().list();
    if profiles.is_empty() {
        return Ok(HashMap::new());
    }
    // The physical adapter, or no test at all: an unbound test could go through the
    // active VPN and show its result for every profile.
    let uplink = crate::diag::physical_uplink().ok_or(
        "не найден физический сетевой адаптер с выходом в интернет — без него проверка пошла бы через VPN",
    )?;
    let port = free_port()?;
    let outbounds: Vec<_> = profiles.iter().map(|p| p.outbound.clone()).collect();
    let config = pingall::build_test_config(&outbounds, Some(&uplink), port);
    let path = std::env::temp_dir().join(format!("ttcm-ping-{}-{port}.json", std::process::id()));
    std::fs::write(&path, serde_json::to_vec(&config).map_err(|e| e.to_string())?)
        .map_err(|e| format!("не удалось записать конфиг проверки: {e}"))?;

    let mut cmd = Command::new(crate::core::resolve_singbox(app)?);
    cmd.arg("run").arg("-c").arg(&path).stdin(Stdio::null()).stdout(Stdio::null()).stderr(Stdio::piped());
    crate::core::no_window(&mut cmd);
    let child = cmd.spawn().map_err(|e| {
        let _ = std::fs::remove_file(&path);
        format!("не удалось запустить проверочное ядро: {e}")
    })?;
    let mut core = TestCore { child, config: path };

    // Wait for its Clash API; an early exit means the config was rejected.
    let controller = format!("127.0.0.1:{port}");
    let started = Instant::now();
    loop {
        if crate::diag::http_get_at(&controller, "/version", 500).is_some() {
            break;
        }
        if let Ok(Some(_)) = core.child.try_wait() {
            let mut err = String::new();
            if let Some(mut e) = core.child.stderr.take() {
                let _ = e.read_to_string(&mut err);
            }
            let line = err.lines().rev().find(|l| !l.trim().is_empty()).unwrap_or("").to_string();
            return Err(format!("проверочное ядро не запустилось: {line}"));
        }
        if started.elapsed() > START_TIMEOUT {
            return Err("проверочное ядро не ответило за 8 с".into());
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // Every profile at once, Google and Cloudflare in parallel.
    let handles: Vec<_> = profiles
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let tag = pingall::test_tag(i);
            let id = p.id.clone();
            let c = controller.clone();
            std::thread::spawn(move || {
                let cf = {
                    let (c, tag) = (c.clone(), tag.clone());
                    std::thread::spawn(move || crate::diag::clash_delay_at(&c, &tag, CLOUDFLARE, TEST_TIMEOUT_MS))
                };
                let google = crate::diag::clash_delay_at(&c, &tag, GOOGLE, TEST_TIMEOUT_MS);
                let cf = cf.join().ok().flatten();
                (id, pingall::classify(google, cf))
            })
        })
        .collect();
    let results = handles.into_iter().filter_map(|h| h.join().ok()).collect();
    drop(core);
    Ok(results)
}
