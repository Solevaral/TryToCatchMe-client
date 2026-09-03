//! sing-box sidecar lifecycle management.
//!
//! Generates a config.json, spawns the sing-box process (`run -c config.json`),
//! waits for the Clash API controller to come up, and stops it gracefully.

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};

use crate::config::{self, GenOptions, CLASH_CONTROLLER};
use crate::profiles::ProfileStore;
use crate::routing::RoutingStore;

#[derive(Default)]
pub struct CoreState {
    inner: Mutex<Inner>,
}

#[derive(Default)]
struct Inner {
    child: Option<Child>,
}

#[derive(Serialize, Clone)]
pub struct CoreStatus {
    pub running: bool,
    pub pid: Option<u32>,
}

impl CoreState {
    pub fn status(&self) -> CoreStatus {
        let mut g = self.inner.lock();
        // Reap the child if it exited on its own.
        let running = match g.child.as_mut() {
            Some(child) => match child.try_wait() {
                Ok(Some(_)) => {
                    g.child = None;
                    false
                }
                Ok(None) => true,
                Err(_) => true,
            },
            None => false,
        };
        CoreStatus {
            running,
            pid: g.child.as_ref().map(|c| c.id()),
        }
    }

    pub fn start(&self, app: &AppHandle) -> Result<(), String> {
        if self.inner.lock().child.is_some() {
            return Ok(());
        }

        let bin = resolve_singbox(app)?;
        let work_dir = bin
            .parent()
            .map(PathBuf::from)
            .ok_or_else(|| "sing-box binary has no parent dir".to_string())?;

        let cfg_dir = app
            .path()
            .app_config_dir()
            .map_err(|e| format!("no app config dir: {e}"))?;
        fs::create_dir_all(&cfg_dir).map_err(|e| format!("create config dir: {e}"))?;
        let cfg_path = cfg_dir.join("config.json");
        let cache_path = cfg_dir.join("cache.db").to_string_lossy().to_string();

        // Inject the active profile's outbound (if any) so traffic actually goes
        // through the selected server; otherwise fall back to direct-only.
        let proxy_outbound = app.state::<ProfileStore>().active_outbound();
        let spec = app.state::<RoutingStore>().route_spec();
        let settings = app.state::<crate::settings::SettingsStore>().get();
        let tun = settings.capture_tun;

        // TUN creates a virtual network adapter and needs administrator rights.
        // Ask the UI to relaunch elevated instead of failing cryptically.
        if tun && !crate::platform::is_elevated() {
            let _ = app.emit(
                "app://needs-admin",
                "Режим TUN требует прав администратора.".to_string(),
            );
            return Err("TUN mode requires administrator rights".to_string());
        }

        let had_rule_sets = !spec.rule_sets.is_empty();
        let opts = GenOptions {
            proxy_outbound: proxy_outbound.clone(),
            route_rules: spec.rules.clone(),
            rule_sets: spec.rule_sets.clone(),
            final_action: spec.final_action.clone(),
            dns_doh: settings.dns_doh,
            block_quic: settings.block_quic,
            cache_path: Some(cache_path.clone()),
            tun,
            ..GenOptions::default()
        };
        let cfg = config::generate(&opts);
        fs::write(&cfg_path, config::to_string(&cfg)).map_err(|e| format!("write config: {e}"))?;

        // Pre-flight: validate the config so a bad profile/rule surfaces the REAL
        // reason in the log instead of a generic "did not come up" after a hang.
        if let Err(err) = preflight_check(&bin, &work_dir, &cfg_path) {
            let _ = app.emit("app://error", format!("Ошибка конфигурации sing-box:\n{err}"));
            return Err(format!("config error: {err}"));
        }

        // First attempt.
        if self.spawn_and_wait(app, &bin, &work_dir, &cfg_path).is_ok() {
            return Ok(());
        }

        // Fallback: a remote rule-set may be unavailable (e.g. a 404), which makes
        // sing-box abort at startup. Retry once WITHOUT geo rule-sets so one broken
        // list can't block the whole tunnel — and tell the user via the log.
        if had_rule_sets {
            let _ = app.emit(
                "app://error",
                "Не удалось загрузить geosite/geoip списки — запускаю без них. Проверьте регион в «Маршрутизации».".to_string(),
            );
            // Drop the geo rule-sets and any rule that references one.
            let filtered_rules: Vec<_> = spec
                .rules
                .into_iter()
                .filter(|r| r.get("rule_set").is_none())
                .collect();
            let opts2 = GenOptions {
                proxy_outbound,
                route_rules: filtered_rules,
                rule_sets: Vec::new(),
                final_action: spec.final_action,
                dns_doh: settings.dns_doh,
                block_quic: settings.block_quic,
                cache_path: Some(cache_path.clone()),
                tun,
                ..GenOptions::default()
            };
            let cfg2 = config::generate(&opts2);
            fs::write(&cfg_path, config::to_string(&cfg2))
                .map_err(|e| format!("write config: {e}"))?;
            return self.spawn_and_wait(app, &bin, &work_dir, &cfg_path);
        }

        Err("sing-box started but Clash API did not come up".to_string())
    }

    /// Spawn sing-box, stream its stdout/stderr into the log console, and wait for
    /// the Clash API to come up. Rolls back (kills the child) if it doesn't.
    fn spawn_and_wait(
        &self,
        app: &AppHandle,
        bin: &PathBuf,
        work_dir: &PathBuf,
        cfg_path: &PathBuf,
    ) -> Result<(), String> {
        {
            let mut g = self.inner.lock();
            if g.child.is_some() {
                return Ok(());
            }
            // Working dir = binary dir so wintun.dll (TUN mode) resolves.
            let mut cmd = Command::new(bin);
            cmd.arg("run")
                .arg("-c")
                .arg(cfg_path)
                .current_dir(work_dir)
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            no_window(&mut cmd);
            let mut child = cmd
                .spawn()
                .map_err(|e| format!("failed to spawn sing-box: {e}"))?;
            // Forward the core's own logs to the console (this is where startup
            // errors show up before the Clash API is even reachable).
            if let Some(out) = child.stdout.take() {
                pipe_logs(app.clone(), out);
            }
            if let Some(err) = child.stderr.take() {
                pipe_logs(app.clone(), err);
            }
            g.child = Some(child);
        }

        if wait_for_controller(CLASH_CONTROLLER, Duration::from_secs(8)) {
            return Ok(());
        }
        // Roll back the process we just started.
        let mut g = self.inner.lock();
        if let Some(mut child) = g.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        Err("sing-box started but Clash API did not come up".to_string())
    }

    /// Stop then start with a freshly generated config (apply routing changes).
    pub fn restart(&self, app: &AppHandle) -> Result<(), String> {
        self.stop()?;
        self.start(app)
    }

    pub fn stop(&self) -> Result<(), String> {
        let mut g = self.inner.lock();
        if let Some(mut child) = g.child.take() {
            child.kill().map_err(|e| format!("kill sing-box: {e}"))?;
            let _ = child.wait();
        }
        Ok(())
    }
}

/// Validate the config with `sing-box check`. Returns the combined output on error.
fn preflight_check(bin: &PathBuf, work_dir: &PathBuf, cfg_path: &PathBuf) -> Result<(), String> {
    let mut cmd = Command::new(bin);
    cmd.arg("check").arg("-c").arg(cfg_path).current_dir(work_dir);
    no_window(&mut cmd);
    let out = cmd
        .output()
        .map_err(|e| format!("failed to run sing-box check: {e}"))?;
    if out.status.success() {
        return Ok(());
    }
    let mut msg = String::from_utf8_lossy(&out.stderr).to_string();
    msg.push_str(&String::from_utf8_lossy(&out.stdout));
    Err(msg.trim().to_string())
}

/// Stream a child pipe line-by-line into the log console via the `clash://log` event.
fn pipe_logs<R: Read + Send + 'static>(app: AppHandle, reader: R) {
    std::thread::spawn(move || {
        let buf = BufReader::new(reader);
        for line in buf.lines().map_while(Result::ok) {
            if line.trim().is_empty() {
                continue;
            }
            let upper = line.to_uppercase();
            let level = if upper.contains("FATAL") || upper.contains("ERROR") {
                "error"
            } else if upper.contains("WARN") {
                "warning"
            } else {
                "info"
            };
            let payload =
                serde_json::json!({ "type": level, "payload": line }).to_string();
            let _ = app.emit("clash://log", payload);
        }
    });
}

/// Resolve the sing-box binary: bundled resource first, dev source tree as fallback.
fn resolve_singbox(app: &AppHandle) -> Result<PathBuf, String> {
    let name = if cfg!(windows) {
        "binaries/sing-box.exe"
    } else {
        "binaries/sing-box"
    };
    if let Ok(p) = app.path().resolve(name, tauri::path::BaseDirectory::Resource) {
        if p.exists() {
            return Ok(p);
        }
    }
    // Dev fallback: src-tauri/binaries/... (path baked at compile time).
    let dev = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(name);
    if dev.exists() {
        return Ok(dev);
    }
    Err("sing-box binary not found (run scripts/fetch-core.ps1 or fetch-core.sh)".to_string())
}

/// Poll a TCP connect until it succeeds or the deadline passes.
fn wait_for_controller(addr: &str, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    let sock = match addr.parse() {
        Ok(s) => s,
        Err(_) => return false,
    };
    while Instant::now() < deadline {
        if TcpStream::connect_timeout(&sock, Duration::from_millis(300)).is_ok() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(150));
    }
    false
}

/// Prevent a console window from flashing when spawning the child on Windows.
#[cfg(windows)]
fn no_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn no_window(_cmd: &mut Command) {}
