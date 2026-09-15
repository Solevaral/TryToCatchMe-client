//! sing-box sidecar lifecycle management.
//!
//! Generates a config.json, spawns the sing-box process (`run -c config.json`),
//! waits for the Clash API controller to come up, and stops it gracefully.

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::Arc;
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
        app_log(app, format!("Ядро: {}", bin.display()));
        let work_dir = bin
            .parent()
            .map(PathBuf::from)
            .ok_or_else(|| "sing-box binary has no parent dir".to_string())?;

        let cfg_dir = app
            .path()
            .app_config_dir()
            .map_err(|e| format!("не найдена папка настроек: {e}"))?;
        fs::create_dir_all(&cfg_dir).map_err(|e| format!("не удалось создать папку настроек: {e}"))?;
        let cfg_path = cfg_dir.join("config.json");
        let cache_path = cfg_dir.join("cache.db").to_string_lossy().to_string();

        // Inject the active profile's outbound (if any) so traffic actually goes
        // through the selected server; otherwise fall back to direct-only.
        let profiles = app.state::<ProfileStore>();
        let proxy_outbound = profiles.active_outbound();
        match profiles.active_summary() {
            Some(s) => app_log(app, format!("Профиль: {s}")),
            None => app_log(app, "Профиль не выбран — весь трафик пойдёт напрямую".to_string()),
        }
        let spec = app.state::<RoutingStore>().route_spec();
        let settings = app.state::<crate::settings::SettingsStore>().get();
        let tun = settings.capture_tun;
        app_log(
            app,
            format!(
                "Перехват: {} · правил маршрутизации: {} · остальной трафик: {}",
                if tun { "TUN (весь трафик)" } else { "системный прокси" },
                spec.rules.len(),
                if proxy_outbound.is_some() { spec.final_action.as_str() } else { "direct" }
            ),
        );

        // TUN creates a virtual network adapter and needs administrator rights.
        // Ask the UI to relaunch elevated instead of failing cryptically.
        if tun && !crate::platform::is_elevated() {
            let _ = app.emit(
                "app://needs-admin",
                "Режим TUN требует прав администратора.".to_string(),
            );
            return Err(
                "Включён режим TUN, но приложение запущено без прав администратора. Перезапустите от имени администратора или переключите «Перехват трафика» на «Системный прокси».".to_string(),
            );
        }

        let mixed_addr = format!("{}:{}", config::MIXED_LISTEN, config::MIXED_PORT);
        ensure_port_free(CLASH_CONTROLLER, "Clash API")?;
        ensure_port_free(&mixed_addr, "локальный прокси")?;

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
        fs::write(&cfg_path, config::to_string(&cfg))
            .map_err(|e| format!("не удалось записать config.json: {e}"))?;
        app_log(app, format!("Конфиг: {}", cfg_path.display()));

        // Pre-flight: validate the config so a bad profile/rule surfaces the REAL
        // reason in the log instead of a generic "did not come up" after a hang.
        if let Err(err) = preflight_check(&bin, &work_dir, &cfg_path) {
            return Err(format!("sing-box отклонил конфигурацию: {err}"));
        }
        app_log(app, "Конфиг прошёл проверку, запускаю ядро…".to_string());

        // First attempt.
        let first_err = match self.spawn_and_wait(app, &bin, &work_dir, &cfg_path) {
            Ok(()) => {
                app_log(app, "Ядро запущено".to_string());
                return Ok(());
            }
            Err(e) => e,
        };

        // Fallback: a remote rule-set may be unavailable (e.g. a 404 or blocked
        // download), which makes sing-box abort at startup. Retry once WITHOUT geo
        // rule-sets — but only when that is actually what failed.
        let rule_set_failure = first_err.to_lowercase().contains("rule-set")
            || first_err.to_lowercase().contains("rule_set");
        if had_rule_sets && rule_set_failure {
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
                .map_err(|e| format!("не удалось записать config.json: {e}"))?;
            self.spawn_and_wait(app, &bin, &work_dir, &cfg_path)?;
            app_log(app, "Ядро запущено (без geo-списков)".to_string());
            return Ok(());
        }

        Err(first_err)
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
        let tail: LogTail = Arc::new(Mutex::new(Vec::new()));
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
                .map_err(|e| format!("не удалось запустить sing-box: {e}"))?;
            // Forward the core's own logs to the console (this is where startup
            // errors show up before the Clash API is even reachable).
            if let Some(out) = child.stdout.take() {
                pipe_logs(app.clone(), out, tail.clone());
            }
            if let Some(err) = child.stderr.take() {
                pipe_logs(app.clone(), err, tail.clone());
            }
            g.child = Some(child);
        }

        // Wait for the Clash API, but bail out immediately if the core exits.
        let deadline = Instant::now() + Duration::from_secs(10);
        let sock: std::net::SocketAddr = CLASH_CONTROLLER.parse().expect("valid controller addr");
        loop {
            // Take the status in its own statement so the lock guard is dropped
            // before we lock again below (parking_lot mutexes aren't reentrant).
            let exited = {
                let mut g = self.inner.lock();
                let status = g.child.as_mut().and_then(|c| c.try_wait().ok().flatten());
                if status.is_some() {
                    g.child = None;
                }
                status
            };
            if let Some(status) = exited {
                // Give the pipe readers a moment to flush the final lines.
                std::thread::sleep(Duration::from_millis(300));
                return Err(format!(
                    "ядро sing-box завершилось при запуске (код {}): {}",
                    status.code().map(|c| c.to_string()).unwrap_or_else(|| "?".into()),
                    summarize_tail(&tail)
                ));
            }
            if TcpStream::connect_timeout(&sock, Duration::from_millis(300)).is_ok() {
                return Ok(());
            }
            if Instant::now() >= deadline {
                break;
            }
            std::thread::sleep(Duration::from_millis(150));
        }

        // Roll back the process we just started.
        let mut g = self.inner.lock();
        if let Some(mut child) = g.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
        Err(format!(
            "ядро не ответило за 10 с: {}",
            summarize_tail(&tail)
        ))
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

type LogTail = Arc<Mutex<Vec<String>>>;

/// Informational step in the log console (so it's never empty on failure).
fn app_log(app: &AppHandle, msg: String) {
    let _ = app.emit("app://log", msg);
}

/// Fail early with a clear message if a port we need is taken by another program.
fn ensure_port_free(addr: &str, what: &str) -> Result<(), String> {
    std::net::TcpListener::bind(addr).map(|_| ()).map_err(|_| {
        format!("порт {addr} ({what}) занят другой программой — закройте её или другой VPN-клиент, использующий этот порт")
    })
}

/// The most useful lines from the core's output: FATAL/ERROR first, else the last line.
fn summarize_tail(tail: &LogTail) -> String {
    let lines = tail.lock();
    let errors: Vec<&String> = lines
        .iter()
        .filter(|l| {
            let u = l.to_uppercase();
            u.contains("FATAL") || u.contains("ERROR")
        })
        .collect();
    if !errors.is_empty() {
        return errors.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(" | ");
    }
    lines
        .last()
        .cloned()
        .unwrap_or_else(|| "ядро ничего не вывело".to_string())
}

/// Strip ANSI color codes sing-box puts in its console output.
fn strip_ansi(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            // Skip "ESC[ ... letter".
            if chars.peek() == Some(&'[') {
                chars.next();
                for n in chars.by_ref() {
                    if n.is_ascii_alphabetic() {
                        break;
                    }
                }
            }
            continue;
        }
        out.push(c);
    }
    out
}

/// Stream a child pipe line-by-line into the log console via the `clash://log` event,
/// keeping the last lines so a startup failure can quote the real reason.
fn pipe_logs<R: Read + Send + 'static>(app: AppHandle, reader: R, tail: LogTail) {
    std::thread::spawn(move || {
        let buf = BufReader::new(reader);
        for raw in buf.lines().map_while(Result::ok) {
            let line = strip_ansi(&raw);
            if line.trim().is_empty() {
                continue;
            }
            {
                let mut t = tail.lock();
                t.push(line.clone());
                if t.len() > 50 {
                    t.remove(0);
                }
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

/// Prevent a console window from flashing when spawning the child on Windows.
#[cfg(windows)]
fn no_window(cmd: &mut Command) {
    use std::os::windows::process::CommandExt;
    const CREATE_NO_WINDOW: u32 = 0x0800_0000;
    cmd.creation_flags(CREATE_NO_WINDOW);
}

#[cfg(not(windows))]
fn no_window(_cmd: &mut Command) {}
