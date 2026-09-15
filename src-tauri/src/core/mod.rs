//! sing-box sidecar lifecycle management.
//!
//! Generates a config.json, spawns the sing-box process (`run -c config.json`),
//! waits for the Clash API controller to come up, applies/releases the OS system proxy
//! and keeps geo lists downloaded.

use std::fs;
use std::io::{BufRead, BufReader, Read};
use std::net::TcpStream;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use parking_lot::Mutex;
use serde::Serialize;
use tauri::{AppHandle, Emitter, Manager};

use crate::clash::ClashStreams;
use crate::config::{self, geo_port, GenOptions, CLASH_CONTROLLER, MIXED_LISTEN};
use crate::sysproxy::SysProxyState;
use crate::profiles::ProfileStore;
use crate::routing::RoutingStore;
use ttcm_core::routing::{profile_tag, service_geo_file, GeoFile, GeoInput};

#[derive(Default)]
pub struct CoreState {
    inner: Mutex<Inner>,
    /// The core is supposed to be running (set on successful start, cleared on stop).
    expected: AtomicBool,
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

        // Inject the active profile's outbound (if any) so traffic actually goes
        // through the selected server; otherwise fall back to direct-only.
        let profiles = app.state::<ProfileStore>();
        let proxy_outbound = profiles.active_outbound();
        match profiles.active_summary() {
            Some(s) => app_log(app, format!("Профиль: {s}")),
            None => app_log(app, "Профиль не выбран — весь трафик пойдёт напрямую".to_string()),
        }
        let settings = app.state::<crate::settings::SettingsStore>().get();
        let tun = settings.capture_tun;
        let port = settings.proxy_port;

        // Geo lists (region + lists backing services) are local files the app downloads
        // itself; missing ones are simply left out and downloaded after connecting.
        let routing = app.state::<RoutingStore>();
        let plan = routing.plan();
        let geo_files = plan.files();
        let geo_dir = crate::geo::dir(app).map(|d| d.to_string_lossy().to_string()).unwrap_or_default();
        let region_ready = crate::geo::all_present(app, &plan.region_files());
        let service_ready: Vec<String> = plan
            .service_geosites
            .iter()
            .filter(|n| crate::geo::present(app, &service_geo_file(n)))
            .cloned()
            .collect();
        let missing: Vec<String> = geo_files
            .iter()
            .filter(|f| !crate::geo::present(app, f))
            .map(|f| f.file_name.clone())
            .collect();
        if !geo_files.is_empty() {
            if missing.is_empty() {
                app_log(app, format!("Гео-списки: загружены ({} шт.)", geo_files.len()));
            } else {
                app_log(
                    app,
                    format!("Гео-списки ещё не скачаны ({}) — подключаюсь без них и скачаю после подключения", missing.join(", ")),
                );
            }
        }
        let geo_input = GeoInput { dir: &geo_dir, region_ready, geosites: &service_ready };
        let spec = routing.route_spec(Some(&geo_input));

        // Services pinned to other profiles get their own outbounds.
        let active_id = profiles.active_id();
        let mut extra_outbounds = Vec::new();
        for pid in &plan.pinned_profiles {
            if Some(pid) == active_id.as_ref() {
                continue; // same server as the active profile: the rule falls back to it
            }
            match profiles.outbound_of(pid, &profile_tag(pid)) {
                Some(ob) => {
                    app_log(
                        app,
                        format!("Отдельный сервер для сервиса: «{}»", profiles.name_of(pid).unwrap_or_default()),
                    );
                    extra_outbounds.push(ob);
                }
                None => app_error(
                    app,
                    "Сервис закреплён за удалённым профилем — он пойдёт через активный профиль".to_string(),
                ),
            }
        }

        // Another VPN client fights over the system proxy / routes; tests "through
        // TryToCatchMe" then silently go through it.
        let others = crate::platform::running_vpn_clients();
        if !others.is_empty() {
            app_error(
                app,
                format!(
                    "Запущен другой VPN-клиент: {}. Он может перехватывать системный прокси и маршруты — трафик пойдёт через него. Для корректной работы закройте его.",
                    others.join(", ")
                ),
            );
        }
        app_log(
            app,
            format!(
                "Перехват: {} · правил маршрутизации: {} · остальной трафик: {}",
                if tun { "TUN (весь трафик)".to_string() } else { format!("системный прокси {MIXED_LISTEN}:{port}") },
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

        ensure_port_free(CLASH_CONTROLLER, "Clash API")?;
        ensure_port_free(&format!("{MIXED_LISTEN}:{port}"), "локальный прокси")?;
        if proxy_outbound.is_some() {
            ensure_port_free(
                &format!("{MIXED_LISTEN}:{}", geo_port(port)),
                "служебный порт загрузки гео-списков (порт прокси + 1)",
            )?;
        }

        let options = |route_rules: Vec<serde_json::Value>, rule_sets: Vec<serde_json::Value>| GenOptions {
            mixed_port: port,
            proxy_outbound: proxy_outbound.clone(),
            extra_outbounds: extra_outbounds.clone(),
            route_rules,
            rule_sets,
            final_action: spec.final_action.clone(),
            dns_doh: settings.dns_doh,
            block_quic: settings.block_quic,
            tun,
            ..GenOptions::default()
        };
        let write_cfg = |opts: &GenOptions| -> Result<(), String> {
            fs::write(&cfg_path, config::to_string(&config::generate(opts)))
                .map_err(|e| format!("не удалось записать config.json: {e}"))
        };
        write_cfg(&options(spec.rules.clone(), spec.rule_sets.clone()))?;
        app_log(app, format!("Конфиг: {}", cfg_path.display()));

        // Pre-flight (`sing-box check`) surfaces the REAL reason for a bad profile/rule
        // instead of a generic "did not come up"; then spawn and wait for the core.
        let check_and_spawn = || -> Result<(), String> {
            preflight_check(&bin, &work_dir, &cfg_path)
                .map_err(|err| format!("sing-box отклонил конфигурацию: {err}"))?;
            app_log(app, "Конфиг прошёл проверку, запускаю ядро…".to_string());
            self.spawn_and_wait(app, &bin, &work_dir, &cfg_path)
        };

        let mut geo_missing = !missing.is_empty();
        match check_and_spawn() {
            Ok(()) => {}
            Err(e) if !spec.rule_sets.is_empty() && e.to_lowercase().contains("rule-set") => {
                // A downloaded list is unreadable (check or run rejected it): drop the
                // lists, run without them, and re-download after connecting.
                app_error(app, format!("Сохранённые гео-списки повреждены — удаляю и запускаюсь без них ({e})"));
                crate::geo::remove(app, &geo_files);
                let rules = spec.rules.iter().filter(|r| r.get("rule_set").is_none()).cloned().collect();
                write_cfg(&options(rules, Vec::new()))?;
                check_and_spawn()?;
                geo_missing = true;
            }
            Err(e) => return Err(e),
        }
        app_log(app, "Ядро запущено".to_string());
        self.expected.store(true, Ordering::SeqCst);

        // The app — not sing-box — owns the OS system proxy (see crate::sysproxy).
        // In TUN mode too: apps that read the system proxy (Electron apps like Claude
        // Desktop, browsers) connect to whatever it points at, and a proxy left by
        // another client (e.g. Hiddify) would send them past the tunnel entirely.
        match app.state::<SysProxyState>().apply(app, port) {
            Ok(()) if tun => app_log(app, format!("Системный прокси тоже направлен в VPN: {MIXED_LISTEN}:{port} (программы, читающие прокси, не уйдут мимо TUN)")),
            Ok(()) => app_log(app, format!("Системный прокси включён: {MIXED_LISTEN}:{port}")),
            Err(e) if tun => app_error(
                app,
                format!("TUN работает, но системный прокси перенаправить не удалось: {e}. Программы, использующие системный прокси, могут идти мимо VPN."),
            ),
            Err(e) => app_error(
                app,
                format!("Ядро работает, но включить системный прокси не удалось: {e}. Укажите вручную {MIXED_LISTEN}:{port}."),
            ),
        }

        if proxy_outbound.is_some() {
            let pinned: Vec<String> = extra_outbounds
                .iter()
                .filter_map(|o| o["tag"].as_str().map(str::to_string))
                .collect();
            warm_up(app, pinned);
        }
        if !geo_files.is_empty() {
            schedule_geo(app, geo_files, proxy_outbound.is_some().then_some(port), geo_missing);
        }
        Ok(())
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
        self.stop(app)?;
        self.start(app)
    }

    /// Stop the core and give the system proxy back. sing-box is hard-killed (there is
    /// no graceful stop signal on Windows), which is exactly why the app — not sing-box —
    /// owns the system proxy: the kill can no longer leave it pointing at a dead port.
    pub fn stop(&self, app: &AppHandle) -> Result<(), String> {
        self.expected.store(false, Ordering::SeqCst);
        let killed = {
            let mut g = self.inner.lock();
            match g.child.take() {
                Some(mut child) => {
                    let r = child.kill().map_err(|e| format!("не удалось остановить sing-box: {e}"));
                    let _ = child.wait();
                    r
                }
                None => Ok(()),
            }
        };
        if let Some(msg) = app.state::<SysProxyState>().release(app) {
            app_log(app, msg);
        }
        killed
    }

    /// True when the core should be running but its process is gone (crashed).
    pub fn died_unexpectedly(&self) -> bool {
        self.expected.load(Ordering::SeqCst) && !self.status().running
    }
}

/// The first request over some transports (e.g. gRPC + Reality) takes several seconds
/// while the connection is set up. Open the tunnel right away so the user's first page
/// doesn't hang, and tell the UI when it's ready (or that it isn't passing traffic).
fn warm_up(app: &AppHandle, pinned_tags: Vec<String>) {
    // Servers that services are pinned to pay the same first-connection cost.
    for tag in pinned_tags {
        std::thread::spawn(move || {
            let _ = crate::diag::clash_delay_via(&tag, "http://www.gstatic.com/generate_204", 15000);
        });
    }
    let app = app.clone();
    std::thread::spawn(move || {
        let _ = app.emit("vpn://warm", "start".to_string());
        let started = Instant::now();
        let deadline = started + Duration::from_secs(30);
        while Instant::now() < deadline {
            if !app.state::<CoreState>().status().running {
                let _ = app.emit("vpn://warm", "done".to_string());
                return;
            }
            if crate::diag::clash_delay("http://www.gstatic.com/generate_204", 8000).is_some() {
                app_log(&app, format!("Туннель готов (прогрев {:.1} с)", started.elapsed().as_secs_f32()));
                let _ = app.emit("vpn://warm", "done".to_string());
                return;
            }
            std::thread::sleep(Duration::from_millis(500));
        }
        let _ = app.emit("vpn://warm", "fail".to_string());
        app_error(
            &app,
            "Туннель поднят, но трафик через сервер не проходит уже 30 с — проверьте профиль (сервер может не работать) или запустите «Диагностику».".to_string(),
        );
    });
}

/// Download geo lists after connecting: when missing (then restart to apply them) or
/// when older than a day (applied on the next connect, no interruption).
fn schedule_geo(app: &AppHandle, files: Vec<GeoFile>, vpn_port: Option<u16>, missing: bool) {
    let stale = crate::geo::oldest_age(app, &files).map(|a| a > crate::geo::MAX_AGE).unwrap_or(true);
    if !missing && !stale {
        return;
    }
    let app = app.clone();
    tauri::async_runtime::spawn(async move {
        app_log(&app, format!("Скачиваю гео-списки ({} шт.)…", files.len()));
        match crate::geo::download(&app, &files, vpn_port).await {
            Ok(how) if missing => {
                app_log(&app, format!("Гео-списки скачаны ({how}) — перезапускаю туннель, чтобы применить их"));
                let app2 = app.clone();
                let _ = tauri::async_runtime::spawn_blocking(move || {
                    let core = app2.state::<CoreState>();
                    if !core.status().running {
                        return;
                    }
                    app2.state::<ClashStreams>().stop();
                    match core.restart(&app2) {
                        Ok(()) => app2.state::<ClashStreams>().start(app2.clone()),
                        Err(e) => {
                            crate::tray::set_state(&app2, "error");
                            let _ = app2.emit("vpn://state", "error".to_string());
                            app_error(&app2, format!("Не удалось перезапустить туннель после загрузки списков: {e}"));
                        }
                    }
                })
                .await;
            }
            Ok(how) => app_log(&app, format!("Гео-списки обновлены ({how}) — применятся при следующем подключении")),
            Err(e) => app_error(
                &app,
                format!(
                    "Не удалось скачать гео-списки: {e}. {}",
                    if missing { "Работаю без них." } else { "Использую сохранённые." }
                ),
            ),
        }
    });
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

/// Error line in the log console (also shown under the connection status).
fn app_error(app: &AppHandle, msg: String) {
    let _ = app.emit("app://error", msg);
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
