//! Connection monitor: detects a crashed core and an overwritten system proxy (every
//! few seconds) and does auto-failover between profiles.
//!
//! While the tunnel is up and "auto-switch" is enabled, periodically time a request
//! through the active proxy. After several consecutive failures, switch to the next
//! profile and restart the core. This recovers from a dead server/profile — it can't
//! fix a target site being down while the VPN itself is healthy (noted in the UI).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use parking_lot::Mutex;
use tauri::{AppHandle, Emitter, Manager};

use crate::clash::ClashStreams;
use crate::core::CoreState;
use crate::profiles::ProfileStore;
use crate::settings::SettingsStore;

const CHECK_INTERVAL_SECS: u64 = 15;
/// How often to check that the core is alive and the system proxy is still ours.
const WATCH_INTERVAL_SECS: u64 = 3;
const FAIL_THRESHOLD: u32 = 3;

#[derive(Default)]
pub struct Monitor {
    stop: Mutex<Option<Arc<AtomicBool>>>,
    handle: Mutex<Option<JoinHandle<()>>>,
}

impl Monitor {
    pub fn start(&self, app: AppHandle) {
        self.stop();
        let flag = Arc::new(AtomicBool::new(false));
        *self.stop.lock() = Some(flag.clone());
        let handle = std::thread::spawn(move || run_loop(app, flag));
        *self.handle.lock() = Some(handle);
    }

    pub fn stop(&self) {
        if let Some(flag) = self.stop.lock().take() {
            flag.store(true, Ordering::SeqCst);
        }
        if let Some(h) = self.handle.lock().take() {
            let _ = h.join();
        }
    }
}

/// Consecutive failed Clash API pings (every `WATCH_INTERVAL_SECS`) after which a core
/// that's still running is considered hung (~20 s).
const HANG_LIMIT: u32 = 6;
/// Consecutive failed requests through the built-in WireGuard tunnel (every
/// `CHECK_INTERVAL_SECS`) after which it's suspended (~45 s).
const WG_FAIL_LIMIT: u32 = 3;

#[derive(Default)]
struct Strikes {
    /// Clash API didn't answer; `pid` is the core it was counted for.
    hang: u32,
    pid: Option<u32>,
    /// Requests through the tunnel failed.
    wg: u32,
}

/// Re-plan the core off the monitor thread: `core::apply` stops the monitor (joins it),
/// so calling it from here would deadlock.
fn apply_detached(app: &AppHandle) {
    let app = app.clone();
    std::thread::spawn(move || {
        if let Err(e) = crate::core::apply(&app) {
            let _ = app.emit("app://error", e);
        }
    });
}

/// A core that runs but no longer answers (hung — e.g. the system stalled on disk I/O):
/// in TUN mode it holds all traffic hostage. Kill it: the TUN adapter and its routes go
/// away with the process and the system proxy is given back — the internet works again,
/// directly, and the user is told why.
fn watch_hang(app: &AppHandle, strikes: &mut Strikes) -> bool {
    let core = app.state::<CoreState>();
    let status = core.status();
    if !status.running || status.pid != strikes.pid {
        strikes.pid = status.pid;
        strikes.hang = 0;
        return false;
    }
    if crate::diag::clash_get("/version", 2000).is_some() {
        strikes.hang = 0;
        return false;
    }
    strikes.hang += 1;
    if strikes.hang < HANG_LIMIT {
        return false;
    }
    strikes.hang = 0;
    core.set_vpn(false);
    app.state::<ClashStreams>().stop();
    let _ = core.stop(app);
    crate::tray::set_state(app, "error");
    let _ = app.emit("vpn://state", "error".to_string());
    let _ = app.emit(
        "app://error",
        "Ядро не отвечало ~20 с и остановлено: TUN и системный прокси сняты, интернет идёт напрямую. Подключитесь снова, когда будете готовы.".to_string(),
    );
    true
}

/// The built-in tunnel: another copy of it showed up (the WireGuard app), or it stopped
/// answering while traffic is routed into it — suspend it so the internet / VPN keep
/// working without it, and say so.
fn watch_tunnel(app: &AppHandle, strikes: &mut Strikes) {
    let wg = app.state::<crate::wireguard::WgState>();
    if !wg.is_applied() || !app.state::<CoreState>().status().running {
        strikes.wg = 0;
        return;
    }
    if let Some(reason) = wg.check_conflict() {
        let _ = app.emit("app://error", format!("WireGuard: {reason}"));
        apply_detached(app);
        return;
    }
    // Only when internet traffic goes into the tunnel: a home-network-only tunnel can't
    // reach the test URL by design.
    if !crate::wireguard::internet_through_tunnel(app) {
        strikes.wg = 0;
        return;
    }
    let tag = ttcm_core::wireguard::WG_TAG;
    let ok = crate::diag::clash_delay_via(tag, "http://www.gstatic.com/generate_204", 5000).is_some();
    // The UI shows "connected" only from a check that answered.
    wg.set_health(ok);
    if ok {
        strikes.wg = 0;
        return;
    }
    strikes.wg += 1;
    if strikes.wg < WG_FAIL_LIMIT {
        return;
    }
    strikes.wg = 0;
    wg.suspend(
        "туннель не отвечал ~45 с — клиент временно работает без него (прямой трафик через провайдера). Нажмите «Подключить» у туннеля, чтобы попробовать снова.".to_string(),
    );
    let _ = app.emit(
        "app://error",
        "WireGuard: туннель не отвечает ~45 с — временно работаю без него, чтобы не пропал интернет. Нажмите «Подключить» у туннеля, чтобы попробовать снова.".to_string(),
    );
    apply_detached(app);
}

/// Core crashed → give the system proxy back and report; proxy overwritten → warn once.
fn watch(app: &AppHandle) {
    let core = app.state::<CoreState>();
    if core.died_unexpectedly() {
        app.state::<ClashStreams>().stop();
        let _ = core.stop(app); // releases the system proxy
        crate::tray::set_state(app, "error");
        let _ = app.emit("vpn://state", "error".to_string());
        let _ = app.emit(
            "app://error",
            "Ядро sing-box неожиданно завершилось — системный прокси возвращён. Причина — в строках лога выше.".to_string(),
        );
        return;
    }
    if let Some(current) = app.state::<crate::sysproxy::SysProxyState>().check_overwritten() {
        let _ = app.emit("sysproxy://overwritten", current.clone());
        let _ = app.emit(
            "app://error",
            format!("Системный прокси перезаписан другой программой (сейчас: {current}) — браузеры идут мимо VPN. Нажмите «Применить снова»."),
        );
    }
}

fn run_loop(app: AppHandle, stop: Arc<AtomicBool>) {
    let mut fails: u32 = 0;
    let mut tick: u64 = 0;
    let mut strikes = Strikes::default();
    loop {
        // Interruptible one-second ticks.
        if stop.load(Ordering::SeqCst) {
            return;
        }
        std::thread::sleep(Duration::from_secs(1));
        tick += 1;
        if tick % WATCH_INTERVAL_SECS == 0 {
            watch(&app);
            if watch_hang(&app, &mut strikes) {
                continue;
            }
        }
        // The tunnel is checked right after a (re)start too, so its status is known
        // within seconds instead of after the first full interval.
        if tick == 5 {
            watch_tunnel(&app, &mut strikes);
        }
        if tick % CHECK_INTERVAL_SECS != 0 {
            continue;
        }
        watch_tunnel(&app, &mut strikes);

        if !app.state::<CoreState>().vpn_connected() {
            continue;
        }
        if !app.state::<SettingsStore>().get().auto_switch_on() {
            fails = 0;
            continue;
        }

        let ok = crate::diag::clash_delay("http://www.gstatic.com/generate_204", 5000).is_some();
        if ok {
            fails = 0;
            continue;
        }

        fails += 1;
        if fails < FAIL_THRESHOLD {
            continue;
        }
        fails = 0;

        // Rotate to the next profile and restart the tunnel.
        let profiles = app.state::<ProfileStore>();
        if let Some(next) = profiles.next_active_id() {
            let name = profiles.name_of(&next).unwrap_or_else(|| next.clone());
            // Только в журнал: экспериментальная функция, без уведомлений.
            let _ = app.emit("app://log", format!("Автопереключение: активный профиль недоступен, переключаюсь на «{name}»"));
            profiles.set_active(&app, Some(next));
            app.state::<ClashStreams>().stop();
            match app.state::<CoreState>().restart(&app) {
                Ok(()) => {
                    app.state::<ClashStreams>().start(app.clone());
                    crate::tray::set_state(&app, "connected");
                    let _ = app.emit("vpn://state", "connected".to_string());
                }
                Err(e) => {
                    crate::tray::set_state(&app, "error");
                    let _ = app.emit("vpn://state", "error".to_string());
                    let _ = app.emit("app://error", format!("Не удалось переключиться на «{name}»: {e}"));
                }
            }
        }
    }
}
