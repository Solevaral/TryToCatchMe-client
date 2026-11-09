//! Connection monitor: detects a crashed core and an overwritten system proxy (every
//! few seconds) and does auto-failover between profiles.
//!
//! While the tunnel is up and "auto-switch" is enabled, periodically time a request
//! through the active proxy. After several consecutive failures, switch to the next
//! profile and restart the core. This recovers from a dead server/profile — it can't
//! fix a target site being down while the VPN itself is healthy (noted in the UI).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
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
}

impl Monitor {
    pub fn start(&self, app: AppHandle) {
        let mut owner = self.stop.lock();
        if let Some(old) = owner.take() { old.store(true, Ordering::SeqCst); }
        let flag = Arc::new(AtomicBool::new(false));
        *owner = Some(flag.clone());
        let watcher_app = app.clone();
        let watcher_flag = flag.clone();
        std::thread::spawn(move || {
            let mut reported = false;
            while !watcher_flag.load(Ordering::SeqCst) {
                std::thread::sleep(Duration::from_secs(WATCH_INTERVAL_SECS));
                if watcher_flag.load(Ordering::SeqCst) { return; }
                // Independent of slow health probes. Cleanup stays in the operation loop.
                if watcher_app.state::<CoreState>().died_unexpectedly() && !reported {
                    reported = true;
                    crate::tray::set_state(&watcher_app, "error");
                    let _ = watcher_app.emit("vpn://state", "error");
                    let _ = watcher_app.emit("core://status", watcher_app.state::<CoreState>().status());
                } else if watcher_app.state::<CoreState>().status().running {
                    reported = false;
                }
            }
        });
        std::thread::spawn(move || run_loop(app, flag));
    }

    pub fn stop(&self) {
        // Detached worker checks cancellation after acquiring op. Never join under op.
        if let Some(flag) = self.stop.lock().take() {
            flag.store(true, Ordering::SeqCst);
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
    /// Tunnel checks so far: the conflict check (a PowerShell query) runs on every 4th
    /// one, i.e. right after a start and then once a minute.
    wg_checks: u32,
}

/// Re-plan after releasing the monitor operation guard. Apply owns the next worker.
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
    strikes.wg_checks += 1;
    if strikes.wg_checks % 4 == 1 {
        if let Some(reason) = wg.check_conflict() {
            let _ = app.emit("app://error", format!("WireGuard: {reason}"));
            apply_detached(app);
            return;
        }
    }
    // Internet through the tunnel: a test URL; only its own networks: hosts behind it.
    // The UI shows "connected" only from a check that answered.
    let was = wg.alive();
    let check = crate::wireguard::check_tunnel(app);
    let Some(ok) = check.ok else {
        strikes.wg = 0;
        return;
    };
    // The change goes to the log, once (not every 15 s).
    if was != Some(ok) && (was.is_some() || !ok) {
        let line = format!("WireGuard: {}", check.text);
        let _ = app.emit("app://log", line);
    }
    if ok {
        strikes.wg = 0;
        return;
    }
    // A home-network-only tunnel being down doesn't touch the internet: keep it (it
    // comes back by itself when the server does), just show it.
    if !check.internet {
        strikes.wg = 0;
        return;
    }
    strikes.wg += 1;
    if strikes.wg < WG_FAIL_LIMIT {
        return;
    }
    strikes.wg = 0;
    wg.suspend(
        "туннель не отвечал ~45 с — клиент временно работает без него (прямой трафик через провайдера). Нажмите «Подключить снова» у туннеля на вкладке WireGuard.".to_string(),
    );
    let _ = app.emit(
        "app://error",
        "WireGuard: туннель не отвечает ~45 с — временно работаю без него, чтобы не пропал интернет. Нажмите «Подключить снова» у туннеля на вкладке WireGuard.".to_string(),
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
            "Ядро sing-box неожиданно завершилось. Результат восстановления системного прокси и причина завершения — в журнале.".to_string(),
        );
        return;
    }
    if let Some(current) = app.state::<crate::sysproxy::SysProxyState>().check_overwritten() {
        crate::tray::set_state(app, "degraded");
        let _ = app.emit("sysproxy://overwritten", current.clone());
        let _ = app.emit(
            "app://error",
            format!("Системный прокси изменён или недоступен для проверки (сейчас: {current}). Перехват через него не подтверждён. Нажмите «Применить снова»."),
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
        let core = app.state::<CoreState>();
        tick += 1;
        if tick % WATCH_INTERVAL_SECS == 0 {
            // The op guard covers only quick state actions, never a network probe: a
            // held guard would make Disconnect / Apply wait for the probe.
            {
                let Some(_operation) = core.op.try_lock() else { continue };
                if stop.load(Ordering::SeqCst) { return; }
                watch(&app);
            }
            core.refresh_capture(&app);
            let status = core.status();
            let _ = app.emit("core://status", status.clone());
            if status.vpn && (status.capture_up != Some(true) || status.health != Some(true)) { crate::tray::set_state(&app, "degraded"); }
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
        let ok = crate::diag::clash_delay("http://www.gstatic.com/generate_204", 5000).is_some();
        if stop.load(Ordering::SeqCst) { return; }
        core.record_health(&app, ok);
        if ok {
            fails = 0;
            continue;
        }

        if !app.state::<SettingsStore>().get().auto_switch_on() { fails = 0; continue; }
        fails += 1;
        if !failover_due(stop.load(Ordering::SeqCst), app.state::<SettingsStore>().get().auto_switch_on(), fails) {
            continue;
        }
        fails = 0;

        // Rotate to the next profile and restart the tunnel.
        // Held through set_active + restart (re-entrant); re-check cancellation under it so
        // a monitor stopped by the user's Disconnect never restarts the core.
        let _operation = core.op.lock();
        if stop.load(Ordering::SeqCst) || !core.vpn_connected() { return; }
        let profiles = app.state::<ProfileStore>();
        if let Some(next) = profiles.next_active_id() {
            let name = profiles.name_of(&next).unwrap_or_else(|| next.clone());
            // Только в журнал: экспериментальная функция, без уведомлений.
            let _ = app.emit("app://log", format!("Автопереключение: активный профиль недоступен, переключаюсь на «{name}»"));
            if let Err(e) = profiles.set_active(&app, Some(next)) {
                let _ = app.emit("app://error", e);
                continue;
            }
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

fn failover_due(cancelled: bool, enabled: bool, failures: u32) -> bool {
    !cancelled && enabled && failures >= FAIL_THRESHOLD
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cancelled_monitor_never_requests_failover() {
        for cancelled in [false, true] {
            for enabled in [false, true] {
                for failures in [0, FAIL_THRESHOLD - 1, FAIL_THRESHOLD, FAIL_THRESHOLD + 1] {
                    assert_eq!(failover_due(cancelled, enabled, failures), !cancelled && enabled && failures >= FAIL_THRESHOLD);
                }
            }
        }
    }
}
