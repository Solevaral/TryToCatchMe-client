//! Auto-failover monitor.
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

fn run_loop(app: AppHandle, stop: Arc<AtomicBool>) {
    let mut fails: u32 = 0;
    loop {
        // Interruptible sleep.
        for _ in 0..CHECK_INTERVAL_SECS {
            if stop.load(Ordering::SeqCst) {
                return;
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        if !app.state::<CoreState>().status().running {
            continue;
        }
        if !app.state::<SettingsStore>().get().auto_switch {
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
            let _ = app.emit(
                "app://error",
                format!("Активный профиль недоступен — переключаюсь на «{name}»"),
            );
            profiles.set_active(&app, Some(next));
            app.state::<ClashStreams>().stop();
            let _ = app.state::<CoreState>().restart(&app);
            app.state::<ClashStreams>().start(app.clone());
            let _ = app.emit("vpn://state", "connected".to_string());
        }
    }
}
