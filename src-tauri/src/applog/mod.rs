//! The log file: everything the "Логи" tab shows that matters for a post-mortem (app
//! messages, errors, the core's warnings and errors), written as it happens so a crash
//! or a reboot doesn't take it away. `<app log dir>/trytocatchme.log`, rotated at
//! `MAX_BYTES` into `trytocatchme.1.log`.

use std::fs::{self, File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use parking_lot::Mutex;
use tauri::{AppHandle, Listener, Manager};
use ttcm_core::logfile::{lines_for_event, utc_stamp, MAX_BYTES};

struct Sink {
    path: PathBuf,
    file: Option<File>,
}

impl Sink {
    fn write(&mut self, lines: &[String]) {
        if lines.is_empty() {
            return;
        }
        if fs::metadata(&self.path).is_ok_and(|m| m.len() > MAX_BYTES) {
            self.file = None;
            let _ = fs::rename(&self.path, self.path.with_file_name("trytocatchme.1.log"));
        }
        if self.file.is_none() {
            self.file = OpenOptions::new().create(true).append(true).open(&self.path).ok();
        }
        let Some(f) = self.file.as_mut() else { return };
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
        let stamp = utc_stamp(now.as_secs(), now.subsec_millis());
        for l in lines {
            let _ = writeln!(f, "{stamp} {l}");
        }
        let _ = f.flush();
    }
}

/// The log file's path (for the UI / messages).
pub fn path(app: &AppHandle) -> Option<PathBuf> {
    app.path().app_log_dir().ok().map(|d| d.join("trytocatchme.log"))
}

/// Start writing the log file. Call once at startup.
pub fn init(app: &AppHandle) {
    let Some(path) = path(app) else { return };
    if let Some(dir) = path.parent() {
        let _ = fs::create_dir_all(dir);
    }
    let sink = std::sync::Arc::new(Mutex::new(Sink { path, file: None }));
    sink.lock().write(&[format!("[app] ---- TryToCatchMe {} запущен ----", env!("CARGO_PKG_VERSION"))]);
    for event in ["app://log", "app://error", "clash://log"] {
        let sink = sink.clone();
        app.listen_any(event, move |e| {
            // Payloads are JSON-encoded strings.
            let payload: String = serde_json::from_str(e.payload()).unwrap_or_else(|_| e.payload().to_string());
            sink.lock().write(&lines_for_event(event, &payload));
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempLog(PathBuf);

    impl TempLog {
        fn new() -> Self {
            let dir = std::env::temp_dir().join(format!("ttcm-log-test-{}", uuid::Uuid::new_v4()));
            fs::create_dir(&dir).unwrap();
            Self(dir)
        }
    }

    impl Drop for TempLog {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rotation_boundary_keeps_complete_unicode_lines() {
        let temp = TempLog::new();
        let path = temp.0.join("trytocatchme.log");
        fs::write(&path, vec![b'x'; MAX_BYTES as usize]).unwrap();
        let mut sink = Sink { path: path.clone(), file: None };
        sink.write(&["Ошибка 🇧🇾".into()]);
        let previous = temp.0.join("trytocatchme.1.log");
        assert!(!previous.exists());
        sink.write(&["Следующая строка".into()]);
        drop(sink);
        assert!(fs::read_to_string(previous).unwrap().ends_with("Ошибка 🇧🇾\n"));
        let current = fs::read_to_string(path).unwrap();
        assert!(current.ends_with("Следующая строка\n"));
        assert!(!current.contains("Ошибка"));
    }

    #[test]
    fn empty_batch_does_not_create_log_file() {
        let temp = TempLog::new();
        let path = temp.0.join("trytocatchme.log");
        Sink { path: path.clone(), file: None }.write(&[]);
        assert!(!path.exists());
    }
}
