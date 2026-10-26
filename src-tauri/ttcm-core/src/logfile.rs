//! The app's log file: what the "Логи" tab shows (app messages, errors, core warnings
//! and errors), kept on disk so a crash or a reboot doesn't take the evidence with it.

/// Rotate when the file grows past this; one previous file is kept.
pub const MAX_BYTES: u64 = 2 * 1024 * 1024;

/// `2026-10-26 16:56:27.481Z` (UTC — no time-zone database here).
pub fn utc_stamp(unix_secs: u64, millis: u32) -> String {
    let days = (unix_secs / 86_400) as i64;
    let rem = unix_secs % 86_400;
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{millis:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Log lines for a UI event: `app://log` → `[app] …`, `app://error` → `[error] …`,
/// `clash://log` (one `{type, payload}` or a JSON array of them) → its warnings and
/// errors as `[core:<level>] …`. Per-connection info lines are left out (a flood in TUN).
pub fn lines_for_event(event: &str, payload: &str) -> Vec<String> {
    match event {
        "app://log" => vec![format!("[app] {payload}")],
        "app://error" => vec![format!("[error] {payload}")],
        "clash://log" => {
            let entries: Vec<serde_json::Value> = match serde_json::from_str::<serde_json::Value>(payload) {
                Ok(serde_json::Value::Array(a)) => a,
                Ok(v) => vec![v],
                Err(_) => return Vec::new(),
            };
            entries
                .iter()
                .filter_map(|e| {
                    let level = e["type"].as_str()?;
                    let text = e["payload"].as_str()?;
                    matches!(level, "warning" | "warn" | "error" | "fatal" | "panic")
                        .then(|| format!("[core:{level}] {text}"))
                })
                .collect()
        }
        _ => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stamps_are_utc_civil_time() {
        assert_eq!(utc_stamp(0, 0), "1970-01-01 00:00:00.000Z");
        // 2026-10-26 16:56:27 UTC
        assert_eq!(utc_stamp(1_793_033_787, 481), "2026-10-26 16:56:27.481Z");
        // Leap day.
        assert_eq!(utc_stamp(1_709_164_800, 7), "2024-02-29 00:00:00.007Z");
        assert_eq!(utc_stamp(951_782_399, 999), "2000-02-28 23:59:59.999Z");
    }

    #[test]
    fn events_become_log_lines() {
        assert_eq!(lines_for_event("app://log", "Ядро запущено"), ["[app] Ядро запущено"]);
        assert_eq!(lines_for_event("app://error", "boom"), ["[error] boom"]);
        assert!(lines_for_event("vpn://state", "connected").is_empty());
    }

    #[test]
    fn core_log_keeps_warnings_and_errors_only() {
        let single = r#"{"type":"error","payload":"FATAL start service"}"#;
        assert_eq!(lines_for_event("clash://log", single), ["[core:error] FATAL start service"]);
        let batch = r#"[{"type":"info","payload":"conn 1"},{"type":"warning","payload":"slow"},{"type":"error","payload":"dns: lookup failed"}]"#;
        assert_eq!(
            lines_for_event("clash://log", batch),
            ["[core:warning] slow", "[core:error] dns: lookup failed"]
        );
        assert!(lines_for_event("clash://log", "not json").is_empty());
    }
}
