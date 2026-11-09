//! The app's log file: what the "Логи" tab shows (app messages, errors, core warnings
//! and errors), kept on disk so a crash or a reboot doesn't take the evidence with it.

use std::net::SocketAddr;

/// Recognize only known harmless failures, preserving other diagnostic details.
pub fn is_noise(text: &str, probe_targets: &[SocketAddr]) -> bool {
    let text = text.to_ascii_lowercase();
    if ["nxdomain", "i/o timeout", "tls", "handshake", "reality"].iter().any(|signal| text.contains(signal)) {
        return false;
    }
    let dns = text.contains("dns: lookup failed for ") || text.contains("router: lookup ");
    if dns && text.ends_with(": empty result") {
        return true;
    }
    let closed = text.contains("upload closed: ") || text.contains("download closed: ");
    if closed && [
        "an existing connection was forcibly closed by the remote host.",
        "connection reset by peer", "broken pipe", "use of closed network connection", ": eof",
    ].iter().any(|reason| text.ends_with(reason)) {
        return true;
    }
    let Some((_, connection)) = text.split_once("connection: open connection to ") else {
        return false;
    };
    let Some((target, detail)) = connection.split_once(" using outbound/wireguard[wg]: connect tcp ") else {
        return false;
    };
    let Some((dial_target, reason)) = detail.split_once(": ") else { return false };
    matches!(reason, "connection was refused" | "connection refused")
        && target == dial_target
        && target.parse::<SocketAddr>().is_ok_and(|a| probe_targets.contains(&a))
}

/// Filter both single entries and batches before forwarding them to the UI or file.
pub fn filter_core_entries(payload: &str, probe_targets: &[SocketAddr]) -> (Vec<serde_json::Value>, u64) {
    let entries = match serde_json::from_str::<serde_json::Value>(payload) {
        Ok(serde_json::Value::Array(entries)) => entries,
        Ok(entry) => vec![entry],
        Err(_) => return (Vec::new(), 0),
    };
    let mut hidden = 0;
    let entries = entries.into_iter().filter(|entry| {
        let (Some(_), Some(text)) = (entry["type"].as_str(), entry["payload"].as_str()) else {
            return false;
        };
        if is_noise(text, probe_targets) {
            hidden += 1;
            return false;
        }
        true
    }).collect();
    (entries, hidden)
}

/// Ten-minute accounting using monotonic seconds supplied by the caller.
pub struct NoiseCounter {
    since: u64,
    hidden: u64,
}

impl NoiseCounter {
    pub fn new(now: u64) -> Self { Self { since: now, hidden: 0 } }

    pub fn record(&mut self, count: u64) { self.hidden = self.hidden.saturating_add(count); }

    pub fn flush(&mut self, now: u64) -> Option<String> {
        if now.saturating_sub(self.since) < 600 {
            return None;
        }
        self.since = now;
        let count = std::mem::take(&mut self.hidden);
        (count > 0).then(|| format!("Скрыто типовых сообщений ядра за 10 мин: {count} (IPv6-запросы в режиме «только IPv4», обрывы соединений клиентом, проверки WireGuard)"))
    }
}

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
    lines_for_event_with_targets(event, payload, &[])
}

pub fn lines_for_event_with_targets(event: &str, payload: &str, probe_targets: &[SocketAddr]) -> Vec<String> {
    match event {
        "app://log" => vec![format!("[app] {payload}")],
        "app://error" => vec![format!("[error] {payload}")],
        "clash://log" => {
            let (entries, _) = filter_core_entries(payload, probe_targets);
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
    fn known_dns_and_established_connection_noise_is_hidden() {
        for text in [
            "dns: lookup failed for ipv6.msftconnecttest.com: empty result",
            "router: lookup ipv6.msftconnecttest.com: empty result",
            "dns: lookup failed for brunhild.challenges.cloudflare.com: empty result",
            "router: lookup brunhild.challenges.cloudflare.com: empty result",
            "connection: connection upload closed: raw-read tcp 127.0.0.1:2080->127.0.0.1:62765: An existing connection was forcibly closed by the remote host.",
            "connection: connection download closed: raw-read tcp 192.168.31.132:64205->4.150.223.112:443: An existing connection was forcibly closed by the remote host.",
            "ERROR [123 1s] connection: connection upload closed: write tcp: connection reset by peer",
            "connection: connection download closed: write tcp: broken pipe",
            "connection: connection upload closed: use of closed network connection",
            "connection: connection download closed: EOF",
        ] {
            assert!(is_noise(text, &[]), "{text}");
        }
    }

    #[test]
    fn refused_wireguard_connections_require_an_exact_probe_target() {
        let targets = ["10.6.0.1:80".parse().unwrap(), "192.168.20.1:443".parse().unwrap(), "[fd00::1]:80".parse().unwrap()];
        for target in targets {
            let text = format!("connection: open connection to {target} using outbound/wireguard[wg]: connect tcp {target}: connection was refused");
            assert!(is_noise(&text, &targets));
            assert!(!is_noise(&text, &[]));
            assert!(lines_for_event_with_targets("clash://log", &serde_json::json!({"type": "error", "payload": text}).to_string(), &targets).is_empty());
        }
        for text in [
            "connection: open connection to 10.6.0.1:443 using outbound/wireguard[wg]: connect tcp 10.6.0.1:443: connection was refused",
            "connection: open connection to 110.6.0.1:80 using outbound/wireguard[wg]: connect tcp 110.6.0.1:80: connection was refused",
            "connection: open connection to 10.6.0.1:80 using outbound/direct[direct]: connect tcp 10.6.0.1:80: connection was refused",
            "connection: open connection to 10.6.0.1:80 using outbound/wireguard[wg]: connect tcp 10.6.0.2:80: connection was refused",
        ] {
            assert!(!is_noise(text, &targets), "{text}");
        }
    }

    #[test]
    fn diagnostic_errors_are_preserved() {
        for text in [
            "dns: lookup failed for example.org: NXDOMAIN",
            "router: lookup example.org: i/o timeout",
            "dns: lookup failed for ipv6.msftconnecttest.com: i/o timeout",
            "connection: open connection to 10.6.0.1:80 using outbound/wireguard[wg]: connect tcp 10.6.0.1:80: i/o timeout",
            "connection: connection upload closed: dial tcp 1.2.3.4:443: i/o timeout",
            "connection: connection download closed: TLS handshake: EOF",
            "connection: connection upload closed: reality handshake: connection reset by peer",
            "connection: open connection: broken pipe",
            "dns: lookup failed: EOF",
            "connection: connection upload closed: unexpected EOF",
            "router: lookup example.org: empty result: upstream unavailable",
            "unknown error",
        ] {
            assert!(!is_noise(text, &["10.6.0.1:80".parse().unwrap()]), "{text}");
            let payload = serde_json::json!({"type": "error", "payload": text}).to_string();
            assert_eq!(lines_for_event("clash://log", &payload), [format!("[core:error] {text}")]);
        }
    }

    #[test]
    fn batches_count_only_hidden_valid_core_entries() {
        let batch = serde_json::json!([
            null, {}, {"type": "error"},
            {"type": "error", "payload": "router: lookup ipv6.msftconnecttest.com: empty result"},
            {"type": "error", "payload": "connection: connection upload closed: EOF"},
            {"type": "error", "payload": "TLS handshake failed"},
            {"type": "info", "payload": "connected"},
        ]).to_string();
        let (entries, hidden) = filter_core_entries(&batch, &[]);
        assert_eq!(hidden, 2);
        assert_eq!(entries.len(), 2);
        assert_eq!(lines_for_event("clash://log", &batch), ["[core:error] TLS handshake failed"]);
        assert_eq!(filter_core_entries("invalid", &[]), (Vec::new(), 0));
        assert_eq!(lines_for_event("app://log", "connection: connection upload closed: EOF"), ["[app] connection: connection upload closed: EOF"]);
    }

    #[test]
    fn noise_summary_flushes_once_per_ten_minutes_and_skips_empty_windows() {
        let mut counter = NoiseCounter::new(50);
        assert_eq!(counter.flush(649), None);
        counter.record(135);
        counter.record(135);
        assert_eq!(counter.flush(49), None);
        assert_eq!(counter.flush(649), None);
        assert_eq!(counter.flush(650), Some("Скрыто типовых сообщений ядра за 10 мин: 270 (IPv6-запросы в режиме «только IPv4», обрывы соединений клиентом, проверки WireGuard)".into()));
        assert_eq!(counter.flush(650), None);
        assert_eq!(counter.flush(1250), None);
        counter.record(1);
        assert_eq!(counter.flush(1849), None);
        assert!(counter.flush(1850).unwrap().contains("за 10 мин: 1 ("));
        assert_eq!(counter.flush(5000), None);
        counter.record(2);
        assert_eq!(counter.flush(5599), None);
        assert!(counter.flush(5600).unwrap().contains("за 10 мин: 2 ("));
    }

    #[test]
    fn unicode_messages_and_malformed_entries_are_handled_without_truncation() {
        let text = "я".repeat(MAX_BYTES as usize / 2 + 1);
        assert_eq!(lines_for_event("app://error", &text), [format!("[error] {text}")]);
        let batch = serde_json::json!([null, 1, {}, {"type":"error"}, {"type":"error", "payload":"Ошибка 🇧🇾"}]);
        assert_eq!(lines_for_event("clash://log", &batch.to_string()), ["[core:error] Ошибка 🇧🇾"]);
    }

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

