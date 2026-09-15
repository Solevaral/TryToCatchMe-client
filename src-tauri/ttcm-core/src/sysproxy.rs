//! Pure helpers for reading/writing OS system-proxy values (Windows registry strings,
//! GNOME gsettings GVariant text, KDE kioslaverc values). The OS calls live in the app;
//! the parsing lives here so it's unit-tested on every platform.

/// Hosts that should never go through the local proxy (Windows ProxyOverride format).
pub const WINDOWS_BYPASS: &str =
    "localhost;127.*;10.*;172.16.*;172.17.*;172.18.*;172.19.*;172.20.*;172.21.*;172.22.*;172.23.*;172.24.*;172.25.*;172.26.*;172.27.*;172.28.*;172.29.*;172.30.*;172.31.*;192.168.*;<local>";

/// Same list in GNOME `ignore-hosts` GVariant form.
pub const GNOME_BYPASS: &str =
    "['localhost', '127.0.0.0/8', '::1', '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16']";

/// Does a Windows `ProxyServer` value point at `host:port`?
/// Handles "127.0.0.1:2080", "http://127.0.0.1:2080" and per-protocol
/// "http=127.0.0.1:2080;https=127.0.0.1:2080" forms.
pub fn windows_server_points_to(server: &str, host: &str, port: u16) -> bool {
    let want = format!("{host}:{port}");
    let entries: Vec<String> = server
        .split(';')
        .map(|e| {
            let e = e.trim();
            // "http=host:port" -> "host:port"; "http://host:port" -> "host:port"
            let e = match e.split_once('=') {
                Some((_, v)) => v,
                None => e,
            };
            let e = e.split_once("://").map(|(_, v)| v).unwrap_or(e);
            e.trim_end_matches('/').to_string()
        })
        .filter(|e| !e.is_empty())
        .collect();
    !entries.is_empty() && entries.iter().any(|e| e.eq_ignore_ascii_case(&want))
}

/// `'manual'` -> `manual`, `"x"` -> `x`, `2080` -> `2080` (gsettings output).
pub fn gvariant_plain(raw: &str) -> String {
    let t = raw.trim();
    let t = t.strip_prefix("uint32 ").unwrap_or(t);
    t.trim_matches(|c| c == '\'' || c == '"').to_string()
}

/// KDE kioslaverc proxy value: "http://127.0.0.1 2080".
pub fn kde_proxy_value(scheme: &str, host: &str, port: u16) -> String {
    format!("{scheme}://{host} {port}")
}

/// Does a KDE proxy value ("http://127.0.0.1 2080" or "http://127.0.0.1:2080") point
/// at `host:port`?
pub fn kde_value_points_to(value: &str, host: &str, port: u16) -> bool {
    let v = value.trim();
    let v = v.split_once("://").map(|(_, rest)| rest).unwrap_or(v);
    let normalized = v.replace(' ', ":");
    normalized.trim_end_matches('/') == format!("{host}:{port}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_server_forms() {
        assert!(windows_server_points_to("127.0.0.1:2080", "127.0.0.1", 2080));
        assert!(windows_server_points_to("http://127.0.0.1:2080", "127.0.0.1", 2080));
        assert!(windows_server_points_to(
            "http=127.0.0.1:2080;https=127.0.0.1:2080",
            "127.0.0.1",
            2080
        ));
        // Hiddify's value is not ours.
        assert!(!windows_server_points_to("http://127.0.0.1:12334", "127.0.0.1", 2080));
        assert!(!windows_server_points_to("", "127.0.0.1", 2080));
    }

    #[test]
    fn gvariant_values() {
        assert_eq!(gvariant_plain("'manual'\n"), "manual");
        assert_eq!(gvariant_plain("2080"), "2080");
        assert_eq!(gvariant_plain("uint32 2080"), "2080");
    }

    #[test]
    fn kde_values() {
        assert_eq!(kde_proxy_value("http", "127.0.0.1", 2080), "http://127.0.0.1 2080");
        assert!(kde_value_points_to("http://127.0.0.1 2080", "127.0.0.1", 2080));
        assert!(kde_value_points_to("socks://127.0.0.1:2080", "127.0.0.1", 2080));
        assert!(!kde_value_points_to("http://127.0.0.1 12334", "127.0.0.1", 2080));
    }
}
