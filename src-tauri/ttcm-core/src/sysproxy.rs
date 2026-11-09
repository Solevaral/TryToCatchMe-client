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

/// Full manual-proxy coverage, distinct from partial ownership during restore.
pub fn windows_server_matches(server: &str, host: &str, port: u16) -> bool {
    let entries: Vec<&str> = server.split(';').map(str::trim).filter(|e| !e.is_empty()).collect();
    let covers_web = !server.contains('=') || ["http", "https"].iter().all(|scheme| {
        entries.iter().any(|e| e.split_once('=').is_some_and(|(key, _)| key.eq_ignore_ascii_case(scheme)))
    });
    covers_web && !entries.is_empty() && entries.iter().all(|e| windows_server_points_to(e, host, port))
}

pub fn linux_proxy_matches(
    gnome: Option<&[(String, String, String)]>,
    kde: Option<&[(String, String)]>,
    host: &str,
    port: u16,
    pac: &str,
) -> bool {
    let gnome_ok = gnome.map(|values| {
        let get = |schema: &str, key: &str| values.iter().find(|(s, k, _)| s == schema && k == key).map(|(_, _, v)| gvariant_plain(v)).unwrap_or_default();
        match get("org.gnome.system.proxy", "mode").as_str() {
            "manual" => ["http", "https", "socks"].iter().all(|scheme| {
                let schema = format!("org.gnome.system.proxy.{scheme}");
                get(&schema, "host") == host && get(&schema, "port") == port.to_string()
            }),
            "auto" => pac_matches(&get("org.gnome.system.proxy", "autoconfig-url"), pac),
            _ => false,
        }
    });
    let kde_ok = kde.map(|values| {
        let get = |key: &str| values.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str()).unwrap_or("");
        match get("ProxyType") {
            "1" => ["httpProxy", "httpsProxy", "socksProxy"].iter().all(|key| kde_value_points_to(get(key), host, port)),
            "2" => pac_matches(get("Proxy Config Script"), pac),
            _ => false,
        }
    });
    (gnome_ok.is_some() || kde_ok.is_some()) && gnome_ok.unwrap_or(true) && kde_ok.unwrap_or(true)
}

fn pac_matches(current: &str, expected: &str) -> bool {
    current == expected || current.strip_prefix(expected).is_some_and(|suffix| suffix.starts_with('?'))
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
    fn partial_proxy_ownership_does_not_confirm_web_coverage() {
        let partial = "http=127.0.0.1:2080;https=127.0.0.1:9999";
        assert!(windows_server_points_to(partial, "127.0.0.1", 2080));
        assert!(!windows_server_matches(partial, "127.0.0.1", 2080));
        assert!(!windows_server_matches("http=127.0.0.1:2080", "127.0.0.1", 2080));
        assert!(windows_server_matches("127.0.0.1:2080", "127.0.0.1", 2080));
        assert!(windows_server_matches("http=127.0.0.1:2080;https=127.0.0.1:2080", "127.0.0.1", 2080));
    }

    #[test]
    fn linux_checks_every_protocol_and_pac_boundary() {
        let mut kde = vec![("ProxyType".into(), "1".into())];
        for key in ["httpProxy", "httpsProxy", "socksProxy"] {
            kde.push((key.into(), "http://127.0.0.1 2080".into()));
        }
        assert!(linux_proxy_matches(None, Some(&kde), "127.0.0.1", 2080, "http://local/proxy.pac"));
        kde[2].1 = "http://127.0.0.1 9999".into();
        assert!(!linux_proxy_matches(None, Some(&kde), "127.0.0.1", 2080, "http://local/proxy.pac"));
        assert!(!linux_proxy_matches(None, None, "127.0.0.1", 2080, "http://local/proxy.pac"));
        assert!(pac_matches("http://local/proxy.pac?123", "http://local/proxy.pac"));
        assert!(!pac_matches("http://local/proxy.pac.evil", "http://local/proxy.pac"));
    }

    #[test]
    fn bypass_lists_cover_lan_without_duplicates() {
        let windows: Vec<_> = WINDOWS_BYPASS.split(';').collect();
        let unique: std::collections::HashSet<_> = windows.iter().collect();
        assert_eq!(windows.len(), unique.len());
        assert!(windows.contains(&"<local>"));
        assert!(!WINDOWS_BYPASS.contains(','));
        for subnet in 16..=31 { assert!(windows.contains(&format!("172.{subnet}.*").as_str())); }
        assert!(GNOME_BYPASS.contains("172.16.0.0/12"));
        assert!(!windows_server_points_to("127.0.0.1:20800", "127.0.0.1", 2080));
        assert!(!windows_server_points_to("http=;https=", "127.0.0.1", 2080));
    }

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
