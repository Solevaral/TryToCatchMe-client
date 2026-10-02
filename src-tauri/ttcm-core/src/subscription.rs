//! Subscription URLs (https://…): recognizing them and reading what the panel sends
//! along with the link list (title, traffic, expiry) — Remnawave / Marzban / 3x-ui style.
//! Downloading is done by the app; everything here is pure.

use base64::Engine;
use serde::{Deserialize, Serialize};
use url::Url;

use crate::links::{self, Profile};

/// Traffic and expiry from the `subscription-userinfo` header (bytes / unix seconds).
#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
pub struct SubInfo {
    pub upload: u64,
    pub download: u64,
    /// 0 = unlimited.
    pub total: u64,
    /// None or 0 = never expires.
    pub expire: Option<u64>,
}

/// The text is a single http(s) URL — a subscription to download, not links to parse.
pub fn as_url(text: &str) -> Option<String> {
    let t = text.trim();
    if t.contains(char::is_whitespace) {
        return None;
    }
    let url = Url::parse(t).ok()?;
    (matches!(url.scheme(), "http" | "https") && url.host_str().is_some()).then(|| t.to_string())
}

/// `upload=0; download=123; total=0; expire=1808933689`
pub fn parse_userinfo(header: &str) -> Option<SubInfo> {
    let mut info = SubInfo::default();
    let mut any = false;
    for part in header.split(';') {
        let Some((k, v)) = part.split_once('=') else { continue };
        let Ok(n) = v.trim().parse::<f64>() else { continue };
        let n = n.max(0.0) as u64;
        any = true;
        match k.trim().to_ascii_lowercase().as_str() {
            "upload" => info.upload = n,
            "download" => info.download = n,
            "total" => info.total = n,
            "expire" => info.expire = (n > 0).then_some(n),
            _ => {}
        }
    }
    any.then_some(info)
}

/// Header text that panels may send as `base64:<utf-8>` (e.g. `profile-title`).
pub fn header_text(raw: &str) -> String {
    let raw = raw.trim();
    if let Some(b64) = raw.strip_prefix("base64:") {
        let e = &base64::engine::general_purpose::STANDARD;
        if let Some(s) = e.decode(b64.trim()).ok().and_then(|b| String::from_utf8(b).ok()) {
            return s.trim().to_string();
        }
    }
    raw.to_string()
}

/// Display name for a subscription: the panel's title, or the URL's host.
pub fn title(profile_title: Option<&str>, url: &str) -> String {
    profile_title
        .map(header_text)
        .filter(|s| !s.is_empty())
        .or_else(|| Url::parse(url).ok()?.host_str().map(str::to_string))
        .unwrap_or_else(|| url.to_string())
}

/// Stub entries panels return instead of real servers ("App not supported",
/// "HWID limit reached", "Subscription expired", …): they point at 0.0.0.0.
pub fn is_stub(p: &Profile) -> bool {
    p.server == "0.0.0.0" || p.port <= 1
}

/// Parse a downloaded subscription body. Stub entries are dropped and their names
/// (the panel's explanation) are reported as errors.
pub fn parse_body(body: &str) -> (Vec<Profile>, Vec<String>) {
    let t = body.trim_start();
    if t.starts_with('{') || t.starts_with('[') {
        return (Vec::new(), vec![
            "подписка вернула JSON-конфиг вместо списка ссылок — панель не узнала клиент".into(),
        ]);
    }
    if t.contains("proxies:") && !t.contains("://") {
        return (Vec::new(), vec![
            "подписка вернула конфиг Clash вместо списка ссылок — панель не узнала клиент".into(),
        ]);
    }
    let (parsed, mut errors) = links::parse_many(body);
    let (stubs, profiles): (Vec<_>, Vec<_>) = parsed.into_iter().partition(is_stub);
    for s in stubs {
        errors.push(format!("сервер подписки ответил заглушкой: «{}»", s.name));
    }
    (profiles, errors)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn b64(s: &str) -> String {
        base64::engine::general_purpose::STANDARD.encode(s)
    }

    #[test]
    fn recognizes_only_a_single_http_url() {
        assert_eq!(as_url("  https://sub.example.com/AbC123 \n").as_deref(), Some("https://sub.example.com/AbC123"));
        assert!(as_url("http://1.2.3.4:2096/sub/x").is_some());
        assert!(as_url("vless://u@h:443").is_none());
        assert!(as_url("https://a.com/1\nhttps://b.com/2").is_none());
        assert!(as_url(&b64("vless://u@h:443")).is_none());
    }

    #[test]
    fn userinfo() {
        let i = parse_userinfo("upload=10; download=115147583447; total=0; expire=1808933689").unwrap();
        assert_eq!(i, SubInfo { upload: 10, download: 115147583447, total: 0, expire: Some(1808933689) });
        assert_eq!(parse_userinfo("expire=0").unwrap().expire, None);
        assert!(parse_userinfo("garbage").is_none());
    }

    #[test]
    fn title_from_header_or_host() {
        assert_eq!(title(Some(&format!("base64:{}", b64("Geo Net"))), "https://x.org/a"), "Geo Net");
        assert_eq!(title(Some("Plain"), "https://x.org/a"), "Plain");
        assert_eq!(title(None, "https://sub.x.org/a"), "sub.x.org");
    }

    #[test]
    fn stub_is_reported_not_imported() {
        let body = b64("vless://00000000-0000-0000-0000-000000000000@0.0.0.0:1?encryption=none&type=tcp&security=none#App%20not%20supported");
        let (ps, errs) = parse_body(&body);
        assert!(ps.is_empty());
        assert!(errs[0].contains("App not supported"));
    }

    #[test]
    fn body_with_links() {
        let body = b64("vless://11111111-1111-1111-1111-111111111111@1.2.3.4:443?security=reality&pbk=K&sid=ab&type=tcp#a\nhysteria2://pw@1.2.3.4:8444/?sni=s.net#b");
        let (ps, errs) = parse_body(&body);
        assert_eq!(ps.len(), 2);
        assert!(errs.is_empty());
    }

    #[test]
    fn json_config_is_a_clear_error() {
        let (ps, errs) = parse_body("[{\"dns\":{}}]");
        assert!(ps.is_empty());
        assert!(errs[0].contains("JSON"));
    }
}
