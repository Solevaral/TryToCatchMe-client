//! Connection-link parsers.
//!
//! Parse share links (vless://, vmess://, ss://, trojan://) and subscriptions
//! (base64 blobs / multi-line lists) into a normalized [`Profile`] whose `outbound`
//! is a ready-to-use sing-box outbound object (the generator sets its `tag`).

use std::collections::HashMap;

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use url::Url;

#[derive(Serialize, Deserialize, Clone)]
pub struct Profile {
    pub id: String,
    pub name: String,
    pub protocol: String,
    pub server: String,
    pub port: u16,
    /// sing-box outbound object (without the "tag" field).
    pub outbound: Value,
}

impl Profile {
    fn new(name: String, protocol: &str, server: String, port: u16, outbound: Value) -> Self {
        Profile {
            id: uuid::Uuid::new_v4().to_string(),
            name,
            protocol: protocol.to_string(),
            server,
            port,
            outbound,
        }
    }
}

/// Parse one or many links / a subscription blob into profiles.
/// Returns the profiles that parsed and a list of human-readable errors.
pub fn parse_many(text: &str) -> (Vec<Profile>, Vec<String>) {
    let mut profiles = Vec::new();
    let mut errors = Vec::new();
    for link in extract_links(text) {
        match parse_link(&link) {
            Ok(p) => profiles.push(p),
            Err(e) => errors.push(format!("{}: {e}", short(&link))),
        }
    }
    if profiles.is_empty() && errors.is_empty() {
        errors.push("No connection links found in the text".to_string());
    }
    (profiles, errors)
}

fn short(link: &str) -> String {
    let l = link.trim();
    if l.len() > 40 {
        format!("{}…", &l[..40])
    } else {
        l.to_string()
    }
}

/// Pull individual links out of raw text; decode a base64 subscription blob if needed.
fn extract_links(text: &str) -> Vec<String> {
    let t = text.trim();
    let body = if t.contains("://") {
        t.to_string()
    } else {
        b64_decode(t)
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| t.to_string())
    };
    body.split(|c: char| c == '\n' || c == '\r' || c == ' ' || c == '\t')
        .map(|s| s.trim())
        .filter(|s| s.contains("://"))
        .map(|s| s.to_string())
        .collect()
}

pub fn parse_link(raw: &str) -> Result<Profile, String> {
    let raw = raw.trim();
    let scheme = raw.split_once("://").map(|(s, _)| s.to_lowercase());
    match scheme.as_deref() {
        Some("vless") => parse_vless(raw),
        Some("vmess") => parse_vmess(raw),
        Some("ss") => parse_ss(raw),
        Some("trojan") => parse_trojan(raw),
        Some("wireguard") | Some("wg") => Err(
            "WireGuard share links are not standardized; import via config file (planned)".into(),
        ),
        Some(other) => Err(format!("Unsupported scheme: {other}")),
        None => Err("Not a connection link".into()),
    }
}

// ---------------------------------------------------------------------------
// VLESS
// ---------------------------------------------------------------------------
fn parse_vless(raw: &str) -> Result<Profile, String> {
    let url = Url::parse(raw).map_err(|e| format!("bad url: {e}"))?;
    let uuid = pct(url.username());
    if uuid.is_empty() {
        return Err("missing uuid".into());
    }
    let server = url.host_str().ok_or("missing host")?.to_string();
    let port = url.port().ok_or("missing port")?;
    let q = query_map(&url);
    let name = frag_name(&url, &server);

    let mut ob = json!({
        "type": "vless",
        "server": server,
        "server_port": port,
        "uuid": uuid,
    });
    if let Some(flow) = q.get("flow").filter(|s| !s.is_empty()) {
        ob["flow"] = json!(flow);
    }

    let security = q.get("security").map(|s| s.as_str()).unwrap_or("none");
    if security == "tls" || security == "reality" {
        ob["tls"] = build_tls(&q, &server, security == "reality");
    }
    if let Some(tr) = build_transport(&q, &server) {
        ob["transport"] = tr;
    }
    ensure_grpc_alpn(&mut ob, &q);

    Ok(Profile::new(name, "vless", server, port, ob))
}

// ---------------------------------------------------------------------------
// VMess (base64-encoded JSON)
// ---------------------------------------------------------------------------
fn parse_vmess(raw: &str) -> Result<Profile, String> {
    let b64 = raw.trim_start_matches("vmess://").trim();
    let bytes = b64_decode(b64).ok_or("bad base64")?;
    let v: Value = serde_json::from_slice(&bytes).map_err(|e| format!("bad json: {e}"))?;

    let server = v["add"].as_str().ok_or("missing add")?.to_string();
    let port = num_field(&v["port"]).ok_or("missing port")? as u16;
    let uuid = v["id"].as_str().ok_or("missing id")?.to_string();
    let aid = num_field(&v["aid"]).unwrap_or(0);
    let scy = v["scy"].as_str().filter(|s| !s.is_empty()).unwrap_or("auto");
    let net = v["net"].as_str().unwrap_or("tcp");
    let name = v["ps"]
        .as_str()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .unwrap_or_else(|| server.clone());

    let mut ob = json!({
        "type": "vmess",
        "server": server,
        "server_port": port,
        "uuid": uuid,
        "alter_id": aid,
        "security": scy,
    });

    if v["tls"].as_str() == Some("tls") {
        let sni = v["sni"]
            .as_str()
            .filter(|s| !s.is_empty())
            .or_else(|| v["host"].as_str())
            .unwrap_or(&server);
        let mut tls = json!({ "enabled": true, "server_name": sni });
        if let Some(alpn) = v["alpn"].as_str().filter(|s| !s.is_empty()) {
            tls["alpn"] = json!(alpn.split(',').map(|s| s.trim()).collect::<Vec<_>>());
        }
        ob["tls"] = tls;
    }

    // transport
    let host_hdr = v["host"].as_str().unwrap_or("").to_string();
    let path = v["path"].as_str().unwrap_or("/").to_string();
    match net {
        "ws" => {
            let mut ws = json!({ "type": "ws", "path": path });
            if !host_hdr.is_empty() {
                ws["headers"] = json!({ "Host": host_hdr });
            }
            ob["transport"] = ws;
        }
        "grpc" => {
            ob["transport"] = json!({ "type": "grpc", "service_name": path });
        }
        "h2" | "http" => {
            let mut h = json!({ "type": "http", "path": path });
            if !host_hdr.is_empty() {
                h["host"] = json!([host_hdr]);
            }
            ob["transport"] = h;
        }
        _ => {}
    }

    Ok(Profile::new(name, "vmess", server, port, ob))
}

// ---------------------------------------------------------------------------
// Shadowsocks
// ---------------------------------------------------------------------------
fn parse_ss(raw: &str) -> Result<Profile, String> {
    let body = raw.trim_start_matches("ss://");
    let (main, frag) = match body.split_once('#') {
        Some((m, f)) => (m, pct(f)),
        None => (body, String::new()),
    };
    // strip any query (plugin params) — not supported yet
    let main = main.split('?').next().unwrap_or(main);

    let (method, password, server, port) = if let Some((userinfo, hostport)) = main.rsplit_once('@')
    {
        // ss://base64(method:password)@host:port  (or plain method:password@host:port)
        let creds = b64_decode(userinfo)
            .and_then(|b| String::from_utf8(b).ok())
            .unwrap_or_else(|| pct(userinfo));
        let (m, p) = creds.split_once(':').ok_or("bad ss credentials")?;
        let (h, port) = split_hostport(hostport)?;
        (m.to_string(), p.to_string(), h, port)
    } else {
        // ss://base64(method:password@host:port)
        let decoded = b64_decode(main)
            .and_then(|b| String::from_utf8(b).ok())
            .ok_or("bad ss base64")?;
        let (creds, hostport) = decoded.rsplit_once('@').ok_or("bad ss format")?;
        let (m, p) = creds.split_once(':').ok_or("bad ss credentials")?;
        let (h, port) = split_hostport(hostport)?;
        (m.to_string(), p.to_string(), h, port)
    };

    let name = if frag.is_empty() { server.clone() } else { frag };
    let ob = json!({
        "type": "shadowsocks",
        "server": server,
        "server_port": port,
        "method": method,
        "password": password,
    });
    Ok(Profile::new(name, "shadowsocks", server, port, ob))
}

// ---------------------------------------------------------------------------
// Trojan
// ---------------------------------------------------------------------------
fn parse_trojan(raw: &str) -> Result<Profile, String> {
    let url = Url::parse(raw).map_err(|e| format!("bad url: {e}"))?;
    let password = pct(url.username());
    if password.is_empty() {
        return Err("missing password".into());
    }
    let server = url.host_str().ok_or("missing host")?.to_string();
    let port = url.port().ok_or("missing port")?;
    let q = query_map(&url);
    let name = frag_name(&url, &server);

    let mut ob = json!({
        "type": "trojan",
        "server": server,
        "server_port": port,
        "password": password,
    });
    // Trojan is TLS by default.
    ob["tls"] = build_tls(&q, &server, false);
    if let Some(tr) = build_transport(&q, &server) {
        ob["transport"] = tr;
    }
    ensure_grpc_alpn(&mut ob, &q);
    Ok(Profile::new(name, "trojan", server, port, ob))
}

// ---------------------------------------------------------------------------
// Shared helpers
// ---------------------------------------------------------------------------
fn build_tls(q: &HashMap<String, String>, server: &str, reality: bool) -> Value {
    let sni = q
        .get("sni")
        .or_else(|| q.get("peer"))
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| server.to_string());
    let mut tls = json!({ "enabled": true, "server_name": sni });
    if let Some(alpn) = q.get("alpn").filter(|s| !s.is_empty()) {
        tls["alpn"] = json!(alpn.split(',').map(|s| s.trim()).collect::<Vec<_>>());
    }
    let fp = q
        .get("fp")
        .filter(|s| !s.is_empty())
        .cloned()
        .unwrap_or_else(|| "chrome".to_string());
    tls["utls"] = json!({ "enabled": true, "fingerprint": fp });
    if reality {
        let pbk = q.get("pbk").cloned().unwrap_or_default();
        let sid = q.get("sid").cloned().unwrap_or_default();
        tls["reality"] = json!({ "enabled": true, "public_key": pbk, "short_id": sid });
    }
    tls
}

fn build_transport(q: &HashMap<String, String>, server: &str) -> Option<Value> {
    let net = q.get("type").map(|s| s.as_str()).unwrap_or("tcp");
    let host_hdr = q.get("host").filter(|s| !s.is_empty()).cloned();
    let path = q.get("path").cloned().unwrap_or_else(|| "/".to_string());
    match net {
        "ws" => {
            let mut ws = json!({ "type": "ws", "path": path });
            if let Some(h) = host_hdr.or_else(|| Some(server.to_string())) {
                ws["headers"] = json!({ "Host": h });
            }
            Some(ws)
        }
        "grpc" => {
            // Different share-link dialects put the gRPC service name in either
            // `serviceName` or `path`.
            let svc = q
                .get("serviceName")
                .or_else(|| q.get("path"))
                .cloned()
                .unwrap_or_default();
            Some(json!({ "type": "grpc", "service_name": svc }))
        }
        "http" | "h2" => {
            let mut h = json!({ "type": "http", "path": path });
            if let Some(hh) = host_hdr {
                h["host"] = json!([hh]);
            }
            Some(h)
        }
        "httpupgrade" => {
            let mut hu = json!({ "type": "httpupgrade", "path": path });
            if let Some(hh) = host_hdr {
                hu["host"] = json!(hh);
            }
            Some(hu)
        }
        _ => None,
    }
}

/// gRPC over TLS needs the h2 ALPN; add it when the link didn't specify one.
fn ensure_grpc_alpn(ob: &mut Value, q: &HashMap<String, String>) {
    if q.get("type").map(|s| s.as_str()) == Some("grpc") {
        if let Some(tls) = ob.get_mut("tls") {
            if tls.get("alpn").is_none() {
                tls["alpn"] = json!(["h2"]);
            }
        }
    }
}

fn query_map(url: &Url) -> HashMap<String, String> {
    url.query_pairs()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn frag_name(url: &Url, fallback: &str) -> String {
    url.fragment()
        .map(pct)
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| fallback.to_string())
}

fn split_hostport(hp: &str) -> Result<(String, u16), String> {
    let (h, p) = hp.rsplit_once(':').ok_or("missing port")?;
    let port: u16 = p.trim().parse().map_err(|_| "bad port")?;
    Ok((h.to_string(), port))
}

/// Percent-decode a string (lossy).
fn pct(s: &str) -> String {
    percent_encoding::percent_decode_str(s)
        .decode_utf8_lossy()
        .to_string()
}

/// Accept a JSON number that may be encoded as a number or a string.
fn num_field(v: &Value) -> Option<u64> {
    v.as_u64()
        .or_else(|| v.as_str().and_then(|s| s.trim().parse().ok()))
}

/// Try several base64 alphabets/paddings.
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let s = s.trim();
    use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
    STANDARD
        .decode(s)
        .ok()
        .or_else(|| URL_SAFE.decode(s).ok())
        .or_else(|| STANDARD_NO_PAD.decode(s).ok())
        .or_else(|| URL_SAFE_NO_PAD.decode(s).ok())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_shadowsocks_sip002() {
        // ss://base64(method:password)@host:port#name
        let creds = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:secret");
        let link = format!("ss://{creds}@1.2.3.4:8388#My%20SS");
        let p = parse_link(&link).unwrap();
        assert_eq!(p.protocol, "shadowsocks");
        assert_eq!(p.server, "1.2.3.4");
        assert_eq!(p.port, 8388);
        assert_eq!(p.name, "My SS");
        assert_eq!(p.outbound["method"], "aes-256-gcm");
        assert_eq!(p.outbound["password"], "secret");
    }

    #[test]
    fn parse_vless_reality() {
        let link = "vless://11111111-1111-1111-1111-111111111111@example.com:443?security=reality&sni=www.microsoft.com&pbk=KEY&sid=ab&fp=chrome&type=tcp&flow=xtls-rprx-vision#node";
        let p = parse_link(link).unwrap();
        assert_eq!(p.protocol, "vless");
        assert_eq!(p.port, 443);
        assert_eq!(p.outbound["flow"], "xtls-rprx-vision");
        assert_eq!(p.outbound["tls"]["reality"]["public_key"], "KEY");
        assert_eq!(p.outbound["tls"]["server_name"], "www.microsoft.com");
    }

    #[test]
    fn parse_trojan_ws() {
        let link = "trojan://pass@host.net:443?type=ws&path=/ws&sni=host.net#t";
        let p = parse_link(link).unwrap();
        assert_eq!(p.protocol, "trojan");
        assert_eq!(p.outbound["password"], "pass");
        assert_eq!(p.outbound["transport"]["type"], "ws");
        assert_eq!(p.outbound["tls"]["enabled"], true);
    }

    #[test]
    fn parse_vmess_json() {
        let inner = json!({
            "v":"2","ps":"vm","add":"a.b.c","port":"443","id":"uuid-x",
            "aid":"0","net":"ws","host":"a.b.c","path":"/p","tls":"tls","scy":"auto"
        })
        .to_string();
        let b64 = base64::engine::general_purpose::STANDARD.encode(inner);
        let link = format!("vmess://{b64}");
        let p = parse_link(&link).unwrap();
        assert_eq!(p.protocol, "vmess");
        assert_eq!(p.port, 443);
        assert_eq!(p.outbound["transport"]["type"], "ws");
        assert_eq!(p.outbound["tls"]["enabled"], true);
    }

    #[test]
    fn subscription_multi() {
        let creds = base64::engine::general_purpose::STANDARD.encode("aes-256-gcm:s");
        let list = format!("ss://{creds}@1.1.1.1:80#a\ntrojan://p@h.net:443#b");
        let (ps, errs) = parse_many(&list);
        assert_eq!(ps.len(), 2);
        assert!(errs.is_empty());
    }
}
