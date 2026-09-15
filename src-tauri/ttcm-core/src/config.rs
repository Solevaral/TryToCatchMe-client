//! sing-box config.json generation.
//!
//! A local `mixed` (SOCKS+HTTP) inbound (the app points the OS system proxy at it),
//! the active outbound (direct-only when no profile), routing rules/rule-sets from the
//! routing layer, and the Clash API controller for the UI (traffic/logs).

use serde_json::{json, Value};

pub const CLASH_CONTROLLER: &str = "127.0.0.1:9090";
pub const MIXED_LISTEN: &str = "127.0.0.1";
/// Default local proxy port (user-configurable in Settings).
pub const MIXED_PORT: u16 = 2080;

/// Port of the internal inbound the app uses to download geo lists THROUGH the
/// proxy: always the proxy port + 1.
pub fn geo_port(mixed_port: u16) -> u16 {
    mixed_port.saturating_add(1)
}

pub struct GenOptions {
    /// Port of the local mixed (HTTP+SOCKS) proxy. The OS system proxy itself is
    /// managed by the app, never by sing-box: the core is stopped with a hard kill, and
    /// sing-box would leave the system proxy pointing at a dead port.
    pub mixed_port: u16,
    /// The active proxy outbound (tag=proxy). `None` => direct-only.
    pub proxy_outbound: Option<Value>,
    pub log_level: String,
    /// sing-box `route.rules` (built by the routing layer).
    pub route_rules: Vec<Value>,
    /// sing-box `route.rule_set` entries (geosite/geoip).
    pub rule_sets: Vec<Value>,
    /// `route.final` outbound tag when nothing matches.
    pub final_action: String,
    /// Resolve DNS over HTTPS through the tunnel (anti-leak). Requires a proxy.
    pub dns_doh: bool,
    /// Block QUIC / UDP:443 so traffic falls back to TLS (helps SNI/Reality rules).
    pub block_quic: bool,
    /// TUN mode: capture ALL system traffic via a virtual adapter (needs admin).
    /// When false, only the local mixed proxy + OS system-proxy setting are used.
    pub tun: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        Self {
            mixed_port: MIXED_PORT,
            proxy_outbound: None,
            log_level: "info".to_string(),
            route_rules: Vec::new(),
            rule_sets: Vec::new(),
            final_action: "proxy".to_string(),
            dns_doh: true,
            block_quic: false,
            tun: false,
        }
    }
}

/// Route-rule matcher keys that DNS rules understand too (used to mirror proxied
/// domains into DNS rules).
const DOMAIN_KEYS: [&str; 3] = ["domain", "domain_suffix", "domain_keyword"];

pub fn generate(opts: &GenOptions) -> Value {
    let has_proxy = opts.proxy_outbound.is_some();

    // `direct` goes first so any of sing-box's own traffic without an explicit detour
    // doesn't silently depend on the proxy. User traffic is steered explicitly by
    // `route.rules` / `route.final`; geo lists set their own detour.
    let mut outbounds = vec![json!({ "type": "direct", "tag": "direct" })];
    if let Some(proxy) = &opts.proxy_outbound {
        outbounds.push(proxy.clone());
    }

    // Without an active proxy, everything is direct and no proxy-targeted rules apply.
    let (user_rules, rule_sets, final_tag): (Vec<Value>, Vec<Value>, String) = if has_proxy {
        (
            opts.route_rules.clone(),
            opts.rule_sets.clone(),
            match opts.final_action.as_str() {
                "direct" => "direct".to_string(),
                _ => "proxy".to_string(),
            },
        )
    } else {
        (Vec::new(), Vec::new(), "direct".to_string())
    };

    // Rule order matters:
    // 1. sniff — recover the domain (TLS SNI / HTTP Host / QUIC) from raw
    //    connections. Without it, TUN traffic is just IPs and domain rules
    //    (services, geosite) never match, so e.g. YouTube would fall to `final`.
    // 2. hijack-dns — in TUN mode, answer the system's DNS queries ourselves.
    // 3. optional QUIC block, then the routing layer's rules.
    let mut rules = vec![json!({ "action": "sniff" })];
    if opts.tun {
        rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));
    }
    // The app's own geo-list downloads always go through the VPN (the ISP often
    // blocks raw.githubusercontent.com), regardless of the routing mode.
    if has_proxy {
        rules.push(json!({ "inbound": ["geo-in"], "outbound": "proxy" }));
    }
    if has_proxy && opts.block_quic {
        rules.push(json!({ "network": "udp", "port": 443, "action": "reject" }));
    }
    rules.extend(user_rules.iter().map(to_action_rule));

    let mut route = serde_json::Map::new();
    route.insert("rules".into(), json!(rules));
    if !rule_sets.is_empty() {
        route.insert("rule_set".into(), json!(rule_sets));
    }
    route.insert("final".into(), json!(final_tag));
    route.insert("auto_detect_interface".into(), json!(true));
    // sing-box 1.14 requires an explicit resolver for outbound server domains.
    route.insert(
        "default_domain_resolver".into(),
        json!({ "server": "dns-direct" }),
    );

    // Inbounds. In TUN mode a virtual adapter captures ALL system traffic (so even
    // apps that ignore the OS proxy go through the VPN). The local mixed proxy is always
    // exposed; the app points the OS system proxy at it when not in TUN mode.
    let mut inbounds = vec![json!({
        "type": "mixed",
        "tag": "mixed-in",
        "listen": MIXED_LISTEN,
        "listen_port": opts.mixed_port
    })];
    if has_proxy {
        inbounds.push(json!({
            "type": "http",
            "tag": "geo-in",
            "listen": MIXED_LISTEN,
            "listen_port": geo_port(opts.mixed_port)
        }));
    }
    if opts.tun {
        inbounds.insert(
            0,
            json!({
                "type": "tun",
                "tag": "tun-in",
                "address": ["172.18.0.1/30", "fdfe:dcba:9876::1/126"],
                "auto_route": true,
                // strict_route stays off: the app stops the core with a hard kill, and
                // strict rules could leave the machine without internet after an
                // unclean exit. Wintun + its routes are removed when the process dies.
                "strict_route": false,
                "stack": "mixed"
            }),
        );
    }

    let cfg_base = json!({
        "log": { "level": opts.log_level, "timestamp": true },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": Value::Object(route),
        "experimental": {
            "clash_api": { "external_controller": CLASH_CONTROLLER }
        }
    });
    let mut cfg = cfg_base;

    // DNS follows routing. `dns-direct` is the system resolver (works exactly like
    // without a VPN, never depends on the proxy). With DoH enabled, domains that are
    // routed THROUGH the VPN are resolved via DoH inside the tunnel (clean, unpoisoned
    // answers, no leak to the ISP); everything else stays on the system resolver, so a
    // slow or broken proxy can never take down direct sites.
    // NOTE: never give a server `detour: "direct"` — sing-box 1.14 rejects a detour to
    // the empty direct outbound at runtime even though `sing-box check` accepts it.
    let doh = has_proxy && opts.dns_doh;
    let mut servers = vec![json!({ "type": "local", "tag": "dns-direct" })];
    let mut dns_rules = Vec::new();
    if doh {
        servers.push(json!({
            "type": "https", "tag": "doh-proxy", "server": "1.1.1.1", "detour": "proxy"
        }));
        for rule in user_rules.iter().filter(|r| r.get("outbound") == Some(&json!("proxy"))) {
            let mut dns_rule = serde_json::Map::new();
            for key in DOMAIN_KEYS {
                if let Some(v) = rule.get(key) {
                    dns_rule.insert(key.into(), v.clone());
                }
            }
            if !dns_rule.is_empty() {
                dns_rule.insert("server".into(), json!("doh-proxy"));
                dns_rules.push(Value::Object(dns_rule));
            }
        }
    }
    let dns_final = if doh && final_tag == "proxy" {
        "doh-proxy"
    } else {
        "dns-direct"
    };
    cfg["dns"] = json!({ "servers": servers, "rules": dns_rules, "final": dns_final });

    cfg
}

/// Convert a routing-layer rule to sing-box 1.14 form: `outbound: "block"` becomes the
/// `reject` action (the legacy block outbound is deprecated).
fn to_action_rule(rule: &Value) -> Value {
    let mut r = rule.clone();
    if r.get("outbound") == Some(&json!("block")) {
        if let Some(obj) = r.as_object_mut() {
            obj.remove("outbound");
            obj.insert("action".into(), json!("reject"));
        }
    }
    r
}

#[cfg(test)]
mod tests {
    use super::*;

    fn proxy() -> Value {
        json!({ "type": "vless", "tag": "proxy", "server": "a.com", "server_port": 443, "uuid": "u" })
    }

    fn only_youtube() -> GenOptions {
        GenOptions {
            proxy_outbound: Some(proxy()),
            route_rules: vec![
                json!({ "ip_is_private": true, "outbound": "direct" }),
                json!({ "domain_suffix": ["youtube.com", "googlevideo.com"], "outbound": "proxy" }),
                json!({ "domain_suffix": ["blocked.example"], "outbound": "block" }),
            ],
            final_action: "direct".into(),
            ..GenOptions::default()
        }
    }

    #[test]
    fn sniff_is_first_and_dns_follows_routing() {
        let cfg = generate(&only_youtube());
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert_eq!(rules[0]["action"], "sniff");
        assert_eq!(cfg["route"]["final"], "direct");
        // Only the proxied service is resolved through the tunnel; the rest is direct.
        assert_eq!(cfg["dns"]["final"], "dns-direct");
        let dns_rules = cfg["dns"]["rules"].as_array().unwrap();
        assert_eq!(dns_rules.len(), 1);
        assert_eq!(dns_rules[0]["server"], "doh-proxy");
        assert_eq!(dns_rules[0]["domain_suffix"][0], "youtube.com");
        // "block" became a reject action and no legacy block outbound is emitted.
        assert!(rules.iter().any(|r| r["action"] == "reject"));
        assert!(cfg["outbounds"].as_array().unwrap().iter().all(|o| o["type"] != "block"));
        // No DNS server may detour to the direct outbound.
        assert!(cfg["dns"]["servers"].as_array().unwrap().iter().all(|s| s["detour"] != "direct"));
    }

    #[test]
    fn tun_hijacks_dns_and_disables_system_proxy() {
        let cfg = generate(&GenOptions { tun: true, ..only_youtube() });
        assert_eq!(cfg["route"]["rules"][1]["action"], "hijack-dns");
        assert_eq!(cfg["inbounds"][0]["type"], "tun");
        // sing-box must never own the system proxy (a hard kill would leave it behind).
        assert!(cfg["inbounds"].as_array().unwrap().iter().all(|i| i.get("set_system_proxy").is_none()));
    }

    #[test]
    fn geo_downloads_are_forced_through_proxy_on_port_plus_one() {
        let cfg = generate(&GenOptions { mixed_port: 3000, ..only_youtube() });
        let inbounds = cfg["inbounds"].as_array().unwrap();
        assert!(inbounds.iter().any(|i| i["tag"] == "mixed-in" && i["listen_port"] == 3000));
        assert!(inbounds.iter().any(|i| i["tag"] == "geo-in" && i["listen_port"] == 3001));
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert!(rules.iter().any(|r| r["inbound"][0] == "geo-in" && r["outbound"] == "proxy"));
    }

    #[test]
    fn global_mode_resolves_everything_through_tunnel() {
        let cfg = generate(&GenOptions {
            proxy_outbound: Some(proxy()),
            ..GenOptions::default()
        });
        assert_eq!(cfg["route"]["final"], "proxy");
        assert_eq!(cfg["dns"]["final"], "doh-proxy");
    }

    #[test]
    fn no_profile_is_direct_only() {
        let cfg = generate(&GenOptions::default());
        assert_eq!(cfg["route"]["final"], "direct");
        assert_eq!(cfg["outbounds"].as_array().unwrap().len(), 1);
        assert_eq!(cfg["dns"]["final"], "dns-direct");
    }
}

pub fn to_string(cfg: &Value) -> String {
    serde_json::to_string_pretty(cfg).unwrap_or_else(|_| "{}".to_string())
}
