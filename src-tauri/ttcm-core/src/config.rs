//! sing-box config.json generation.
//!
//! A local `mixed` (SOCKS+HTTP) inbound that can set the OS system proxy, the active
//! outbound (direct-only when no profile), routing rules/rule-sets from the routing
//! layer, and the Clash API controller for the UI (traffic/logs).

use serde_json::{json, Value};

pub const CLASH_CONTROLLER: &str = "127.0.0.1:9090";
pub const MIXED_LISTEN: &str = "127.0.0.1";
pub const MIXED_PORT: u16 = 2080;

pub struct GenOptions {
    /// When true, the mixed inbound configures the OS system proxy (no admin).
    pub set_system_proxy: bool,
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
    /// Absolute path for sing-box's rule-set cache (persists downloaded geo lists).
    pub cache_path: Option<String>,
    /// TUN mode: capture ALL system traffic via a virtual adapter (needs admin).
    /// When false, only the local mixed proxy + OS system-proxy setting are used.
    pub tun: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        Self {
            set_system_proxy: true,
            proxy_outbound: None,
            log_level: "info".to_string(),
            route_rules: Vec::new(),
            rule_sets: Vec::new(),
            final_action: "proxy".to_string(),
            dns_doh: true,
            block_quic: false,
            cache_path: None,
            tun: false,
        }
    }
}

pub fn generate(opts: &GenOptions) -> Value {
    let mut outbounds = Vec::new();
    let has_proxy = opts.proxy_outbound.is_some();

    if let Some(proxy) = &opts.proxy_outbound {
        outbounds.push(proxy.clone());
    }
    outbounds.push(json!({ "type": "direct", "tag": "direct" }));
    outbounds.push(json!({ "type": "block", "tag": "block" }));

    // Without an active proxy, everything is direct and no proxy-targeted rules apply.
    let (rules, rule_sets, final_tag): (Vec<Value>, Vec<Value>, &str) = if has_proxy {
        (
            opts.route_rules.clone(),
            opts.rule_sets.clone(),
            opts.final_action.as_str(),
        )
    } else {
        (Vec::new(), Vec::new(), "direct")
    };

    let mut rules = rules;
    // Kill QUIC (UDP/443) so apps fall back to TLS/TCP — makes SNI/Reality rules
    // reliable and closes a common leak path. Only meaningful with a proxy.
    if has_proxy && opts.block_quic {
        rules.insert(0, json!({ "network": "udp", "port": 443, "outbound": "block" }));
    }

    let mut route = serde_json::Map::new();
    route.insert("rules".into(), json!(rules));
    if !rule_sets.is_empty() {
        route.insert("rule_set".into(), json!(rule_sets));
    }
    route.insert("final".into(), json!(final_tag));
    route.insert("auto_detect_interface".into(), json!(true));
    if has_proxy {
        // sing-box 1.14 requires an explicit resolver for outbound server domains.
        // Always resolve them via the direct DNS server (no loop).
        route.insert(
            "default_domain_resolver".into(),
            json!({ "server": "dns-direct" }),
        );
    }

    // Inbounds. In TUN mode a virtual adapter captures ALL system traffic (so even
    // apps that ignore the OS proxy go through the VPN); the system proxy is left off.
    // Otherwise a local mixed proxy is exposed and set as the OS system proxy.
    let mut inbounds = vec![json!({
        "type": "mixed",
        "tag": "mixed-in",
        "listen": MIXED_LISTEN,
        "listen_port": MIXED_PORT,
        "set_system_proxy": !opts.tun && opts.set_system_proxy
    })];
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

    let mut cfg = json!({
        "log": { "level": opts.log_level, "timestamp": true },
        "inbounds": inbounds,
        "outbounds": outbounds,
        "route": Value::Object(route),
        "experimental": {
            "clash_api": { "external_controller": CLASH_CONTROLLER }
        }
    });

    // Persist downloaded rule-sets so they aren't re-fetched on every connect.
    if let Some(path) = &opts.cache_path {
        cfg["experimental"]["cache_file"] = json!({ "enabled": true, "path": path });
    }

    // DNS-over-HTTPS through the tunnel (anti-leak). IP-literal endpoint avoids a
    // bootstrap-resolution loop. Only when a proxy is active.
    // A DNS block is always present when a proxy is active (needed for
    // default_domain_resolver). With DoH enabled, queries go through the tunnel
    // (anti-leak); otherwise a plain direct resolver just serves domain resolution.
    if has_proxy {
        // NOTE: the direct resolver must NOT set `detour: "direct"` — sing-box 1.14
        // rejects a detour to the (empty) direct outbound at runtime ("makes no
        // sense"), even though `sing-box check` accepts it. Direct is the default.
        cfg["dns"] = if opts.dns_doh {
            json!({
                "servers": [
                    { "type": "https", "tag": "doh-proxy", "server": "1.1.1.1", "detour": "proxy" },
                    { "type": "https", "tag": "dns-direct", "server": "1.1.1.1" }
                ],
                "final": "doh-proxy"
            })
        } else {
            json!({
                "servers": [
                    { "type": "udp", "tag": "dns-direct", "server": "1.1.1.1" }
                ],
                "final": "dns-direct"
            })
        };
    }

    cfg
}

pub fn to_string(cfg: &Value) -> String {
    serde_json::to_string_pretty(cfg).unwrap_or_else(|_| "{}".to_string())
}
