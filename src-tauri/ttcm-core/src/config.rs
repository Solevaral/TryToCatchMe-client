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
/// TUN interface name on Linux (firewall rules are bound to it).
pub const TUN_IFACE_LINUX: &str = "ttcm0";

/// Port of the internal inbound the app uses to download geo lists THROUGH the
/// proxy: always the proxy port + 1.
pub fn geo_port(mixed_port: u16) -> u16 {
    mixed_port.saturating_add(1)
}

/// Port of the app's PAC server for the system proxy: always the proxy port + 2.
pub fn pac_port(mixed_port: u16) -> u16 {
    mixed_port.saturating_add(2)
}

pub struct GenOptions {
    /// Port of the local mixed (HTTP+SOCKS) proxy. The OS system proxy itself is
    /// managed by the app, never by sing-box: the core is stopped with a hard kill, and
    /// sing-box would leave the system proxy pointing at a dead port.
    pub mixed_port: u16,
    /// The active proxy outbound (tag=proxy). `None` => direct-only.
    pub proxy_outbound: Option<Value>,
    /// Extra outbounds for services pinned to other profiles (tags `via-<profile id>`).
    pub extra_outbounds: Vec<Value>,
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
    /// TUN mode: upstream DNS server for `dns-direct`, queried by the core itself
    /// instead of the system resolver. Needed on Linux with systemd-resolved: the
    /// `local` server asks resolved, resolved sends the query into the tun (its DNS is
    /// the tun's), hijack-dns hands it back to `local` — a loop that kills all DNS.
    /// Empty => `local` (system resolver), as everywhere else.
    pub direct_dns: Vec<String>,
    /// TUN mode: give the tun an IPv6 address (and so an IPv6 default route). Off when
    /// the uplink has no IPv6: otherwise the system believes IPv6 works (the tun's ULA
    /// counts for getaddrinfo's AI_ADDRCONFIG), apps connect to AAAA addresses, the
    /// core accepts the connection and can't dial it out — a TLS error instead of the
    /// IPv4 fallback.
    pub tun_ipv6: bool,
}

impl Default for GenOptions {
    fn default() -> Self {
        Self {
            mixed_port: MIXED_PORT,
            proxy_outbound: None,
            extra_outbounds: Vec::new(),
            log_level: "info".to_string(),
            route_rules: Vec::new(),
            rule_sets: Vec::new(),
            final_action: "proxy".to_string(),
            dns_doh: true,
            block_quic: false,
            tun: false,
            direct_dns: Vec::new(),
            tun_ipv6: true,
        }
    }
}

/// Does a /proc/net/if_inet6 listing show a usable IPv6 uplink: a global-scope,
/// non-ULA address on a physical interface? (The tun's own fdfe:: ULA, Docker / VPN
/// adapters and loopback don't count.)
pub fn has_global_ipv6(if_inet6: &str) -> bool {
    if_inet6.lines().any(|line| {
        let f: Vec<&str> = line.split_whitespace().collect();
        // address, ifindex, prefix length, scope, flags, interface
        let [addr, _, _, scope, _, iface] = f[..] else { return false };
        let ula = addr.len() == 32 && matches!(&addr[..2], "fc" | "fd");
        scope == "00" && !ula && iface != "lo" && iface != TUN_IFACE_LINUX
            && !crate::gateway::is_virtual(iface, "")
    })
}

/// The TUN adapter's own addresses (the tun's DNS lives in these subnets).
const TUN_ADDRESSES: [&str; 2] = ["172.18.0.1/30", "fdfe:dcba:9876::1/126"];

fn in_tun_subnet(ip: std::net::IpAddr) -> bool {
    match ip {
        // 172.18.0.0/30
        std::net::IpAddr::V4(v4) => v4.octets()[..3] == [172, 18, 0] && v4.octets()[3] < 4,
        // fdfe:dcba:9876::/126
        std::net::IpAddr::V6(v6) => {
            let s = v6.segments();
            s[..7] == [0xfdfe, 0xdcba, 0x9876, 0, 0, 0, 0] && s[7] < 4
        }
    }
}

/// Real upstream DNS servers from a resolv.conf-style file (systemd-resolved's
/// /run/systemd/resolve/resolv.conf or a plain /etc/resolv.conf): skips loopback stubs
/// (127.0.0.53 is resolved itself — the loop), link-local scoped addresses and the
/// tun's own DNS left over from a previous connection.
pub fn upstream_nameservers(resolv_conf: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for line in resolv_conf.lines() {
        let mut parts = line.split_whitespace();
        if parts.next() != Some("nameserver") {
            continue;
        }
        let Some(Ok(ip)) = parts.next().map(|s| s.parse::<std::net::IpAddr>()) else { continue };
        if ip.is_loopback() || ip.is_unspecified() || in_tun_subnet(ip) {
            continue;
        }
        let s = ip.to_string();
        if !out.contains(&s) {
            out.push(s);
        }
    }
    out
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
        outbounds.extend(opts.extra_outbounds.iter().cloned());
    }
    let extra_tags: Vec<String> = if has_proxy {
        opts.extra_outbounds
            .iter()
            .filter_map(|o| o["tag"].as_str().map(str::to_string))
            .collect()
    } else {
        Vec::new()
    };

    // Without an active proxy, everything is direct and no proxy-targeted rules apply.
    // Rules pointing at a pinned profile that isn't available fall back to the proxy.
    let known = |tag: &str| tag == "proxy" || extra_tags.iter().any(|t| t == tag);
    let (user_rules, rule_sets, final_tag): (Vec<Value>, Vec<Value>, String) = if has_proxy {
        (
            opts.route_rules
                .iter()
                .map(|r| match r["outbound"].as_str() {
                    Some(t) if t.starts_with("via-") && !known(t) => {
                        let mut r = r.clone();
                        r["outbound"] = json!("proxy");
                        r
                    }
                    _ => r.clone(),
                })
                .collect(),
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
    // exposed; the app points the OS system proxy at it (in TUN mode too).
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
        let mut tun = json!({
            "type": "tun",
            "tag": "tun-in",
            "address": if opts.tun_ipv6 { &TUN_ADDRESSES[..] } else { &TUN_ADDRESSES[..1] },
            "auto_route": true,
            // strict_route stays off: the app stops the core with a hard kill, and
            // strict rules could leave the machine without internet after an
            // unclean exit. Wintun + its routes are removed when the process dies.
            "strict_route": false,
            "stack": "mixed"
        });
        if cfg!(target_os = "linux") {
            // Fixed name: the one-time setup allows it in ufw / firewalld (the "mixed"
            // stack hands TCP back through the tun as inbound packets). Keep in sync
            // with platform::linux::IFACE.
            tun["interface_name"] = json!(TUN_IFACE_LINUX);
        }
        inbounds.insert(0, tun);
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
    // In TUN mode with a known upstream the core dials it itself: its own sockets are
    // bound to the physical interface (auto_detect_interface), so the query never
    // re-enters the tun.
    let dns_direct = match opts.direct_dns.first() {
        Some(server) if opts.tun => json!({ "type": "udp", "tag": "dns-direct", "server": server }),
        _ => json!({ "type": "local", "tag": "dns-direct" }),
    };
    let mut servers = vec![dns_direct];
    let mut dns_rules = Vec::new();
    if doh {
        servers.push(json!({
            "type": "https", "tag": "doh-proxy", "server": "1.1.1.1", "detour": "proxy"
        }));
        // Pinned profiles resolve through their own tunnel, too.
        for tag in &extra_tags {
            servers.push(json!({
                "type": "https", "tag": format!("doh-{tag}"), "server": "1.1.1.1", "detour": tag
            }));
        }
        for rule in &user_rules {
            let server = match rule.get("outbound").and_then(|o| o.as_str()) {
                Some("proxy") => "doh-proxy".to_string(),
                Some(t) if extra_tags.iter().any(|e| e == t) => format!("doh-{t}"),
                // Direct rules still take their DNS slot in order, or a narrower direct
                // service would resolve through a broader proxied one.
                Some("direct") => "dns-direct".to_string(),
                _ => continue,
            };
            let mut dns_rule = serde_json::Map::new();
            for key in DOMAIN_KEYS {
                if let Some(v) = rule.get(key) {
                    dns_rule.insert(key.into(), v.clone());
                }
            }
            // Domain lists (geosite, antifilter domains) can drive DNS too; IP lists can't.
            if let Some(sets) = rule.get("rule_set").and_then(|v| v.as_array()) {
                let domain_sets: Vec<Value> = sets
                    .iter()
                    .filter(|t| t.as_str().is_some_and(|t| t.contains("geosite") || t == "antifilter-domains"))
                    .cloned()
                    .collect();
                if !domain_sets.is_empty() {
                    dns_rule.insert("rule_set".into(), json!(domain_sets));
                }
            }
            if !dns_rule.is_empty() {
                dns_rule.insert("server".into(), json!(server));
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
    fn antifilter_domains_resolve_through_the_tunnel() {
        let opts = GenOptions {
            route_rules: vec![
                json!({ "ip_is_private": true, "outbound": "direct" }),
                json!({ "rule_set": ["antifilter-domains", "antifilter-ip"], "outbound": "proxy" }),
            ],
            ..only_youtube()
        };
        let cfg = generate(&opts);
        let dns_rules = cfg["dns"]["rules"].as_array().unwrap();
        // The domain list drives DNS (a poisoned answer from the ISP is avoided); the IP list can't.
        assert_eq!(dns_rules.len(), 1);
        assert_eq!(dns_rules[0]["rule_set"], json!(["antifilter-domains"]));
        assert_eq!(dns_rules[0]["server"], "doh-proxy");
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
    fn tun_with_upstream_dials_dns_itself() {
        let direct_dns = vec!["192.168.1.1".to_string(), "1.1.1.1".to_string()];
        let cfg = generate(&GenOptions { tun: true, direct_dns: direct_dns.clone(), ..only_youtube() });
        let direct = &cfg["dns"]["servers"][0];
        assert_eq!(direct["tag"], "dns-direct");
        assert_eq!(direct["type"], "udp");
        assert_eq!(direct["server"], "192.168.1.1");
        // Outbound server domains still resolve through it.
        assert_eq!(cfg["route"]["default_domain_resolver"]["server"], "dns-direct");

        // Without TUN nothing captures the resolver's queries: keep the system resolver.
        let cfg = generate(&GenOptions { direct_dns, ..only_youtube() });
        assert_eq!(cfg["dns"]["servers"][0]["type"], "local");
        // TUN without a known upstream: also the system resolver (Windows, macOS).
        let cfg = generate(&GenOptions { tun: true, ..only_youtube() });
        assert_eq!(cfg["dns"]["servers"][0]["type"], "local");
    }

    #[test]
    fn tun_ipv6_address_only_with_ipv6_uplink() {
        let cfg = generate(&GenOptions { tun: true, ..only_youtube() });
        assert_eq!(cfg["inbounds"][0]["address"], json!(["172.18.0.1/30", "fdfe:dcba:9876::1/126"]));
        let cfg = generate(&GenOptions { tun: true, tun_ipv6: false, ..only_youtube() });
        assert_eq!(cfg["inbounds"][0]["address"], json!(["172.18.0.1/30"]));
    }

    #[test]
    fn global_ipv6_ignores_link_local_ula_tun_and_virtual() {
        // No IPv6 from the ISP: link-local, loopback, the tun's ULA only.
        let none = "fe80000000000000bf77d3fbb64bb2e6 02 40 20 80  enp34s0\n\
                    00000000000000000000000000000001 01 80 10 80       lo\n\
                    fdfedcba987600000000000000000001 24 7e 00 80    ttcm0\n\
                    fd000000000000000000000000000001 05 40 00 80  enp34s0\n\
                    2a0200000000000000000000000000aa 06 40 00 80  docker0";
        assert!(!has_global_ipv6(none));
        let real = format!("{none}\n2a0206b8000000000000000000000001 02 40 00 00  enp34s0");
        assert!(has_global_ipv6(&real));
    }

    #[test]
    fn upstream_nameservers_skip_stub_and_tun() {
        let resolved = "# This is /run/systemd/resolve/resolv.conf\n\
                        nameserver 192.168.20.1\n\
                        nameserver 1.1.1.1\n\
                        nameserver 172.18.0.2\n\
                        nameserver fdfe:dcba:9876::2\n\
                        nameserver 2606:4700:4700::1111\n\
                        nameserver 1.1.1.1\n\
                        search lan\n";
        assert_eq!(upstream_nameservers(resolved), ["192.168.20.1", "1.1.1.1", "2606:4700:4700::1111"]);
        let stub = "# Generated by NetworkManager\nnameserver 127.0.0.53\noptions edns0 trust-ad\n";
        assert!(upstream_nameservers(stub).is_empty());
        assert_eq!(upstream_nameservers("nameserver fe80::1%enp34s0\nnameserver ::1\nnameserver 9.9.9.9"), ["9.9.9.9"]);
    }

    #[test]
    fn tun_interface_name_is_fixed_on_linux_only() {
        let cfg = generate(&GenOptions { tun: true, ..only_youtube() });
        let name = cfg["inbounds"][0].get("interface_name");
        if cfg!(target_os = "linux") {
            assert_eq!(name.and_then(|v| v.as_str()), Some("ttcm0"));
        } else {
            assert!(name.is_none());
        }
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
    fn pinned_profile_gets_outbound_and_its_own_dns() {
        let mut via = proxy();
        via["tag"] = json!("via-p2");
        let cfg = generate(&GenOptions {
            extra_outbounds: vec![via],
            route_rules: vec![
                json!({ "domain_suffix": ["gemini.google.com"], "outbound": "via-p2" }),
                json!({ "domain_suffix": ["x.com"], "outbound": "via-gone" }),
            ],
            final_action: "direct".into(),
            ..only_youtube()
        });
        let tags: Vec<&str> = cfg["outbounds"].as_array().unwrap().iter().filter_map(|o| o["tag"].as_str()).collect();
        assert!(tags.contains(&"via-p2"));
        let rules = cfg["route"]["rules"].as_array().unwrap();
        // unknown pinned profile falls back to the active proxy
        assert!(rules.iter().any(|r| r["domain_suffix"][0] == "x.com" && r["outbound"] == "proxy"));
        let servers = cfg["dns"]["servers"].as_array().unwrap();
        assert!(servers.iter().any(|s| s["tag"] == "doh-via-p2" && s["detour"] == "via-p2"));
        let dns_rules = cfg["dns"]["rules"].as_array().unwrap();
        assert!(dns_rules.iter().any(|r| r["domain_suffix"][0] == "gemini.google.com" && r["server"] == "doh-via-p2"));
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
