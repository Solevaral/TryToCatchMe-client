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
    /// Network interface the `direct` outbound is bound to (`bind_interface`), e.g. the
    /// adapter of another full-tunnel VPN (WireGuard), so direct traffic goes through it
    /// instead of the physical uplink `auto_detect_interface` picks. The `proxy`
    /// outbound is left alone (the server is still reached over the uplink) unless
    /// `proxy_via_direct_interface` is on.
    /// `None` => no binding, the config is exactly as without this option.
    pub direct_interface: Option<String>,
    /// Also bind the proxy outbounds (`proxy` and the pinned `via-*` ones) to
    /// `direct_interface`: the VPN server itself is then reached through the other VPN
    /// (helps when the local ISP blocks the server). No effect without `direct_interface`.
    pub proxy_via_direct_interface: bool,
    /// TUN + `direct_interface`: traffic of these programs (e.g. the other VPN's own
    /// client, `wireguard.exe`) goes to `direct-physical` — the uplink without the
    /// binding — instead of looping back into the other VPN's tunnel through `direct`.
    pub tun_bypass_processes: Vec<String>,
    /// Same for these destinations (CIDRs, e.g. the other VPN's server): also excluded
    /// from the TUN routes. Ignored outside TUN + `direct_interface`.
    pub tun_bypass_cidrs: Vec<String>,
    /// Built-in WireGuard: the active tunnel's sing-box endpoint (tag `wg`, see
    /// `wireguard::endpoint`). When set, the external-interface options above are
    /// ignored — the built-in tunnel replaces them.
    pub wg: Option<Value>,
    /// The tunnel's DNS servers (IPs): direct domains resolve through them when direct
    /// traffic goes through the tunnel.
    pub wg_dns: Vec<String>,
    /// The networks the tunnel is for (its AllowedIPs without the catch-all ranges,
    /// e.g. a home LAN): always routed into it, whatever the modes.
    pub wg_routes: Vec<String>,
    /// Direct traffic (rules/final `direct`) goes through the tunnel; LAN stays local.
    pub direct_via_wg: bool,
    /// The proxy outbounds dial the VPN server through the tunnel (`detour`).
    pub proxy_via_wg: bool,
    /// "Through the ISP": domains (and their subdomains) / IPs / CIDRs that go straight
    /// out of the physical uplink — past the tunnel and past the VPN.
    pub provider_list: Vec<String>,
    /// The same for services picked from the catalog (their domains, as suffixes, and
    /// IP ranges — see `provider_from_services`).
    pub provider_service_domains: Vec<String>,
    pub provider_service_cidrs: Vec<String>,
    /// IPv4 only, everywhere: DNS answers A records only (TUN apps, the tunnel, direct
    /// sites), and VPN destinations are resolved here and handed to the server as IPv4
    /// addresses — it can no longer pick IPv6 for some connections and IPv4 for others,
    /// so sites like Google see one IP per session instead of two.
    pub ipv4_only: bool,
}

/// A "through the ISP" entry: an IP/CIDR, or a domain (also pasted as a URL or
/// `*.domain`). `None` for garbage.
pub enum ProviderEntry {
    Cidr(String),
    Domain(String),
}

pub fn provider_entry(entry: &str) -> Option<ProviderEntry> {
    let e = entry.trim();
    if let Some(c) = bypass_cidr(e) {
        return Some(ProviderEntry::Cidr(c));
    }
    let e = e.strip_prefix("https://").or_else(|| e.strip_prefix("http://")).unwrap_or(e);
    let host = e.split(['/', '?', '#']).next().unwrap_or("");
    let host = host.trim_start_matches("*.").trim_start_matches('.').trim_end_matches('.').to_lowercase();
    let valid = host.contains('.')
        && host.split('.').all(|l| !l.is_empty() && l.chars().all(|c| c.is_alphanumeric() || c == '-'));
    valid.then_some(ProviderEntry::Domain(host))
}

/// The "through the ISP" list split into (domain suffixes, CIDRs); garbage is dropped.
pub fn split_provider_list(list: &[String]) -> (Vec<String>, Vec<String>) {
    let (mut domains, mut cidrs) = (Vec::new(), Vec::new());
    for e in list {
        match provider_entry(e) {
            Some(ProviderEntry::Domain(d)) if !domains.contains(&d) => domains.push(d),
            Some(ProviderEntry::Cidr(c)) if !cidrs.contains(&c) => cidrs.push(c),
            _ => {}
        }
    }
    (domains, cidrs)
}

/// Domains (suffixes, as the catalog has them — single labels like `google` included)
/// and CIDRs of the picked services, without duplicates; unknown ids are skipped.
pub fn provider_from_services(catalog: &[crate::routing::Service], ids: &[String]) -> (Vec<String>, Vec<String>) {
    let (mut domains, mut cidrs): (Vec<String>, Vec<String>) = (Vec::new(), Vec::new());
    for svc in catalog.iter().filter(|s| ids.contains(&s.id)) {
        for d in &svc.domains {
            let d = d.trim().trim_start_matches("*.").trim_start_matches('.').to_lowercase();
            if !d.is_empty() && !domains.contains(&d) {
                domains.push(d);
            }
        }
        for c in svc.ip_cidrs.iter().filter_map(|c| bypass_cidr(c)) {
            if !cidrs.contains(&c) {
                cidrs.push(c);
            }
        }
    }
    (domains, cidrs)
}

/// An IP or CIDR from the bypass list as a CIDR (`1.2.3.4` → `1.2.3.4/32`); `None`
/// for anything else (a domain, a typo).
pub fn bypass_cidr(entry: &str) -> Option<String> {
    let entry = entry.trim();
    let (ip, prefix) = match entry.split_once('/') {
        Some((ip, p)) => (ip, Some(p.parse::<u8>().ok()?)),
        None => (entry, None),
    };
    let ip: std::net::IpAddr = ip.parse().ok()?;
    let max = if ip.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.unwrap_or(max);
    (prefix <= max).then(|| format!("{ip}/{prefix}"))
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
            direct_interface: None,
            proxy_via_direct_interface: false,
            tun_bypass_processes: Vec::new(),
            tun_bypass_cidrs: Vec::new(),
            wg: None,
            wg_dns: Vec::new(),
            wg_routes: Vec::new(),
            direct_via_wg: false,
            proxy_via_wg: false,
            provider_list: Vec::new(),
            provider_service_domains: Vec::new(),
            provider_service_cidrs: Vec::new(),
            ipv4_only: false,
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

/// Windows: does an `alias|ip|description` listing (IPv6 addresses with their adapter)
/// show a usable IPv6 uplink — a global unicast address (2000::/3) on a physical
/// adapter? Link-local, ULA (the tun's own fdfe::), the TUN / VPN / virtual adapters
/// don't count. Same idea as `has_global_ipv6` for Linux.
pub fn has_global_ipv6_windows(listing: &str) -> bool {
    listing.lines().any(|line| {
        let mut f = line.splitn(3, '|');
        let (Some(alias), Some(ip), desc) = (f.next(), f.next(), f.next()) else { return false };
        let Ok(ip) = ip.trim().split('%').next().unwrap_or("").parse::<std::net::Ipv6Addr>() else { return false };
        ip.segments()[0] & 0xe000 == 0x2000 && !crate::gateway::is_virtual(alias.trim(), desc.unwrap_or("").trim())
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
    let wg = opts.wg.as_ref();
    // The built-in tunnel replaces the external-interface options.
    let legacy_iface = if wg.is_some() { None } else { opts.direct_interface.as_ref() };
    let direct_via_wg = wg.is_some() && opts.direct_via_wg;
    let wg_tag = crate::wireguard::WG_TAG;

    // `direct` goes first so any of sing-box's own traffic without an explicit detour
    // doesn't silently depend on the proxy. User traffic is steered explicitly by
    // `route.rules` / `route.final`; geo lists set their own detour.
    let mut direct = json!({ "type": "direct", "tag": "direct" });
    if let Some(iface) = legacy_iface {
        direct["bind_interface"] = json!(iface);
    }
    let mut outbounds = vec![direct];
    if let Some(proxy) = &opts.proxy_outbound {
        outbounds.push(proxy.clone());
        outbounds.extend(opts.extra_outbounds.iter().cloned());
        if let (Some(iface), true) = (legacy_iface, opts.proxy_via_direct_interface) {
            for o in &mut outbounds[1..] {
                o["bind_interface"] = json!(iface);
            }
        }
        // VPN over the tunnel: the VPN server is dialed through it.
        if wg.is_some() && opts.proxy_via_wg {
            for o in &mut outbounds[1..] {
                o["detour"] = json!(wg_tag);
            }
        }
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
    // Direct traffic through the tunnel: `direct` targets become the tunnel, except the
    // routing layer's LAN rule (a home network must stay reachable).
    let (user_rules, final_tag) = if direct_via_wg {
        let rules = user_rules
            .into_iter()
            .map(|mut r| {
                if r["outbound"] == "direct" && r.get("ip_is_private").is_none() {
                    r["outbound"] = json!(wg_tag);
                }
                r
            })
            .collect();
        let fin = if final_tag == "direct" { wg_tag.to_string() } else { final_tag };
        (rules, fin)
    } else {
        (user_rules, final_tag)
    };
    let (mut provider_domains, mut provider_cidrs) = split_provider_list(&opts.provider_list);
    for d in &opts.provider_service_domains {
        if !provider_domains.contains(d) {
            provider_domains.push(d.clone());
        }
    }
    for c in &opts.provider_service_cidrs {
        if !provider_cidrs.contains(c) {
            provider_cidrs.push(c.clone());
        }
    }
    let has_provider = !provider_domains.is_empty() || !provider_cidrs.is_empty();

    // Rule order matters:
    // 1. sniff — recover the domain (TLS SNI / HTTP Host / QUIC) from raw
    //    connections. Without it, TUN traffic is just IPs and domain rules
    //    (services, geosite) never match, so e.g. YouTube would fall to `final`.
    // 2. hijack-dns — in TUN mode, answer the system's DNS queries ourselves.
    // 3. optional QUIC block, then the routing layer's rules.
    // 0. TUN with direct bound to another VPN's tunnel: that VPN's own packets (its
    //    client process, its server address) leave through the uplink unbound —
    //    through `direct` they'd loop back into its tunnel. First, before anything
    //    else can claim them.
    let mut rules = Vec::new();
    let bypass = opts.tun && legacy_iface.is_some();
    // An unbound direct (auto_detect_interface puts it on the physical uplink), needed
    // whenever `direct` itself is bound to another VPN's adapter.
    let physical = bypass || (has_provider && legacy_iface.is_some());
    if physical {
        outbounds.push(json!({ "type": "direct", "tag": "direct-physical" }));
    }
    if bypass {
        if !opts.tun_bypass_processes.is_empty() {
            rules.push(json!({ "process_name": opts.tun_bypass_processes, "outbound": "direct-physical" }));
        }
        if !opts.tun_bypass_cidrs.is_empty() {
            rules.push(json!({ "ip_cidr": opts.tun_bypass_cidrs, "outbound": "direct-physical" }));
        }
    }
    rules.push(json!({ "action": "sniff" }));
    if opts.tun {
        rules.push(json!({ "protocol": "dns", "action": "hijack-dns" }));
    }
    // IPv4 only: resolve here, before any rule sends the connection on (domain rules
    // still match: the sniffed name is kept).
    if opts.ipv4_only && has_proxy {
        rules.push(json!({ "action": "resolve", "strategy": "ipv4_only" }));
    }
    // The app's own geo-list downloads always go through the VPN (the ISP often
    // blocks raw.githubusercontent.com), regardless of the routing mode.
    if has_proxy {
        rules.push(json!({ "inbound": ["geo-in"], "outbound": "proxy" }));
    }
    if has_proxy && opts.block_quic {
        rules.push(json!({ "network": "udp", "port": 443, "action": "reject" }));
    }
    // 4. The tunnel's own networks (a home LAN behind it) go into it — before the local
    //    LAN rule, which would otherwise claim these private ranges.
    if wg.is_some() && !opts.wg_routes.is_empty() {
        rules.push(json!({ "ip_cidr": opts.wg_routes, "outbound": wg_tag }));
    }
    //    Direct through the tunnel: the LAN stays local whatever the routing layer says.
    if direct_via_wg {
        rules.push(json!({ "ip_is_private": true, "outbound": "direct" }));
    }
    // 5. "Through the ISP": straight out of the physical uplink, before any service or
    //    list could send these sites into the VPN or the tunnel.
    let provider_tag = if physical { "direct-physical" } else { "direct" };
    if !provider_domains.is_empty() {
        rules.push(json!({ "domain_suffix": provider_domains, "outbound": provider_tag }));
    }
    if !provider_cidrs.is_empty() {
        rules.push(json!({ "ip_cidr": provider_cidrs, "outbound": provider_tag }));
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
        // Keep the bypassed addresses off the tun altogether (the route rule above
        // still catches packets that reach it anyway, e.g. a socket bound to the tun).
        if bypass && !opts.tun_bypass_cidrs.is_empty() {
            tun["route_exclude_address"] = json!(opts.tun_bypass_cidrs);
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
    if let Some(ep) = wg {
        cfg["endpoints"] = json!([ep]);
    }

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
    // Direct through the tunnel: direct domains resolve with the tunnel's DNS (the ISP's
    // resolver may lie about sites it blocks). Server domains (the tunnel's own endpoint
    // included) still use `dns-direct` via default_domain_resolver — no chicken-and-egg.
    let dns_wg = direct_via_wg && !opts.wg_dns.is_empty();
    if dns_wg {
        servers.push(json!({ "type": "udp", "tag": "dns-wg", "server": opts.wg_dns[0], "detour": wg_tag }));
    }
    let tunnel_dns = if dns_wg { "dns-wg" } else { "dns-direct" };
    if (doh || dns_wg) && !provider_domains.is_empty() {
        dns_rules.push(json!({ "domain_suffix": provider_domains, "server": "dns-direct" }));
    }
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
                Some(t) if t == wg_tag => tunnel_dns.to_string(),
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
    } else if final_tag == wg_tag {
        tunnel_dns
    } else {
        "dns-direct"
    };
    cfg["dns"] = json!({ "servers": servers, "rules": dns_rules, "final": dns_final });
    // Direct traffic through a tunnel without an IPv6 address: an AAAA answer would send
    // the connection into the tunnel over IPv6, which it can't carry ("missing IPv6
    // local address") — dual-stack sites (Cloudflare & co.) just failed. A records only.
    // The same when the user asked for IPv4 only (the system's own lookups in TUN too).
    let wg_has_ipv6 = wg.is_some_and(|ep| {
        ep["address"].as_array().is_some_and(|a| a.iter().any(|x| x.as_str().is_some_and(|s| s.contains(':'))))
    });
    if opts.ipv4_only || (direct_via_wg && !wg_has_ipv6) {
        cfg["dns"]["strategy"] = json!("ipv4_only");
    }

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
    fn windows_ipv6_uplink_only_counts_global_on_physical() {
        // The user's machine: no IPv6 from the ISP — only link-local and the tun's ULA.
        let none = "Ethernet|fe80::746c:89d9:ef04:4a3c%11|Realtek PCIe GbE Family Controller
\n                    Loopback Pseudo-Interface 1|::1|
\n                    tun0|fdfe:dcba:9876::1|sing-tun Tunnel
";
        assert!(!has_global_ipv6_windows(none));
        // A real global address on the network card.
        let real = format!("{none}Ethernet|2a02:6b8:1::5|Realtek PCIe GbE Family Controller
");
        assert!(has_global_ipv6_windows(&real));
        // Global addresses on VPN / virtual adapters don't count.
        assert!(!has_global_ipv6_windows("all-rodoro-home|2001:db8::3|WireGuard Tunnel
vEthernet (WSL)|2001:db8::4|Hyper-V Virtual Ethernet Adapter
tun0|2001:db8::5|sing-tun Tunnel"));
        assert!(!has_global_ipv6_windows("garbage
||
Ethernet|not-an-ip|x"));
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

    #[test]
    fn direct_is_unbound_by_default() {
        let cfg = generate(&only_youtube());
        assert_eq!(cfg["outbounds"][0], json!({ "type": "direct", "tag": "direct" }));
        assert_eq!(cfg["route"]["auto_detect_interface"], true);
    }

    #[test]
    fn direct_interface_binds_only_direct() {
        let base = generate(&only_youtube());
        let cfg = generate(&GenOptions { direct_interface: Some("all-rodoro-home".into()), ..only_youtube() });
        assert_eq!(
            cfg["outbounds"][0],
            json!({ "type": "direct", "tag": "direct", "bind_interface": "all-rodoro-home" })
        );
        assert_eq!(cfg["outbounds"][1], proxy());
        // Everything else (proxy outbound, auto_detect_interface, DNS, rules) is unchanged.
        let mut expected = base;
        expected["outbounds"][0]["bind_interface"] = json!("all-rodoro-home");
        assert_eq!(cfg, expected);
    }

    #[test]
    fn direct_interface_keeps_reject_rules_and_proxy() {
        let iface = Some("all-rodoro-home".to_string());
        for tun in [false, true] {
            let base = GenOptions { block_quic: true, tun, ..only_youtube() };
            let before = generate(&base);
            let after = generate(&GenOptions { direct_interface: iface.clone(), ..base });
            let rejects = |cfg: &Value| -> Vec<Value> {
                cfg["route"]["rules"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .filter(|r| r["action"] == "reject")
                    .cloned()
                    .collect()
            };
            // QUIC block + the "blocked" service.
            assert_eq!(rejects(&before).len(), 2);
            assert_eq!(rejects(&after), rejects(&before));
            assert_eq!(after["route"]["rules"], before["route"]["rules"]);
            assert_eq!(after["outbounds"][1], proxy());
            assert_eq!(after["route"]["auto_detect_interface"], true);
        }
    }

    fn pinned() -> GenOptions {
        GenOptions {
            extra_outbounds: vec![json!({ "type": "trojan", "tag": "via-p2", "server": "b.com", "server_port": 443 })],
            block_quic: true,
            ..only_youtube()
        }
    }

    #[test]
    fn proxy_via_interface_off_changes_nothing() {
        let base = generate(&GenOptions { direct_interface: Some("wg0".into()), ..pinned() });
        let cfg = generate(&GenOptions {
            direct_interface: Some("wg0".into()),
            proxy_via_direct_interface: false,
            ..pinned()
        });
        assert_eq!(cfg, base);
        assert!(cfg["outbounds"].as_array().unwrap()[1..].iter().all(|o| o.get("bind_interface").is_none()));
    }

    #[test]
    fn proxy_via_interface_binds_all_proxy_outbounds() {
        let base = generate(&GenOptions { direct_interface: Some("wg0".into()), ..pinned() });
        let cfg = generate(&GenOptions {
            direct_interface: Some("wg0".into()),
            proxy_via_direct_interface: true,
            ..pinned()
        });
        let outbounds = cfg["outbounds"].as_array().unwrap();
        assert_eq!(outbounds.len(), 3);
        assert!(outbounds.iter().all(|o| o["bind_interface"] == "wg0"));
        // Only the outbounds change: route (incl. reject rules), DNS, inbounds stay as is.
        let mut expected = base;
        expected["outbounds"][1]["bind_interface"] = json!("wg0");
        expected["outbounds"][2]["bind_interface"] = json!("wg0");
        assert_eq!(cfg, expected);
    }

    fn tun_bypass(tun: bool, iface: Option<&str>) -> GenOptions {
        GenOptions {
            tun,
            direct_interface: iface.map(str::to_string),
            tun_bypass_processes: vec!["wireguard.exe".into(), "openvpn.exe".into()],
            tun_bypass_cidrs: vec!["46.138.253.10/32".into()],
            ..pinned()
        }
    }

    #[test]
    fn tun_bypass_goes_first_to_unbound_direct() {
        let cfg = generate(&tun_bypass(true, Some("wg0")));
        let outbounds = cfg["outbounds"].as_array().unwrap();
        let physical = outbounds.iter().find(|o| o["tag"] == "direct-physical").unwrap();
        assert_eq!(physical, &json!({ "type": "direct", "tag": "direct-physical" }));
        assert_eq!(outbounds[0]["bind_interface"], "wg0");
        let rules = cfg["route"]["rules"].as_array().unwrap();
        assert_eq!(
            rules[0],
            json!({ "process_name": ["wireguard.exe", "openvpn.exe"], "outbound": "direct-physical" })
        );
        assert_eq!(rules[1], json!({ "ip_cidr": ["46.138.253.10/32"], "outbound": "direct-physical" }));
        assert_eq!(rules[2]["action"], "sniff");
        assert_eq!(cfg["inbounds"][0]["route_exclude_address"], json!(["46.138.253.10/32"]));
        // The rest is the plain TUN + direct_interface config.
        let mut expected = generate(&GenOptions {
            tun_bypass_processes: Vec::new(),
            tun_bypass_cidrs: Vec::new(),
            ..tun_bypass(true, Some("wg0"))
        });
        let r = expected["route"]["rules"].as_array_mut().unwrap();
        r.insert(0, rules[1].clone());
        r.insert(0, rules[0].clone());
        expected["inbounds"][0]["route_exclude_address"] = json!(["46.138.253.10/32"]);
        assert_eq!(cfg, expected);
    }

    #[test]
    fn tun_bypass_only_with_tun_and_direct_interface() {
        // No TUN or no interface: the lists change nothing.
        for (tun, iface) in [(false, Some("wg0")), (true, None), (false, None)] {
            let cfg = generate(&tun_bypass(tun, iface));
            let plain = generate(&GenOptions {
                tun_bypass_processes: Vec::new(),
                tun_bypass_cidrs: Vec::new(),
                ..tun_bypass(tun, iface)
            });
            assert_eq!(cfg, plain);
            assert!(cfg["outbounds"].as_array().unwrap().iter().all(|o| o["tag"] != "direct-physical"));
            assert!(!to_string(&cfg).contains("process_name"));
        }
        // TUN + interface with empty lists: just the spare outbound, no rules.
        let cfg = generate(&GenOptions {
            tun_bypass_processes: Vec::new(),
            tun_bypass_cidrs: Vec::new(),
            ..tun_bypass(true, Some("wg0"))
        });
        assert_eq!(cfg["route"]["rules"][0]["action"], "sniff");
        assert!(cfg["inbounds"][0].get("route_exclude_address").is_none());
    }

    #[test]
    fn bypass_entries_become_cidrs() {
        assert_eq!(bypass_cidr(" 46.138.253.10 ").as_deref(), Some("46.138.253.10/32"));
        assert_eq!(bypass_cidr("10.0.0.0/8").as_deref(), Some("10.0.0.0/8"));
        assert_eq!(bypass_cidr("2001:db8::1").as_deref(), Some("2001:db8::1/128"));
        assert_eq!(bypass_cidr("1.2.3.4/33"), None);
        assert_eq!(bypass_cidr("home.example.com"), None);
    }

    // ---- built-in WireGuard ----

    fn wg_tunnel() -> crate::wireguard::WgTunnel {
        let conf = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.6.0.3/32\nDNS = 10.6.0.1\n\
                    [Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 0.0.0.0/1, 128.0.0.0/1\nEndpoint = 46.138.253.10:51820\n";
        let (interface, peers) = crate::wireguard::parse_conf(conf).unwrap();
        crate::wireguard::WgTunnel { id: "t".into(), name: "home".into(), interface, peers }
    }

    /// Rule mode with services, a pinned profile, a direct list and LAN — plus the tunnel.
    fn with_wg(direct: bool, vpn_over: bool) -> GenOptions {
        let t = wg_tunnel();
        GenOptions {
            route_rules: vec![
                json!({ "ip_is_private": true, "outbound": "direct" }),
                json!({ "domain_suffix": ["chatgpt.com"], "outbound": "proxy" }),
                json!({ "domain_suffix": ["ru"], "outbound": "direct" }),
                json!({ "domain_suffix": ["blocked.example"], "outbound": "block" }),
            ],
            wg: Some(crate::wireguard::endpoint(&t, "wg", direct || vpn_over)),
            wg_dns: crate::wireguard::dns_servers(&t.interface),
            direct_via_wg: direct,
            proxy_via_wg: vpn_over,
            ..pinned()
        }
    }

    fn rules(cfg: &Value) -> &Vec<Value> {
        cfg["route"]["rules"].as_array().unwrap()
    }

    #[test]
    fn wg_endpoint_is_added_and_never_routed_into_itself() {
        for (direct, vpn_over, tun) in [(false, false, false), (true, false, true), (true, true, true), (false, true, false)] {
            let cfg = generate(&GenOptions { tun, ..with_wg(direct, vpn_over) });
            let eps = cfg["endpoints"].as_array().unwrap();
            assert_eq!(eps.len(), 1);
            assert_eq!(eps[0]["tag"], "wg");
            // The endpoint dials its server itself on the uplink: no detour or binding,
            // and no rule anywhere sends traffic for its server into the tunnel.
            assert!(eps[0].get("detour").is_none() && eps[0].get("bind_interface").is_none());
            assert!(!to_string(&cfg["route"]).contains("46.138.253.10"));
            assert_eq!(cfg["route"]["default_domain_resolver"]["server"], "dns-direct");
            assert_eq!(cfg["route"]["auto_detect_interface"], true);
            // The plain direct outbound is never bound or detoured.
            assert_eq!(cfg["outbounds"][0], json!({ "type": "direct", "tag": "direct" }));
        }
    }

    /// A home-network-only `.conf` (the real case that broke: no internet through it).
    fn split_tunnel() -> crate::wireguard::WgTunnel {
        let conf = "[Interface]\nPrivateKey = yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=\nAddress = 10.6.0.3/32\nDNS = 1.1.1.1\n\
                    [Peer]\nPublicKey = xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=\nAllowedIPs = 10.6.0.0/24, 192.168.10.0/24, 192.168.20.0/24\nEndpoint = 46.138.253.10:51820\n";
        let (interface, peers) = crate::wireguard::parse_conf(conf).unwrap();
        crate::wireguard::WgTunnel { id: "s".into(), name: "home".into(), interface, peers }
    }

    #[test]
    fn split_tunnel_carries_internet_when_a_mode_uses_it() {
        let t = split_tunnel();
        // A mode sends internet traffic in: the peer must accept any destination.
        for (direct, vpn_over) in [(true, false), (false, true), (true, true)] {
            let cfg = generate(&GenOptions {
                wg: Some(crate::wireguard::endpoint(&t, "wg", direct || vpn_over)),
                wg_routes: crate::wireguard::routed_subnets(&t),
                ..with_wg(direct, vpn_over)
            });
            assert_eq!(cfg["endpoints"][0]["peers"][0]["allowed_ips"], json!(["0.0.0.0/0", "::/0"]));
        }
        // Tunnel only for the home network: AllowedIPs as in the file.
        let ep = crate::wireguard::endpoint(&t, "wg", false);
        assert_eq!(ep["peers"][0]["allowed_ips"], json!(["10.6.0.0/24", "192.168.10.0/24", "192.168.20.0/24"]));
    }

    #[test]
    fn tunnel_subnets_go_into_the_tunnel_before_the_lan_rule() {
        let t = split_tunnel();
        for direct in [false, true] {
            let cfg = generate(&GenOptions {
                wg: Some(crate::wireguard::endpoint(&t, "wg", direct)),
                wg_routes: crate::wireguard::routed_subnets(&t),
                ..with_wg(direct, false)
            });
            let r = rules(&cfg);
            let sub = r
                .iter()
                .position(|x| x == &json!({ "ip_cidr": ["10.6.0.0/24", "192.168.10.0/24", "192.168.20.0/24"], "outbound": "wg" }))
                .unwrap();
            let lan = r.iter().position(|x| x.get("ip_is_private").is_some()).unwrap();
            assert!(sub < lan, "{r:?}");
        }
        // Catch-all AllowedIPs aren't subnets to route: that's the modes' job.
        assert!(crate::wireguard::routed_subnets(&wg_tunnel()).is_empty());
        // No tunnel: no such rule.
        let cfg = generate(&GenOptions { wg: None, wg_routes: vec!["192.168.10.0/24".into()], ..pinned() });
        assert!(!to_string(&cfg).contains("192.168.10.0/24"));
    }

    #[test]
    fn wg_connected_but_unused_changes_only_endpoints() {
        let cfg = generate(&with_wg(false, false));
        let mut plain = generate(&GenOptions { wg: None, wg_dns: Vec::new(), ..with_wg(false, false) });
        plain["endpoints"] = cfg["endpoints"].clone();
        assert_eq!(cfg, plain);
    }

    #[test]
    fn direct_via_wg_moves_direct_traffic_into_the_tunnel() {
        let cfg = generate(&with_wg(true, false));
        assert_eq!(cfg["route"]["final"], "wg");
        let r = rules(&cfg);
        // LAN pinned to the real direct before everything else from routing.
        let lan = r.iter().position(|x| x == &json!({ "ip_is_private": true, "outbound": "direct" })).unwrap();
        let ru = r.iter().position(|x| x["domain_suffix"] == json!(["ru"])).unwrap();
        assert!(lan < ru);
        assert_eq!(r[ru]["outbound"], "wg");
        // VPN services and blocks are untouched.
        assert!(r.iter().any(|x| x["domain_suffix"] == json!(["chatgpt.com"]) && x["outbound"] == "proxy"));
        assert!(r.iter().any(|x| x["domain_suffix"] == json!(["blocked.example"]) && x["action"] == "reject"));
        assert!(r.iter().all(|x| x["outbound"] != "direct" || x.get("ip_is_private").is_some()));
        // Proxy outbounds are not detoured in this mode.
        assert!(cfg["outbounds"].as_array().unwrap().iter().all(|o| o.get("detour").is_none()));
    }

    #[test]
    fn direct_via_wg_resolves_direct_domains_with_the_tunnel_dns() {
        let cfg = generate(&with_wg(true, false));
        let servers = cfg["dns"]["servers"].as_array().unwrap();
        assert!(servers.contains(&json!({ "type": "udp", "tag": "dns-wg", "server": "10.6.0.1", "detour": "wg" })));
        assert_eq!(cfg["dns"]["final"], "dns-wg");
        let dns_rules = cfg["dns"]["rules"].as_array().unwrap();
        assert!(dns_rules.contains(&json!({ "domain_suffix": ["ru"], "server": "dns-wg" })));
        assert!(dns_rules.contains(&json!({ "domain_suffix": ["chatgpt.com"], "server": "doh-proxy" })));
        // A tunnel without DNS: direct domains keep the system resolver.
        let mut opts = with_wg(true, false);
        opts.wg_dns.clear();
        let cfg = generate(&opts);
        assert!(cfg["dns"]["servers"].as_array().unwrap().iter().all(|s| s["tag"] != "dns-wg"));
        assert_eq!(cfg["dns"]["final"], "dns-direct");
    }

    #[test]
    fn ipv4_only_dns_when_direct_goes_into_a_v4_only_tunnel() {
        // wg_tunnel() has only 10.6.0.3/32: AAAA answers would die in it.
        let cfg = generate(&with_wg(true, false));
        assert_eq!(cfg["dns"]["strategy"], "ipv4_only");
        // Direct traffic through the ISP: nothing goes into the tunnel by default.
        let cfg = generate(&with_wg(false, true));
        assert!(cfg["dns"].get("strategy").is_none());
        // A tunnel with an IPv6 address carries IPv6: no restriction.
        let mut t = wg_tunnel();
        t.interface.addresses.push("fd00::3/128".into());
        let cfg = generate(&GenOptions { wg: Some(crate::wireguard::endpoint(&t, "wg", true)), ..with_wg(true, false) });
        assert!(cfg["dns"].get("strategy").is_none());
        // No tunnel: unchanged.
        assert!(generate(&pinned())["dns"].get("strategy").is_none());
    }

    #[test]
    fn vpn_over_wg_detours_every_proxy_outbound() {
        let cfg = generate(&with_wg(false, true));
        let outbounds = cfg["outbounds"].as_array().unwrap();
        assert_eq!(outbounds[1]["tag"], "proxy");
        assert_eq!(outbounds[1]["detour"], "wg");
        assert_eq!(outbounds[2]["tag"], "via-p2");
        assert_eq!(outbounds[2]["detour"], "wg");
        assert!(outbounds[0].get("detour").is_none());
        // Routing itself is the plain one: direct stays direct.
        assert_eq!(cfg["route"]["final"], "direct");
        let plain = generate(&GenOptions { proxy_via_wg: false, ..with_wg(false, true) });
        assert_eq!(cfg["route"], plain["route"]);
        assert_eq!(cfg["dns"], plain["dns"]);
    }

    #[test]
    fn both_modes_together_with_tun_and_global() {
        let cfg = generate(&GenOptions { tun: true, final_action: "proxy".into(), ..with_wg(true, true) });
        assert_eq!(cfg["route"]["final"], "proxy");
        assert_eq!(cfg["outbounds"][1]["detour"], "wg");
        assert_eq!(cfg["inbounds"][0]["type"], "tun");
        assert_eq!(rules(&cfg)[1]["action"], "hijack-dns");
        assert_eq!(cfg["dns"]["final"], "doh-proxy");
        // Without a profile: everything direct goes through the tunnel.
        let cfg = generate(&GenOptions {
            proxy_outbound: None,
            extra_outbounds: Vec::new(),
            tun: true,
            ..with_wg(true, true)
        });
        assert_eq!(cfg["route"]["final"], "wg");
        assert_eq!(cfg["outbounds"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn built_in_tunnel_overrides_the_external_interface_options() {
        let opts = GenOptions {
            direct_interface: Some("all-rodoro-home".into()),
            proxy_via_direct_interface: true,
            tun: true,
            tun_bypass_processes: vec!["wireguard.exe".into()],
            tun_bypass_cidrs: vec!["46.138.253.10/32".into()],
            ..with_wg(true, false)
        };
        let s = to_string(&generate(&opts));
        assert!(!s.contains("bind_interface") && !s.contains("process_name") && !s.contains("direct-physical"));
        assert!(!s.contains("route_exclude_address"));
    }

    #[test]
    fn provider_list_goes_straight_out_by_domain_and_ip() {
        let opts = GenOptions {
            provider_list: vec![
                "Warframe.com".into(),
                "https://github.com/user/repo".into(),
                "*.wikipedia.org".into(),
                "1.2.3.4".into(),
                "10.0.0.0/8".into(),
                "not a domain".into(),
                "warframe.com".into(),
            ],
            ..with_wg(true, true)
        };
        let cfg = generate(&opts);
        let r = rules(&cfg);
        let d = r.iter().position(|x| x["domain_suffix"] == json!(["warframe.com", "github.com", "wikipedia.org"])).unwrap();
        assert_eq!(r[d]["outbound"], "direct");
        assert_eq!(r[d + 1], json!({ "ip_cidr": ["1.2.3.4/32", "10.0.0.0/8"], "outbound": "direct" }));
        // Before every routing-layer rule (services / lists), after sniff.
        let first_service = r.iter().position(|x| x["domain_suffix"] == json!(["chatgpt.com"])).unwrap();
        assert!(d < first_service && r[0]["action"] == "sniff");
        // Their DNS goes to the ISP's resolver too.
        assert_eq!(cfg["dns"]["rules"][0], json!({ "domain_suffix": ["warframe.com", "github.com", "wikipedia.org"], "server": "dns-direct" }));
    }

    #[test]
    fn provider_list_with_the_external_interface_uses_the_unbound_direct() {
        let opts = GenOptions {
            direct_interface: Some("wg0".into()),
            provider_list: vec!["github.com".into()],
            ..pinned()
        };
        let cfg = generate(&opts);
        assert!(cfg["outbounds"].as_array().unwrap().iter().any(|o| o == &json!({ "type": "direct", "tag": "direct-physical" })));
        assert!(rules(&cfg).iter().any(|x| x == &json!({ "domain_suffix": ["github.com"], "outbound": "direct-physical" })));
        // Without any tunnel or interface: plain direct.
        let cfg = generate(&GenOptions { provider_list: vec!["github.com".into()], ..pinned() });
        assert!(rules(&cfg).iter().any(|x| x == &json!({ "domain_suffix": ["github.com"], "outbound": "direct" })));
        assert!(cfg["outbounds"].as_array().unwrap().iter().all(|o| o["tag"] != "direct-physical"));
    }

    #[test]
    fn provider_services_expand_to_domains_and_ranges() {
        let svc = |id: &str, domains: &[&str], cidrs: &[&str]| crate::routing::Service {
            id: id.into(),
            name: id.into(),
            icon: String::new(),
            domains: domains.iter().map(|s| s.to_string()).collect(),
            ip_cidrs: cidrs.iter().map(|s| s.to_string()).collect(),
            geosite: None,
        };
        let catalog = vec![
            svc("discord", &["discord.com", "Discord.gg", "*.discordapp.net"], &["162.159.128.0/19", "bad"]),
            svc("google", &["google.com", "google", "discord.com"], &[]),
            svc("telegram", &["t.me"], &["91.108.4.0/22"]),
        ];
        let ids = vec!["discord".to_string(), "google".to_string(), "gone".to_string()];
        let (d, c) = provider_from_services(&catalog, &ids);
        // Single-label TLDs from the catalog are kept; duplicates and bad ranges dropped.
        assert_eq!(d, ["discord.com", "discord.gg", "discordapp.net", "google.com", "google"]);
        assert_eq!(c, ["162.159.128.0/19"]);
        // Merged with the typed list, in one rule each, before the routing rules.
        let cfg = generate(&GenOptions {
            provider_list: vec!["warframe.com".into(), "discord.com".into()],
            provider_service_domains: d,
            provider_service_cidrs: c,
            ..with_wg(true, false)
        });
        let r = rules(&cfg);
        assert!(r.contains(&json!({ "domain_suffix": ["warframe.com", "discord.com", "discord.gg", "discordapp.net", "google.com", "google"], "outbound": "direct" })));
        assert!(r.contains(&json!({ "ip_cidr": ["162.159.128.0/19"], "outbound": "direct" })));
        // Nothing picked: no change.
        assert_eq!(provider_from_services(&catalog, &[]), (Vec::<String>::new(), Vec::<String>::new()));
    }

    #[test]
    fn provider_entries_are_normalized() {
        let parse = |e: &str| match provider_entry(e) {
            Some(ProviderEntry::Domain(d)) => format!("d:{d}"),
            Some(ProviderEntry::Cidr(c)) => format!("c:{c}"),
            None => "-".into(),
        };
        assert_eq!(parse(" GitHub.com "), "d:github.com");
        assert_eq!(parse("http://ru.wikipedia.org/wiki/X"), "d:ru.wikipedia.org");
        assert_eq!(parse(".steampowered.com"), "d:steampowered.com");
        assert_eq!(parse("пример.рф"), "d:пример.рф");
        assert_eq!(parse("2001:db8::/32"), "c:2001:db8::/32");
        assert_eq!(parse("localhost"), "-");
        assert_eq!(parse("a..b"), "-");
        assert_eq!(parse(""), "-");
    }

    #[test]
    fn ipv4_only_resolves_locally_after_sniff() {
        for tun in [false, true] {
            let cfg = generate(&GenOptions { ipv4_only: true, tun, ..only_youtube() });
            let r = rules(&cfg);
            let resolve = r.iter().position(|x| x == &json!({ "action": "resolve", "strategy": "ipv4_only" })).unwrap();
            let sniff = r.iter().position(|x| x["action"] == "sniff").unwrap();
            let first_route = r.iter().position(|x| x.get("outbound").is_some()).unwrap();
            assert!(sniff < resolve && resolve < first_route, "{r:?}");
            if tun {
                assert_eq!(r[1]["action"], "hijack-dns");
            }
            assert_eq!(cfg["dns"]["strategy"], "ipv4_only");
            // Only the resolve rule and the DNS strategy change.
            let mut plain = generate(&GenOptions { tun, ..only_youtube() });
            plain["route"]["rules"].as_array_mut().unwrap().insert(resolve, r[resolve].clone());
            plain["dns"]["strategy"] = json!("ipv4_only");
            assert_eq!(cfg, plain);
        }
        // Without a VPN profile: DNS is still IPv4-only, but there's no server to hand
        // resolved addresses to — no resolve rule.
        let cfg = generate(&GenOptions { ipv4_only: true, ..GenOptions::default() });
        let mut plain = generate(&GenOptions::default());
        plain["dns"]["strategy"] = json!("ipv4_only");
        assert_eq!(cfg, plain);
    }

    #[test]
    fn proxy_via_interface_needs_direct_interface() {
        let base = generate(&pinned());
        let cfg = generate(&GenOptions { proxy_via_direct_interface: true, ..pinned() });
        assert_eq!(cfg, base);
        // Without a profile there's nothing to bind either.
        let cfg = generate(&GenOptions {
            direct_interface: Some("wg0".into()),
            proxy_via_direct_interface: true,
            ..GenOptions::default()
        });
        assert_eq!(cfg["outbounds"], json!([{ "type": "direct", "tag": "direct", "bind_interface": "wg0" }]));
    }
}

pub fn to_string(cfg: &Value) -> String {
    serde_json::to_string_pretty(cfg).unwrap_or_else(|_| "{}".to_string())
}
