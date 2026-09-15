//! Picking the real router among default routes (pure, testable).
//!
//! VPN/virtual adapters (Radmin VPN, Hamachi, ZeroTier, Tailscale, Wintun/TUN, Hyper-V,
//! WSL, Docker, …) also install 0.0.0.0/0 routes. The "PC → router" hop must use the
//! physical adapter that actually carries internet traffic: skip virtual adapters and
//! take the lowest metric.

#[derive(Clone, Debug, PartialEq)]
pub struct RouteCandidate {
    pub gateway: String,
    pub metric: u32,
    /// Adapter / interface name ("Ethernet", "eth0").
    pub adapter: String,
    /// Adapter description, if known ("Realtek PCIe GbE Family Controller").
    pub description: String,
}

const VIRTUAL_WORDS: [&str; 16] = [
    "vpn", "radmin", "hamachi", "zerotier", "tailscale", "wireguard", "wintun", "openvpn",
    "tap-windows", "hiddify", "sing-box", "virtualbox", "vmware", "hyper-v", "vethernet", "loopback",
];
const VIRTUAL_IFACE_PREFIXES: [&str; 10] =
    ["tun", "tap", "wg", "tailscale", "zt", "docker", "br-", "veth", "virbr", "vmnet"];

/// Is this a VPN / virtual adapter rather than a physical network card?
pub fn is_virtual(adapter: &str, description: &str) -> bool {
    let text = format!("{adapter} {description}").to_lowercase();
    if VIRTUAL_WORDS.iter().any(|w| text.contains(w)) {
        return true;
    }
    let name = adapter.to_lowercase();
    VIRTUAL_IFACE_PREFIXES.iter().any(|p| name.starts_with(p))
}

/// The best gateway: physical adapters first, lowest metric; otherwise lowest metric.
pub fn pick_gateway(routes: &[RouteCandidate]) -> Option<&RouteCandidate> {
    let usable: Vec<&RouteCandidate> = routes
        .iter()
        .filter(|r| !r.gateway.is_empty() && r.gateway != "0.0.0.0" && r.gateway.parse::<std::net::Ipv4Addr>().is_ok())
        .collect();
    usable
        .iter()
        .filter(|r| !is_virtual(&r.adapter, &r.description))
        .min_by_key(|r| r.metric)
        .or_else(|| usable.iter().min_by_key(|r| r.metric))
        .copied()
}

/// Parse `gateway|metric|adapter|description` lines (produced by a PowerShell query).
pub fn parse_windows_routes(text: &str) -> Vec<RouteCandidate> {
    text.lines()
        .filter_map(|l| {
            let mut parts = l.trim().splitn(4, '|');
            let gateway = parts.next()?.trim().to_string();
            let metric = parts.next()?.trim().parse().ok()?;
            Some(RouteCandidate {
                gateway,
                metric,
                adapter: parts.next().unwrap_or("").trim().to_string(),
                description: parts.next().unwrap_or("").trim().to_string(),
            })
        })
        .collect()
}

/// Parse `route print 0.0.0.0` rows ("0.0.0.0 0.0.0.0 <gw> <iface-ip> <metric>").
/// No adapter names here, so this is only a fallback.
pub fn parse_route_print(text: &str) -> Vec<RouteCandidate> {
    text.lines()
        .filter_map(|l| {
            let c: Vec<&str> = l.split_whitespace().collect();
            (c.len() >= 5 && c[0] == "0.0.0.0" && c[1] == "0.0.0.0").then(|| RouteCandidate {
                gateway: c[2].to_string(),
                metric: c[4].parse().unwrap_or(u32::MAX),
                adapter: String::new(),
                description: c[3].to_string(),
            })
        })
        .collect()
}

/// Parse `ip route show default` ("default via 192.168.1.1 dev eth0 proto dhcp metric 100").
pub fn parse_linux_routes(text: &str) -> Vec<RouteCandidate> {
    text.lines()
        .filter_map(|l| {
            let t: Vec<&str> = l.split_whitespace().collect();
            if t.first() != Some(&"default") {
                return None;
            }
            let after = |key: &str| t.iter().position(|x| *x == key).and_then(|i| t.get(i + 1)).map(|s| s.to_string());
            Some(RouteCandidate {
                gateway: after("via")?,
                metric: after("metric").and_then(|m| m.parse().ok()).unwrap_or(0),
                adapter: after("dev").unwrap_or_default(),
                description: String::new(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_radmin_vpn_on_windows() {
        // Real output from a machine where diagnostics used to pick Radmin's 26.0.0.1.
        let routes = parse_windows_routes(
            "26.0.0.1|9257|Radmin VPN|Famatech Radmin VPN Ethernet Adapter\n\
             192.168.20.1|25|Ethernet|Realtek PCIe GbE Family Controller\n",
        );
        let gw = pick_gateway(&routes).unwrap();
        assert_eq!(gw.gateway, "192.168.20.1");
        assert_eq!(gw.adapter, "Ethernet");
    }

    #[test]
    fn prefers_physical_even_with_worse_metric() {
        let routes = vec![
            RouteCandidate { gateway: "10.8.0.1".into(), metric: 1, adapter: "Hamachi".into(), description: "".into() },
            RouteCandidate { gateway: "192.168.1.1".into(), metric: 50, adapter: "Wi-Fi".into(), description: "Intel Wireless".into() },
        ];
        assert_eq!(pick_gateway(&routes).unwrap().gateway, "192.168.1.1");
    }

    #[test]
    fn on_link_tun_routes_are_ignored() {
        let routes = parse_windows_routes("0.0.0.0|0|singbox_tun|Wintun Userspace Tunnel\n192.168.0.1|35|Ethernet|Intel\n");
        assert_eq!(pick_gateway(&routes).unwrap().gateway, "192.168.0.1");
    }

    #[test]
    fn falls_back_to_route_print_metric() {
        let text = "  0.0.0.0          0.0.0.0         26.0.0.1       26.1.2.3   9257\n  0.0.0.0          0.0.0.0     192.168.20.1   192.168.20.5     25\n";
        assert_eq!(pick_gateway(&parse_route_print(text)).unwrap().gateway, "192.168.20.1");
    }

    #[test]
    fn linux_skips_tun_and_uses_metric() {
        let text = "default dev tun0 scope link\n\
                    default via 10.0.0.1 dev wg0 metric 50\n\
                    default via 192.168.1.1 dev enp3s0 proto dhcp metric 100\n";
        let routes = parse_linux_routes(text);
        let gw = pick_gateway(&routes).unwrap();
        assert_eq!(gw.gateway, "192.168.1.1");
        assert_eq!(gw.adapter, "enp3s0");
    }
}
