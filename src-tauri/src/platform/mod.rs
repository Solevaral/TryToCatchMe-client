//! Platform-specific integration behind a common surface.
//! Keep OS specifics isolated so other platforms can be added later.

#[cfg(windows)]
pub mod win;
#[cfg(target_os = "linux")]
pub mod linux;

/// Whether the current process has the privileges TUN mode needs.
#[cfg(windows)]
pub fn is_elevated() -> bool {
    win::is_elevated()
}

/// Relaunch the app with elevated privileges (triggers a UAC prompt), then the
/// caller should exit the current, non-elevated instance.
#[cfg(windows)]
pub fn relaunch_elevated() -> Result<(), String> {
    win::relaunch_elevated()
}

#[cfg(not(windows))]
pub fn is_elevated() -> bool {
    // Not gated here: on Linux the core itself gets CAP_NET_ADMIN on connect
    // (see linux::tun_core), the app never needs to be relaunched as root.
    true
}

#[cfg(not(windows))]
pub fn relaunch_elevated() -> Result<(), String> {
    Ok(())
}

/// Names of the active network interfaces, as sing-box's `bind_interface` expects them
/// (Windows: adapter names like `Ethernet`, `Wi-Fi`, a WireGuard tunnel's name).
/// Loopback and our own TUN adapter are left out. Sorted, no duplicates.
pub fn network_interfaces() -> Vec<String> {
    let mut names: Vec<String> = interface_names()
        .into_iter()
        .map(|n| n.trim().to_string())
        .filter(|n| !n.is_empty() && n != "lo" && n != ttcm_core::config::TUN_IFACE_LINUX)
        .collect();
    names.sort_by_key(|n| n.to_lowercase());
    names.dedup();
    names
}

#[cfg(windows)]
fn interface_names() -> Vec<String> {
    use std::os::windows::process::CommandExt;
    // UTF-8 output: adapter names may be localized (e.g. «Беспроводная сеть»).
    const QUERY: &str = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-NetAdapter -ErrorAction SilentlyContinue | Where-Object Status -eq 'Up' | ForEach-Object Name";
    let mut ps = std::process::Command::new("powershell");
    ps.args(["-NoProfile", "-NonInteractive", "-Command", QUERY]);
    ps.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    let Ok(out) = ps.output() else { return Vec::new() };
    String::from_utf8_lossy(&out.stdout).lines().map(str::to_string).collect()
}

#[cfg(not(windows))]
fn interface_names() -> Vec<String> {
    let Ok(dir) = std::fs::read_dir("/sys/class/net") else { return Vec::new() };
    dir.filter_map(|e| e.ok()).map(|e| e.file_name().to_string_lossy().into_owned()).collect()
}

/// Windows: the network has real IPv6 (a global address on a physical adapter). If the
/// query fails: assume yes, as before.
#[cfg(windows)]
pub fn uplink_has_ipv6() -> bool {
    use std::os::windows::process::CommandExt;
    const QUERY: &str = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-NetIPAddress -AddressFamily IPv6 -ErrorAction SilentlyContinue | ForEach-Object { $a = Get-NetAdapter -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue; $_.InterfaceAlias + '|' + $_.IPAddress + '|' + $a.InterfaceDescription }";
    let mut ps = std::process::Command::new("powershell");
    ps.args(["-NoProfile", "-NonInteractive", "-Command", QUERY]);
    ps.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    match ps.output() {
        Ok(out) if out.status.success() && !out.stdout.is_empty() => {
            ttcm_core::config::has_global_ipv6_windows(&String::from_utf8_lossy(&out.stdout))
        }
        _ => true,
    }
}

/// Every adapter's IP addresses as (adapter, ip) — to spot another copy of a WireGuard
/// tunnel (the WireGuard app holding the same address).
pub fn interface_addresses() -> Vec<(String, String)> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const QUERY: &str = "[Console]::OutputEncoding = [Text.Encoding]::UTF8; Get-NetIPAddress -ErrorAction SilentlyContinue | ForEach-Object { $_.InterfaceAlias + '|' + $_.IPAddress }";
        let mut ps = std::process::Command::new("powershell");
        ps.args(["-NoProfile", "-NonInteractive", "-Command", QUERY]);
        ps.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        let Ok(out) = ps.output() else { return Vec::new() };
        ttcm_core::wireguard::parse_name_ip_lines(&String::from_utf8_lossy(&out.stdout))
    }
    #[cfg(not(windows))]
    {
        let Ok(out) = std::process::Command::new("ip").args(["-o", "addr", "show"]).output() else { return Vec::new() };
        ttcm_core::wireguard::parse_ip_o_addr(&String::from_utf8_lossy(&out.stdout))
    }
}

/// Other VPN/proxy clients that are running right now (display names). They compete for
/// the system proxy and routes, so traffic may silently go through them instead of us.
pub fn running_vpn_clients() -> Vec<String> {
    const KNOWN: [(&str, &str); 17] = [
        ("hiddify", "Hiddify"),
        ("v2rayn", "v2rayN"),
        ("nekobox", "NekoBox"),
        ("nekoray", "NekoRay"),
        ("clash-verge", "Clash Verge"),
        ("verge-mihomo", "Clash Verge"),
        ("flclash", "FlClash"),
        ("mihomo", "Mihomo/Clash"),
        ("clash", "Clash"),
        ("karing", "Karing"),
        ("happ", "Happ"),
        ("v2raytun", "v2RayTun"),
        ("throne", "Throne"),
        ("amneziavpn", "AmneziaVPN"),
        ("outline", "Outline"),
        ("xray", "Xray"),
        ("sing-box", "sing-box (сторонний)"),
    ];
    let mut found: Vec<String> = Vec::new();
    for name in process_names() {
        let n = name.to_lowercase();
        let n = n.strip_suffix(".exe").unwrap_or(&n);
        if let Some((_, label)) = KNOWN.iter().find(|(k, _)| n.starts_with(k)) {
            if !found.iter().any(|f| f == label) {
                found.push(label.to_string());
            }
        }
    }
    found
}

#[cfg(windows)]
fn process_names() -> Vec<String> {
    use std::os::windows::process::CommandExt;
    let mut cmd = std::process::Command::new("tasklist");
    cmd.args(["/FO", "CSV", "/NH"]).creation_flags(0x0800_0000);
    let Ok(out) = cmd.output() else { return Vec::new() };
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .filter_map(|l| l.split(',').next().map(|s| s.trim_matches('"').to_string()))
        .collect()
}

#[cfg(not(windows))]
fn process_names() -> Vec<String> {
    let Ok(out) = std::process::Command::new("ps").args(["-eo", "comm="]).output() else { return Vec::new() };
    String::from_utf8_lossy(&out.stdout).lines().map(|l| l.trim().to_string()).collect()
}
