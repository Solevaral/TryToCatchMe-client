//! Platform-specific integration behind a common surface.
//! Keep OS specifics isolated so other platforms can be added later.

#[cfg(windows)]
pub mod win;

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
    // On non-Windows we don't gate TUN here yet.
    true
}

#[cfg(not(windows))]
pub fn relaunch_elevated() -> Result<(), String> {
    Ok(())
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
