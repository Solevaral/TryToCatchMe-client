//! Built-in WireGuard: `.conf` parsing / export, validation, the sing-box endpoint, the
//! tunnel store and the migration from the 1.3.8–1.3.91 "direct traffic through an
//! interface" options.
//!
//! The tunnel runs inside sing-box (a userspace `wireguard` endpoint), no wireguard.exe.

use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::config::bypass_cidr;

/// sing-box tag of the active tunnel's endpoint.
pub const WG_TAG: &str = "wg";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct WgInterface {
    pub private_key: String,
    /// As written in the file (`10.6.0.3/32`, or a bare IP).
    #[serde(default)]
    pub addresses: Vec<String>,
    /// DNS servers and search domains, as in wg-quick.
    #[serde(default)]
    pub dns: Vec<String>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Keys we don't use (Table, PostUp, FwMark, …), kept for a lossless export.
    #[serde(default)]
    pub extra: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct WgPeer {
    pub public_key: String,
    #[serde(default)]
    pub preshared_key: Option<String>,
    /// `host:port` / `[v6]:port`.
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub allowed_ips: Vec<String>,
    #[serde(default)]
    pub persistent_keepalive: Option<u16>,
    #[serde(default)]
    pub extra: Vec<(String, String)>,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct WgTunnel {
    pub id: String,
    pub name: String,
    pub interface: WgInterface,
    pub peers: Vec<WgPeer>,
}

/// `wireguard.json`: the tunnels and the active one (`None` = built-in WireGuard off).
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Default)]
pub struct WgStore {
    #[serde(default)]
    pub tunnels: Vec<WgTunnel>,
    #[serde(default)]
    pub active: Option<String>,
}

impl WgStore {
    pub fn active_tunnel(&self) -> Option<&WgTunnel> {
        let id = self.active.as_deref()?;
        self.tunnels.iter().find(|t| t.id == id)
    }
}

// ---- parsing ----

enum Section {
    None,
    Interface,
    Peer,
}

fn split_list(v: &str) -> impl Iterator<Item = String> + '_ {
    v.split(',').map(str::trim).filter(|s| !s.is_empty()).map(str::to_string)
}

fn parse_u16(key: &str, v: &str) -> Result<u16, String> {
    v.parse::<u16>().map_err(|_| format!("{key}: «{v}» — не число от 0 до 65535"))
}

fn set_once<T>(slot: &mut Option<T>, key: &str, value: T) -> Result<(), String> {
    if slot.is_some() {
        return Err(format!("{key} указан дважды"));
    }
    *slot = Some(value);
    Ok(())
}

/// Parse a wg-quick `.conf`: one `[Interface]`, one or more `[Peer]`. Accepts a UTF-8
/// BOM, CRLF, `#` comments (also after a value), any key case and repeated list keys.
/// The result is validated (see [`validate`]).
pub fn parse_conf(text: &str) -> Result<(WgInterface, Vec<WgPeer>), String> {
    let text = text.strip_prefix('\u{feff}').unwrap_or(text);
    let mut section = Section::None;
    let mut iface: Option<WgInterface> = None;
    let mut private_key: Option<String> = None;
    let mut mtu: Option<u16> = None;
    let mut listen_port: Option<u16> = None;
    let mut peers: Vec<WgPeer> = Vec::new();
    // Per-peer single-value keys (a repeat is an error), moved into the peer at the
    // next section / the end.
    #[derive(Default)]
    struct PeerSingle {
        public_key: Option<String>,
        preshared_key: Option<String>,
        endpoint: Option<String>,
        keepalive: Option<Option<u16>>,
    }
    let mut peer_single = PeerSingle::default();

    let flush_peer = |peers: &mut Vec<WgPeer>, single: &mut PeerSingle| {
        if let Some(p) = peers.last_mut() {
            let s = std::mem::take(single);
            p.public_key = s.public_key.unwrap_or_default();
            p.preshared_key = s.preshared_key;
            p.endpoint = s.endpoint;
            p.persistent_keepalive = s.keepalive.flatten();
        }
    };

    for (n, raw) in text.lines().enumerate() {
        let line = raw.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let at = |msg: String| format!("строка {}: {msg}", n + 1);
        if line.starts_with('[') {
            let name = line.trim_start_matches('[').trim_end_matches(']').trim().to_ascii_lowercase();
            if !line.ends_with(']') {
                return Err(at(format!("незакрытая секция «{line}»")));
            }
            match name.as_str() {
                "interface" => {
                    if iface.is_some() {
                        return Err(at("секция [Interface] указана дважды".into()));
                    }
                    flush_peer(&mut peers, &mut peer_single);
                    iface = Some(WgInterface::default());
                    section = Section::Interface;
                }
                "peer" => {
                    flush_peer(&mut peers, &mut peer_single);
                    peers.push(WgPeer::default());
                    section = Section::Peer;
                }
                _ => return Err(at(format!("неизвестная секция [{name}]"))),
            }
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            return Err(at(format!("ожидалось «ключ = значение»: «{line}»")));
        };
        let (key_raw, value) = (key.trim(), value.trim());
        // `PrivateKey abc…=`: the `=` is the base64 padding, not the separator.
        if key_raw.is_empty() || key_raw.contains(char::is_whitespace) {
            return Err(at(format!("ожидалось «ключ = значение»: «{line}»")));
        }
        let key = key_raw.to_ascii_lowercase();
        match section {
            Section::None => return Err(at("параметр до секции [Interface] / [Peer]".into())),
            Section::Interface => {
                let i = iface.as_mut().expect("interface section");
                match key.as_str() {
                    "privatekey" => set_once(&mut private_key, "PrivateKey", value.to_string()).map_err(at)?,
                    "address" => i.addresses.extend(split_list(value)),
                    "dns" => i.dns.extend(split_list(value)),
                    "mtu" => set_once(&mut mtu, "MTU", parse_u16("MTU", value).map_err(at)?).map_err(at)?,
                    "listenport" => {
                        set_once(&mut listen_port, "ListenPort", parse_u16("ListenPort", value).map_err(at)?).map_err(at)?
                    }
                    _ => i.extra.push((key_raw.to_string(), value.to_string())),
                }
            }
            Section::Peer => {
                let p = peers.last_mut().expect("peer section");
                match key.as_str() {
                    "publickey" => set_once(&mut peer_single.public_key, "PublicKey", value.to_string()).map_err(at)?,
                    "presharedkey" => set_once(&mut peer_single.preshared_key, "PresharedKey", value.to_string()).map_err(at)?,
                    "endpoint" => set_once(&mut peer_single.endpoint, "Endpoint", value.to_string()).map_err(at)?,
                    "allowedips" => p.allowed_ips.extend(split_list(value)),
                    "persistentkeepalive" => {
                        let ka = if value.eq_ignore_ascii_case("off") {
                            None
                        } else {
                            Some(parse_u16("PersistentKeepalive", value).map_err(at)?)
                        };
                        set_once(&mut peer_single.keepalive, "PersistentKeepalive", ka).map_err(at)?
                    }
                    _ => p.extra.push((key_raw.to_string(), value.to_string())),
                }
            }
        }
    }
    flush_peer(&mut peers, &mut peer_single);

    let mut iface = iface.ok_or("нет секции [Interface]")?;
    iface.private_key = private_key.unwrap_or_default();
    iface.mtu = mtu;
    iface.listen_port = listen_port;
    validate(&iface, &peers)?;
    Ok((iface, peers))
}

// ---- validation ----

/// A WireGuard key: base64 of exactly 32 bytes.
pub fn is_valid_key(key: &str) -> bool {
    base64::engine::general_purpose::STANDARD
        .decode(key.trim())
        .is_ok_and(|b| b.len() == 32)
}

/// `host:port` or `[v6]:port` → (host, port).
pub fn parse_endpoint(endpoint: &str) -> Result<(String, u16), String> {
    let e = endpoint.trim();
    let bad = || format!("Endpoint «{e}»: нужен вид адрес:порт");
    let (host, port) = if let Some(rest) = e.strip_prefix('[') {
        let (h, p) = rest.split_once("]:").ok_or_else(bad)?;
        h.parse::<std::net::Ipv6Addr>().map_err(|_| bad())?;
        (h, p)
    } else {
        let (h, p) = e.rsplit_once(':').ok_or_else(bad)?;
        if h.contains(':') {
            // A bare IPv6 address needs brackets.
            return Err(format!("Endpoint «{e}»: IPv6-адрес пишется в скобках: [адрес]:порт"));
        }
        (h, p)
    };
    let valid_host = !host.is_empty()
        && host.chars().all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'));
    if !valid_host {
        return Err(bad());
    }
    match port.parse::<u16>() {
        Ok(p) if p > 0 => Ok((host.to_string(), p)),
        _ => Err(format!("Endpoint «{e}»: неверный порт")),
    }
}

/// Everything sing-box needs to dial the tunnel, checked up front so a bad file never
/// reaches the core.
pub fn validate(iface: &WgInterface, peers: &[WgPeer]) -> Result<(), String> {
    if iface.private_key.trim().is_empty() {
        return Err("не указан PrivateKey".into());
    }
    if !is_valid_key(&iface.private_key) {
        return Err("PrivateKey: неверный ключ (нужен base64 из 32 байт)".into());
    }
    if iface.addresses.is_empty() {
        return Err("не указан Address".into());
    }
    for a in &iface.addresses {
        bypass_cidr(a).ok_or_else(|| format!("Address «{a}»: не IP-адрес/подсеть"))?;
    }
    if let Some(mtu) = iface.mtu {
        if !(576..=9000).contains(&mtu) {
            return Err(format!("MTU {mtu}: допустимо от 576 до 9000"));
        }
    }
    if peers.is_empty() {
        return Err("нет ни одной секции [Peer]".into());
    }
    for (i, p) in peers.iter().enumerate() {
        let who = format!("Peer {}", i + 1);
        if p.public_key.trim().is_empty() {
            return Err(format!("{who}: не указан PublicKey"));
        }
        if !is_valid_key(&p.public_key) {
            return Err(format!("{who}: PublicKey — неверный ключ"));
        }
        if let Some(psk) = &p.preshared_key {
            if !is_valid_key(psk) {
                return Err(format!("{who}: PresharedKey — неверный ключ"));
            }
        }
        if let Some(e) = &p.endpoint {
            parse_endpoint(e).map_err(|err| format!("{who}: {err}"))?;
        }
        for a in &p.allowed_ips {
            bypass_cidr(a).ok_or_else(|| format!("{who}: AllowedIPs «{a}» — не IP-адрес/подсеть"))?;
        }
    }
    if peers.iter().all(|p| p.endpoint.is_none()) {
        return Err("ни у одного [Peer] нет Endpoint — некуда подключаться".into());
    }
    Ok(())
}

/// A tunnel name: non-empty, at most 64 chars, unique (case-insensitive) among the
/// other tunnels.
pub fn validate_name(name: &str, tunnels: &[WgTunnel], own_id: Option<&str>) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("пустое имя туннеля".into());
    }
    if name.chars().count() > 64 {
        return Err("имя туннеля длиннее 64 символов".into());
    }
    let taken = tunnels
        .iter()
        .any(|t| Some(t.id.as_str()) != own_id && t.name.to_lowercase() == name.to_lowercase());
    if taken {
        return Err(format!("туннель «{name}» уже есть"));
    }
    Ok(name.to_string())
}

/// Default tunnel name from an imported file name (`home.conf` → `home`).
pub fn name_from_file(file: &str) -> String {
    let base = file.rsplit(['/', '\\']).next().unwrap_or(file);
    let base = base.strip_suffix(".conf").unwrap_or(base);
    base.trim().to_string()
}

// ---- export ----

/// Back to wg-quick `.conf`. Comments aren't kept; every value is.
pub fn to_conf(iface: &WgInterface, peers: &[WgPeer]) -> String {
    let mut out = String::from("[Interface]\n");
    out += &format!("PrivateKey = {}\n", iface.private_key);
    if !iface.addresses.is_empty() {
        out += &format!("Address = {}\n", iface.addresses.join(", "));
    }
    if !iface.dns.is_empty() {
        out += &format!("DNS = {}\n", iface.dns.join(", "));
    }
    if let Some(m) = iface.mtu {
        out += &format!("MTU = {m}\n");
    }
    if let Some(p) = iface.listen_port {
        out += &format!("ListenPort = {p}\n");
    }
    for (k, v) in &iface.extra {
        out += &format!("{k} = {v}\n");
    }
    for p in peers {
        out += "\n[Peer]\n";
        out += &format!("PublicKey = {}\n", p.public_key);
        if let Some(psk) = &p.preshared_key {
            out += &format!("PresharedKey = {psk}\n");
        }
        if !p.allowed_ips.is_empty() {
            out += &format!("AllowedIPs = {}\n", p.allowed_ips.join(", "));
        }
        if let Some(e) = &p.endpoint {
            out += &format!("Endpoint = {e}\n");
        }
        if let Some(ka) = p.persistent_keepalive {
            out += &format!("PersistentKeepalive = {ka}\n");
        }
        for (k, v) in &p.extra {
            out += &format!("{k} = {v}\n");
        }
    }
    out
}

// ---- sing-box ----

/// The networks the tunnel is for, from AllowedIPs (e.g. a home LAN `192.168.10.0/24`),
/// routed into it like WireGuard itself does. Catch-all ranges (`/0`, the `/1` halves)
/// are left out: whether internet traffic goes in is the user's mode choice.
pub fn routed_subnets(t: &WgTunnel) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for p in &t.peers {
        for c in p.allowed_ips.iter().filter_map(|a| bypass_cidr(a)) {
            let prefix: u8 = c.rsplit('/').next().and_then(|p| p.parse().ok()).unwrap_or(0);
            if prefix > 1 && !out.contains(&c) {
                out.push(c);
            }
        }
    }
    out
}

/// The tunnel's DNS servers that are IP addresses (wg-quick search domains are skipped).
pub fn dns_servers(iface: &WgInterface) -> Vec<String> {
    iface
        .dns
        .iter()
        .filter(|d| d.parse::<std::net::IpAddr>().is_ok())
        .cloned()
        .collect()
}

/// sing-box 1.14 `wireguard` endpoint for the tunnel (userspace, `system: false`).
/// It has no detour: its own UDP is dialed by the core like any of its sockets, i.e.
/// on the physical uplink (auto_detect_interface) — never into the tunnel itself or
/// the TUN adapter.
///
/// `full`: the client sends internet traffic into the tunnel (direct traffic or the VPN
/// through it), so the server's peer must accept any destination — whatever AllowedIPs
/// the file has (a home-network-only `.conf` would otherwise drop it all). What goes
/// in is decided by the route rules, not by AllowedIPs.
pub fn endpoint(t: &WgTunnel, tag: &str, full: bool) -> Value {
    let cidrs = |v: &[String]| -> Vec<String> { v.iter().filter_map(|a| bypass_cidr(a)).collect() };
    let main_peer = t.peers.iter().position(|p| p.endpoint.is_some());
    let peers: Vec<Value> = t
        .peers
        .iter()
        .enumerate()
        .map(|(n, p)| {
            let allowed = if p.allowed_ips.is_empty() || (full && Some(n) == main_peer) {
                vec!["0.0.0.0/0".to_string(), "::/0".to_string()]
            } else {
                cidrs(&p.allowed_ips)
            };
            let mut peer = json!({
                "public_key": p.public_key.trim(),
                "allowed_ips": allowed,
            });
            if let Some((host, port)) = p.endpoint.as_deref().and_then(|e| parse_endpoint(e).ok()) {
                peer["address"] = json!(host);
                peer["port"] = json!(port);
            }
            if let Some(psk) = &p.preshared_key {
                peer["pre_shared_key"] = json!(psk.trim());
            }
            if let Some(ka) = p.persistent_keepalive.filter(|ka| *ka > 0) {
                peer["persistent_keepalive_interval"] = json!(ka);
            }
            peer
        })
        .collect();
    let mut ep = json!({
        "type": "wireguard",
        "tag": tag,
        "system": false,
        "address": cidrs(&t.interface.addresses),
        "private_key": t.interface.private_key.trim(),
        "peers": peers,
    });
    if let Some(mtu) = t.interface.mtu {
        ep["mtu"] = json!(mtu);
    }
    if let Some(port) = t.interface.listen_port {
        ep["listen_port"] = json!(port);
    }
    ep
}

// ---- migration from 1.3.8–1.3.91 ----

/// The interface options of 1.3.8–1.3.91 (an external VPN's adapter).
#[derive(Clone, Debug, PartialEq, Default)]
pub struct LegacyOptions {
    pub direct_interface: Option<String>,
    pub proxy_via_direct_interface: bool,
    pub tun_bypass_addresses: Vec<String>,
}

/// What the built-in tunnel settings become when the user accepts the migration.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct Migration {
    /// The old interface (for the message).
    pub interface: String,
    pub direct_via_tunnel: bool,
    pub vpn_over_tunnel: bool,
    /// The old "bypass TUN" addresses go to the "through the ISP" list.
    pub provider_list: Vec<String>,
}

/// An offer to move from the external interface to the built-in tunnel: only when the
/// old option is in use and there's a tunnel to move to. Programs from the old bypass
/// list aren't carried over (the built-in tunnel has no external client to exclude).
pub fn migration_offer(legacy: &LegacyOptions, has_tunnels: bool) -> Option<Migration> {
    let interface = legacy.direct_interface.clone()?;
    if !has_tunnels {
        return None;
    }
    Some(Migration {
        interface,
        direct_via_tunnel: true,
        vpn_over_tunnel: legacy.proxy_via_direct_interface,
        provider_list: legacy.tun_bypass_addresses.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const K1: &str = "yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk=";
    const K2: &str = "xTIBA5rboUvnH4htodjb6e697QjLERt1NAB4mZqp8Dg=";
    const K3: &str = "HIgo9xNzJMWLKASShiTqIybxZ0U3wGLiUeJ1PKf8ykw=";

    fn sample() -> String {
        format!(
            "[Interface]\nPrivateKey = {K1}\nAddress = 10.6.0.3/32, fd00::3/128\nDNS = 10.6.0.1, home.lan\nMTU = 1420\n\n\
             [Peer]\nPublicKey = {K2}\nPresharedKey = {K3}\nAllowedIPs = 0.0.0.0/1, 128.0.0.0/1\nEndpoint = 46.138.253.10:51820\nPersistentKeepalive = 25\n"
        )
    }

    fn tunnel(text: &str) -> WgTunnel {
        let (interface, peers) = parse_conf(text).unwrap();
        WgTunnel { id: "t1".into(), name: "home".into(), interface, peers }
    }

    #[test]
    fn parses_all_fields() {
        let (i, p) = parse_conf(&sample()).unwrap();
        assert_eq!(i.private_key, K1);
        assert_eq!(i.addresses, ["10.6.0.3/32", "fd00::3/128"]);
        assert_eq!(i.dns, ["10.6.0.1", "home.lan"]);
        assert_eq!(i.mtu, Some(1420));
        assert_eq!(i.listen_port, None);
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].public_key, K2);
        assert_eq!(p[0].preshared_key.as_deref(), Some(K3));
        assert_eq!(p[0].allowed_ips, ["0.0.0.0/1", "128.0.0.0/1"]);
        assert_eq!(p[0].endpoint.as_deref(), Some("46.138.253.10:51820"));
        assert_eq!(p[0].persistent_keepalive, Some(25));
    }

    #[test]
    fn bom_crlf_comments_case_and_repeated_keys() {
        let text = format!(
            "\u{feff}# exported by WireGuard\r\n[interface]\r\nprivatekey={K1}  # mine\r\nADDRESS = 10.0.0.2/24\r\naddress = fd00::2/64\r\nListenPort = 51000\r\n\r\n\
             [PEER]\r\npublickey = {K2}\r\nAllowedIPs = 0.0.0.0/0\r\nallowedips = ::/0\r\nendpoint = vpn.example.com:443\r\nPersistentKeepalive = off\r\n"
        );
        let (i, p) = parse_conf(&text).unwrap();
        assert_eq!(i.private_key, K1);
        assert_eq!(i.addresses, ["10.0.0.2/24", "fd00::2/64"]);
        assert_eq!(i.listen_port, Some(51000));
        assert_eq!(p[0].allowed_ips, ["0.0.0.0/0", "::/0"]);
        assert_eq!(p[0].endpoint.as_deref(), Some("vpn.example.com:443"));
        assert_eq!(p[0].persistent_keepalive, None);
    }

    #[test]
    fn several_peers_and_ipv6_endpoint() {
        let text = format!(
            "[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2\n\
             [Peer]\nPublicKey = {K2}\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 10.0.0.0/24\n\
             [Peer]\nPublicKey = {K3}\nAllowedIPs = 10.1.0.0/24\n"
        );
        let (_, p) = parse_conf(&text).unwrap();
        assert_eq!(p.len(), 2);
        assert_eq!(p[0].endpoint.as_deref(), Some("[2001:db8::1]:51820"));
        assert_eq!(p[1].public_key, K3);
        assert_eq!(p[1].endpoint, None);
        assert_eq!(p[1].allowed_ips, ["10.1.0.0/24"]);
        assert_eq!(parse_endpoint("[2001:db8::1]:51820").unwrap(), ("2001:db8::1".to_string(), 51820));
    }

    #[test]
    fn unknown_keys_are_kept_for_export() {
        let text = format!(
            "[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\nTable = off\nPostUp = echo up\n[Peer]\nPublicKey = {K2}\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n"
        );
        let (i, _) = parse_conf(&text).unwrap();
        assert_eq!(i.extra, [("Table".to_string(), "off".to_string()), ("PostUp".to_string(), "echo up".to_string())]);
    }

    #[test]
    fn broken_files_are_clear_errors() {
        let ok_peer = format!("[Peer]\nPublicKey = {K2}\nEndpoint = 1.2.3.4:51820\nAllowedIPs = 0.0.0.0/0\n");
        let cases: Vec<(String, &str)> = vec![
            (String::new(), "нет секции [Interface]"),
            ("just text".into(), "ожидалось «ключ = значение»"),
            (format!("PrivateKey = {K1}\n"), "параметр до секции"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\n"), "нет ни одной секции [Peer]"),
            (format!("[Interface]\nAddress = 10.0.0.2/32\n{ok_peer}"), "не указан PrivateKey"),
            (format!("[Interface]\nPrivateKey = abc\nAddress = 10.0.0.2/32\n{ok_peer}"), "PrivateKey: неверный ключ"),
            (format!("[Interface]\nPrivateKey = {K1}\n{ok_peer}"), "не указан Address"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.300/32\n{ok_peer}"), "Address «10.0.0.300/32»"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\nMTU = big\n{ok_peer}"), "MTU: «big»"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\nMTU = 100\n{ok_peer}"), "MTU 100"),
            (format!("[Interface]\nPrivateKey = {K1}\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\n{ok_peer}"), "PrivateKey указан дважды"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\n[Interface]\n{ok_peer}"), "[Interface] указана дважды"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\n[Wat]\n"), "неизвестная секция"),
            (format!("[Interface\nPrivateKey = {K1}\n"), "незакрытая секция"),
            (format!("[Interface]\nPrivateKey {K1}\n"), "ожидалось «ключ = значение»"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\n[Peer]\nEndpoint = 1.2.3.4:5\n"), "Peer 1: не указан PublicKey"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {K2}\nEndpoint = 1.2.3.4\n"), "нужен вид адрес:порт"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {K2}\nEndpoint = 1.2.3.4:0\n"), "неверный порт"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {K2}\nEndpoint = 2001:db8::1:51820\n"), "в скобках"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {K2}\nAllowedIPs = 0.0.0.0/0\n"), "нет Endpoint"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {K2}\nPresharedKey = nope\nEndpoint = 1.2.3.4:5\n"), "PresharedKey — неверный ключ"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {K2}\nEndpoint = 1.2.3.4:5\nAllowedIPs = everything\n"), "AllowedIPs «everything»"),
            (format!("[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2/32\n[Peer]\nPublicKey = {K2}\nEndpoint = 1.2.3.4:5\nPersistentKeepalive = -1\n"), "PersistentKeepalive"),
        ];
        for (text, expected) in cases {
            let err = parse_conf(&text).unwrap_err();
            assert!(err.contains(expected), "{text:?}: got «{err}», expected «{expected}»");
        }
    }

    #[test]
    fn line_numbers_in_errors() {
        let err = parse_conf("[Interface]\n\n# c\nMTU = x\n").unwrap_err();
        assert!(err.starts_with("строка 4:"), "{err}");
    }

    #[test]
    fn export_round_trips_without_loss() {
        let samples = vec![
            sample(),
            format!(
                "[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2\nListenPort = 51000\nTable = off\n\
                 [Peer]\nPublicKey = {K2}\nEndpoint = [2001:db8::1]:51820\nAllowedIPs = 10.0.0.0/24, ::/0\nJc = 4\n\
                 [Peer]\nPublicKey = {K3}\nAllowedIPs = 10.1.0.0/24\nPersistentKeepalive = 15\n"
            ),
        ];
        for text in samples {
            let parsed = parse_conf(&text).unwrap();
            let exported = to_conf(&parsed.0, &parsed.1);
            assert_eq!(parse_conf(&exported).unwrap(), parsed, "{exported}");
            // Stable: exporting again gives the same text.
            let again = parse_conf(&exported).unwrap();
            assert_eq!(to_conf(&again.0, &again.1), exported);
        }
    }

    #[test]
    fn edited_fields_survive_export() {
        let mut t = tunnel(&sample());
        t.interface.mtu = Some(1280);
        t.interface.dns = vec!["1.1.1.1".into()];
        t.peers[0].endpoint = Some("home.example.com:51821".into());
        let text = to_conf(&t.interface, &t.peers);
        let (i, p) = parse_conf(&text).unwrap();
        assert_eq!(i.mtu, Some(1280));
        assert_eq!(i.dns, ["1.1.1.1"]);
        assert_eq!(p[0].endpoint.as_deref(), Some("home.example.com:51821"));
    }

    #[test]
    fn endpoint_json_for_sing_box() {
        let ep = endpoint(&tunnel(&sample()), WG_TAG, false);
        assert_eq!(
            ep,
            json!({
                "type": "wireguard",
                "tag": "wg",
                "system": false,
                "address": ["10.6.0.3/32", "fd00::3/128"],
                "private_key": K1,
                "mtu": 1420,
                "peers": [{
                    "address": "46.138.253.10",
                    "port": 51820,
                    "public_key": K2,
                    "pre_shared_key": K3,
                    "allowed_ips": ["0.0.0.0/1", "128.0.0.0/1"],
                    "persistent_keepalive_interval": 25
                }]
            })
        );
        // Never routed through anything: no detour, no interface binding.
        assert!(ep.get("detour").is_none() && ep.get("bind_interface").is_none());
    }

    #[test]
    fn endpoint_json_normalizes_and_defaults() {
        let text = format!(
            "[Interface]\nPrivateKey = {K1}\nAddress = 10.0.0.2\nListenPort = 51000\n\
             [Peer]\nPublicKey = {K2}\nEndpoint = [2001:db8::1]:51820\n\
             [Peer]\nPublicKey = {K3}\nAllowedIPs = 10.1.0.0/24\nPersistentKeepalive = 0\n"
        );
        let ep = endpoint(&tunnel(&text), "x", false);
        assert_eq!(ep["address"], json!(["10.0.0.2/32"]));
        assert_eq!(ep["listen_port"], 51000);
        assert!(ep.get("mtu").is_none());
        assert_eq!(ep["peers"][0]["address"], "2001:db8::1");
        assert_eq!(ep["peers"][0]["allowed_ips"], json!(["0.0.0.0/0", "::/0"]));
        assert!(ep["peers"][1].get("address").is_none());
        assert!(ep["peers"][1].get("persistent_keepalive_interval").is_none());
    }

    #[test]
    fn dns_servers_skip_search_domains() {
        let t = tunnel(&sample());
        assert_eq!(dns_servers(&t.interface), ["10.6.0.1"]);
    }

    #[test]
    fn names_are_validated() {
        let mut a = tunnel(&sample());
        a.name = "Home".into();
        let tunnels = vec![a];
        assert_eq!(validate_name("  Работа ", &tunnels, None).unwrap(), "Работа");
        assert!(validate_name("", &tunnels, None).is_err());
        assert!(validate_name("   ", &tunnels, None).is_err());
        assert!(validate_name(&"x".repeat(65), &tunnels, None).is_err());
        assert!(validate_name("home", &tunnels, None).unwrap_err().contains("уже есть"));
        // Renaming a tunnel to its own name (any case) is fine.
        assert_eq!(validate_name("HOME", &tunnels, Some("t1")).unwrap(), "HOME");
        assert_eq!(name_from_file("C:\\Users\\me\\all-rodoro-home.conf"), "all-rodoro-home");
        assert_eq!(name_from_file("work"), "work");
    }

    #[test]
    fn keys_are_checked() {
        assert!(is_valid_key(K1));
        assert!(!is_valid_key(""));
        assert!(!is_valid_key("AAAA"));
        assert!(!is_valid_key(&K1.replace('=', "")[..42])); // truncated
        assert!(!is_valid_key("yAnz5TF+lXXJte14tji3zlMNq+hd2rYUIgJBgB3fBmk!"));
    }

    #[test]
    fn store_serializes_and_picks_active() {
        let mut store = WgStore { tunnels: vec![tunnel(&sample())], active: Some("t1".into()) };
        let mut second = tunnel(&sample());
        second.id = "t2".into();
        second.name = "work".into();
        second.interface.mtu = None;
        store.tunnels.push(second);
        let json = serde_json::to_string_pretty(&store).unwrap();
        let back: WgStore = serde_json::from_str(&json).unwrap();
        assert_eq!(back, store);
        assert_eq!(back.active_tunnel().unwrap().name, "home");
        let off = WgStore { active: None, ..back.clone() };
        assert!(off.active_tunnel().is_none());
        let dangling = WgStore { active: Some("gone".into()), ..back };
        assert!(dangling.active_tunnel().is_none());
        // An empty / old file reads as "no tunnels".
        assert_eq!(serde_json::from_str::<WgStore>("{}").unwrap(), WgStore::default());
    }

    #[test]
    fn migration_is_offered_only_when_useful() {
        let legacy = LegacyOptions {
            direct_interface: Some("all-rodoro-home".into()),
            proxy_via_direct_interface: true,
            tun_bypass_addresses: vec!["46.138.253.10".into()],
        };
        assert_eq!(
            migration_offer(&legacy, true),
            Some(Migration {
                interface: "all-rodoro-home".into(),
                direct_via_tunnel: true,
                vpn_over_tunnel: true,
                provider_list: vec!["46.138.253.10".into()],
            })
        );
        // No tunnel imported yet: nothing to move to.
        assert_eq!(migration_offer(&legacy, false), None);
        // The old option isn't used.
        assert_eq!(migration_offer(&LegacyOptions::default(), true), None);
        let plain = LegacyOptions { direct_interface: Some("wg0".into()), ..LegacyOptions::default() };
        let m = migration_offer(&plain, true).unwrap();
        assert!(m.direct_via_tunnel && !m.vpn_over_tunnel && m.provider_list.is_empty());
    }
}
