//! Persisted application settings (security toggles, auto-failover).

use std::fs;
use std::path::PathBuf;

use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use tauri::{AppHandle, Manager};

fn default_true() -> bool {
    true
}

fn default_proxy_port() -> u16 {
    ttcm_core::config::MIXED_PORT
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Settings {
    /// DNS-over-HTTPS through the tunnel (anti-leak).
    #[serde(default = "default_true")]
    pub dns_doh: bool,
    /// Block QUIC / UDP:443.
    #[serde(default)]
    pub block_quic: bool,
    /// Auto-switch to the next profile when the active one fails. Works only with
    /// `experimental` on.
    #[serde(default)]
    pub auto_switch: bool,
    /// Experimental features (auto-switch between profiles).
    #[serde(default)]
    pub experimental: bool,
    /// TUN capture mode (all system traffic via a virtual adapter; needs admin).
    #[serde(default)]
    pub capture_tun: bool,
    /// Local proxy port the system proxy points at (geo downloads use port + 1).
    #[serde(default = "default_proxy_port")]
    pub proxy_port: u16,
    /// Log every connection (core log level `info`). Thousands of lines per second in
    /// TUN mode: costs CPU in the core and memory in the log console, so it's off by
    /// default and only the core's warnings and errors are streamed.
    #[serde(default)]
    pub verbose_logs: bool,
    /// Network interface for direct traffic (sing-box `bind_interface` on the `direct`
    /// outbound), e.g. another VPN's full-tunnel adapter. `None` => automatic, as before.
    #[serde(default)]
    pub direct_interface: Option<String>,
    /// Reach the VPN server through `direct_interface` too (when the local ISP blocks
    /// the server). Ignored while `direct_interface` is automatic.
    #[serde(default)]
    pub proxy_via_direct_interface: bool,
    /// TUN + `direct_interface`: programs whose traffic bypasses the client and leaves
    /// through the physical uplink (the other VPN's own client — else a loop).
    #[serde(default = "default_bypass_processes")]
    pub tun_bypass_processes: Vec<String>,
    /// Same for addresses: IPs, CIDRs or domains (resolved on connect).
    #[serde(default)]
    pub tun_bypass_addresses: Vec<String>,
    /// Built-in WireGuard (when a tunnel is active): direct traffic through the tunnel
    /// (else through the ISP).
    #[serde(default = "default_true")]
    pub wg_direct_via_tunnel: bool,
    /// Built-in WireGuard: reach the VPN server through the tunnel.
    #[serde(default)]
    pub wg_vpn_over_tunnel: bool,
    /// "Through the ISP": domains / IPs that skip both the tunnel and the VPN.
    #[serde(default)]
    pub provider_list: Vec<String>,
    /// The migration to the built-in tunnel was accepted (the old interface options are
    /// kept for rollbacks, just not offered again).
    #[serde(default)]
    pub wg_migrated: bool,
}

fn default_bypass_processes() -> Vec<String> {
    let names: &[&str] = if cfg!(windows) {
        &["wireguard.exe", "amneziawg.exe", "openvpn.exe"]
    } else {
        // Kernel WireGuard has no process: only userspace clients can match here.
        &["openvpn", "amneziawg-go", "wireguard-go"]
    };
    names.iter().map(|s| s.to_string()).collect()
}

impl Default for Settings {
    fn default() -> Self {
        Settings {
            dns_doh: true,
            block_quic: false,
            auto_switch: false,
            experimental: false,
            capture_tun: false,
            proxy_port: default_proxy_port(),
            verbose_logs: false,
            direct_interface: None,
            proxy_via_direct_interface: false,
            tun_bypass_processes: default_bypass_processes(),
            tun_bypass_addresses: Vec::new(),
            wg_direct_via_tunnel: true,
            wg_vpn_over_tunnel: false,
            provider_list: Vec::new(),
            wg_migrated: false,
        }
    }
}

#[derive(Default)]
pub struct SettingsStore {
    inner: Mutex<Settings>,
}

impl Settings {
    /// Auto-switch is an experimental feature: off unless both toggles are on.
    pub fn auto_switch_on(&self) -> bool {
        self.experimental && self.auto_switch
    }
}

impl SettingsStore {
    fn file(app: &AppHandle) -> Result<PathBuf, String> {
        let dir = app
            .path()
            .app_config_dir()
            .map_err(|e| format!("no app config dir: {e}"))?;
        Ok(dir.join("settings.json"))
    }

    pub fn load(&self, app: &AppHandle) {
        if let Ok(path) = Self::file(app) {
            if let Ok(bytes) = fs::read(&path) {
                if let Ok(s) = serde_json::from_slice::<Settings>(&bytes) {
                    *self.inner.lock() = s;
                }
            }
        }
    }

    pub fn get(&self) -> Settings {
        self.inner.lock().clone()
    }

    pub fn set(&self, app: &AppHandle, s: Settings) {
        *self.inner.lock() = s;
        if let Ok(path) = Self::file(app) {
            if let Some(parent) = path.parent() {
                let _ = fs::create_dir_all(parent);
            }
            if let Ok(json) = serde_json::to_string_pretty(&*self.inner.lock()) {
                let _ = fs::write(&path, json);
            }
        }
    }
}
