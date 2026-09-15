//! OS-level system proxy access, with no Tauri dependency.
//!
//! - Windows: WinINet per-connection options (the same API the Settings app and
//!   browsers read), followed by a settings-changed broadcast.
//! - Linux: GNOME (gsettings) and KDE (kioslaverc via kreadconfig/kwriteconfig),
//!   whichever is present.
//!
//! `snapshot` captures the user's settings exactly so `restore` can put them back.

use serde::{Deserialize, Serialize};

#[cfg(target_os = "linux")]
use ttcm_core::sysproxy::{gvariant_plain, kde_proxy_value, kde_value_points_to, GNOME_BYPASS};
#[cfg(windows)]
use ttcm_core::sysproxy::{windows_server_points_to, WINDOWS_BYPASS};

pub const HOST: &str = "127.0.0.1";

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct Snapshot {
    #[serde(default)]
    pub windows: Option<WinSnap>,
    /// (schema, key, raw GVariant value)
    #[serde(default)]
    pub gnome: Option<Vec<(String, String, String)>>,
    /// (key, value) in kioslaverc [Proxy Settings]
    #[serde(default)]
    pub kde: Option<Vec<(String, String)>>,
}

#[derive(Serialize, Deserialize, Clone, Debug, Default, PartialEq)]
pub struct WinSnap {
    pub flags: u32,
    pub server: Option<String>,
    pub bypass: Option<String>,
    pub autoconfig_url: Option<String>,
}

// ---------------------------------------------------------------------------
// Windows
// ---------------------------------------------------------------------------
#[cfg(windows)]
mod imp {
    use super::*;
    use std::ffi::c_void;
    use std::ptr;
    use windows_sys::Win32::Foundation::GlobalFree;
    use windows_sys::Win32::Networking::WinInet::{
        InternetQueryOptionW, InternetSetOptionW, INTERNET_OPTION_PER_CONNECTION_OPTION,
        INTERNET_OPTION_REFRESH, INTERNET_OPTION_SETTINGS_CHANGED, INTERNET_PER_CONN_AUTOCONFIG_URL,
        INTERNET_PER_CONN_FLAGS, INTERNET_PER_CONN_OPTIONW, INTERNET_PER_CONN_OPTION_LISTW,
        INTERNET_PER_CONN_PROXY_BYPASS, INTERNET_PER_CONN_PROXY_SERVER, PROXY_TYPE_DIRECT,
        PROXY_TYPE_PROXY,
    };

    fn wide(s: &str) -> Vec<u16> {
        s.encode_utf16().chain(std::iter::once(0)).collect()
    }

    /// Read a PWSTR allocated by WinINet and free it.
    unsafe fn take_wstr(p: *mut u16) -> Option<String> {
        if p.is_null() {
            return None;
        }
        let mut len = 0;
        while *p.add(len) != 0 {
            len += 1;
        }
        let s = String::from_utf16_lossy(std::slice::from_raw_parts(p, len));
        GlobalFree(p as *mut c_void);
        if s.is_empty() {
            None
        } else {
            Some(s)
        }
    }

    pub fn snapshot() -> Result<Snapshot, String> {
        let mut opts: [INTERNET_PER_CONN_OPTIONW; 4] = unsafe { std::mem::zeroed() };
        opts[0].dwOption = INTERNET_PER_CONN_FLAGS;
        opts[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        opts[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
        opts[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
        let mut list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: ptr::null_mut(),
            dwOptionCount: opts.len() as u32,
            dwOptionError: 0,
            pOptions: opts.as_mut_ptr(),
        };
        let mut size = list.dwSize;
        let ok = unsafe {
            InternetQueryOptionW(
                ptr::null(),
                INTERNET_OPTION_PER_CONNECTION_OPTION,
                &mut list as *mut _ as *mut c_void,
                &mut size,
            )
        };
        if ok == 0 {
            return Err(format!(
                "не удалось прочитать системный прокси: {}",
                std::io::Error::last_os_error()
            ));
        }
        unsafe {
            Ok(Snapshot {
                windows: Some(WinSnap {
                    flags: opts[0].Value.dwValue,
                    server: take_wstr(opts[1].Value.pszValue),
                    bypass: take_wstr(opts[2].Value.pszValue),
                    autoconfig_url: take_wstr(opts[3].Value.pszValue),
                }),
                ..Default::default()
            })
        }
    }

    fn write(snap: &WinSnap) -> Result<(), String> {
        let server = snap.server.as_deref().map(wide);
        let bypass = snap.bypass.as_deref().map(wide);
        let pac = snap.autoconfig_url.as_deref().map(wide);
        let ptr_of = |v: &Option<Vec<u16>>| -> *mut u16 {
            v.as_ref().map(|w| w.as_ptr() as *mut u16).unwrap_or(ptr::null_mut())
        };
        let mut opts: [INTERNET_PER_CONN_OPTIONW; 4] = unsafe { std::mem::zeroed() };
        opts[0].dwOption = INTERNET_PER_CONN_FLAGS;
        opts[0].Value.dwValue = snap.flags;
        opts[1].dwOption = INTERNET_PER_CONN_PROXY_SERVER;
        opts[1].Value.pszValue = ptr_of(&server);
        opts[2].dwOption = INTERNET_PER_CONN_PROXY_BYPASS;
        opts[2].Value.pszValue = ptr_of(&bypass);
        opts[3].dwOption = INTERNET_PER_CONN_AUTOCONFIG_URL;
        opts[3].Value.pszValue = ptr_of(&pac);
        let list = INTERNET_PER_CONN_OPTION_LISTW {
            dwSize: std::mem::size_of::<INTERNET_PER_CONN_OPTION_LISTW>() as u32,
            pszConnection: ptr::null_mut(),
            dwOptionCount: opts.len() as u32,
            dwOptionError: 0,
            pOptions: opts.as_mut_ptr(),
        };
        let ok = unsafe {
            InternetSetOptionW(
                ptr::null(),
                INTERNET_OPTION_PER_CONNECTION_OPTION,
                &list as *const _ as *const c_void,
                list.dwSize,
            )
        };
        if ok == 0 {
            return Err(format!(
                "не удалось изменить системный прокси: {}",
                std::io::Error::last_os_error()
            ));
        }
        // Tell running apps to re-read the settings.
        unsafe {
            InternetSetOptionW(ptr::null(), INTERNET_OPTION_SETTINGS_CHANGED, ptr::null(), 0);
            InternetSetOptionW(ptr::null(), INTERNET_OPTION_REFRESH, ptr::null(), 0);
        }
        Ok(())
    }

    pub fn apply(host: &str, port: u16) -> Result<(), String> {
        write(&WinSnap {
            flags: PROXY_TYPE_DIRECT | PROXY_TYPE_PROXY,
            server: Some(format!("{host}:{port}")),
            bypass: Some(WINDOWS_BYPASS.to_string()),
            autoconfig_url: None,
        })
    }

    pub fn restore(s: &Snapshot) -> Result<(), String> {
        match &s.windows {
            Some(w) => write(w),
            None => Ok(()),
        }
    }

    pub fn disabled() -> Snapshot {
        Snapshot {
            windows: Some(WinSnap { flags: PROXY_TYPE_DIRECT, ..Default::default() }),
            ..Default::default()
        }
    }

    pub fn points_to(host: &str, port: u16) -> bool {
        match snapshot() {
            Ok(Snapshot { windows: Some(w), .. }) => {
                w.flags & PROXY_TYPE_PROXY != 0
                    && w.server.as_deref().map(|s| windows_server_points_to(s, host, port)).unwrap_or(false)
            }
            _ => false,
        }
    }

    pub fn describe() -> String {
        match snapshot() {
            Ok(Snapshot { windows: Some(w), .. }) => {
                let on = w.flags & PROXY_TYPE_PROXY != 0;
                match (&w.server, &w.autoconfig_url) {
                    (_, Some(pac)) if w.flags & 4 != 0 => format!("PAC {pac}"),
                    (Some(s), _) => format!("{s} · {}", if on { "вкл" } else { "выкл" }),
                    (None, _) => "не задан".to_string(),
                }
            }
            Ok(_) => "не задан".to_string(),
            Err(e) => e,
        }
    }
}

// ---------------------------------------------------------------------------
// Linux (GNOME + KDE)
// ---------------------------------------------------------------------------
#[cfg(target_os = "linux")]
mod imp {
    use super::*;
    use std::process::Command;

    const GNOME_KEYS: [(&str, &str); 8] = [
        ("org.gnome.system.proxy", "ignore-hosts"),
        ("org.gnome.system.proxy.http", "host"),
        ("org.gnome.system.proxy.http", "port"),
        ("org.gnome.system.proxy.https", "host"),
        ("org.gnome.system.proxy.https", "port"),
        ("org.gnome.system.proxy.socks", "host"),
        ("org.gnome.system.proxy.socks", "port"),
        // `mode` last so restore switches the proxy on/off after the values are back.
        ("org.gnome.system.proxy", "mode"),
    ];
    const KDE_KEYS: [&str; 5] = ["ProxyType", "httpProxy", "httpsProxy", "socksProxy", "NoProxyFor"];

    fn run(cmd: &str, args: &[&str]) -> Option<String> {
        let out = Command::new(cmd).args(args).output().ok()?;
        if out.status.success() {
            Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
        } else {
            None
        }
    }

    fn gnome_available() -> bool {
        run("gsettings", &["get", "org.gnome.system.proxy", "mode"]).is_some()
    }

    /// A command exists if it can be spawned at all.
    fn exists(cmd: &str) -> bool {
        Command::new(cmd).arg("--help").output().is_ok()
    }

    fn kde_tools() -> Option<(&'static str, &'static str)> {
        [("kreadconfig6", "kwriteconfig6"), ("kreadconfig5", "kwriteconfig5")]
            .into_iter()
            .find(|(r, w)| exists(r) && exists(w))
    }

    fn kde_read(r: &str, key: &str) -> String {
        run(r, &["--file", "kioslaverc", "--group", "Proxy Settings", "--key", key]).unwrap_or_default()
    }

    fn kde_write(w: &str, key: &str, value: &str) {
        let mut args = vec!["--file", "kioslaverc", "--group", "Proxy Settings", "--key", key];
        if value.is_empty() {
            args.push("--delete");
        } else {
            args.push(value);
        }
        let _ = Command::new(w).args(&args).status();
    }

    fn kde_notify() {
        let _ = Command::new("dbus-send")
            .args([
                "--type=signal",
                "/KIO/Scheduler",
                "org.kde.KIO.Scheduler.reparseSlaveConfiguration",
                "string:",
            ])
            .status();
    }

    pub fn snapshot() -> Result<Snapshot, String> {
        let mut snap = Snapshot::default();
        if gnome_available() {
            snap.gnome = Some(
                GNOME_KEYS
                    .iter()
                    .filter_map(|(s, k)| {
                        run("gsettings", &["get", s, k]).map(|v| (s.to_string(), k.to_string(), v))
                    })
                    .collect(),
            );
        }
        if let Some((r, _)) = kde_tools() {
            snap.kde = Some(KDE_KEYS.iter().map(|k| (k.to_string(), kde_read(r, k))).collect());
        }
        if snap.gnome.is_none() && snap.kde.is_none() {
            return Err("не найден gsettings (GNOME) или kwriteconfig (KDE) — системный прокси нужно задать вручную".into());
        }
        Ok(snap)
    }

    pub fn apply(host: &str, port: u16) -> Result<(), String> {
        let mut done = false;
        if gnome_available() {
            let h = format!("'{host}'");
            let p = port.to_string();
            for scheme in ["http", "https", "socks"] {
                let schema = format!("org.gnome.system.proxy.{scheme}");
                let _ = Command::new("gsettings").args(["set", &schema, "host", &h]).status();
                let _ = Command::new("gsettings").args(["set", &schema, "port", &p]).status();
            }
            let _ = Command::new("gsettings")
                .args(["set", "org.gnome.system.proxy", "ignore-hosts", GNOME_BYPASS])
                .status();
            let _ = Command::new("gsettings").args(["set", "org.gnome.system.proxy", "mode", "'manual'"]).status();
            done = true;
        }
        if let Some((_, w)) = kde_tools() {
            kde_write(w, "httpProxy", &kde_proxy_value("http", host, port));
            kde_write(w, "httpsProxy", &kde_proxy_value("http", host, port));
            kde_write(w, "socksProxy", &kde_proxy_value("socks", host, port));
            kde_write(w, "NoProxyFor", "localhost,127.0.0.1,::1");
            kde_write(w, "ProxyType", "1");
            kde_notify();
            done = true;
        }
        if done {
            Ok(())
        } else {
            Err("не найден gsettings (GNOME) или kwriteconfig (KDE) — задайте системный прокси вручную".into())
        }
    }

    pub fn restore(s: &Snapshot) -> Result<(), String> {
        if let Some(values) = &s.gnome {
            for (schema, key, value) in values {
                let _ = Command::new("gsettings").args(["set", schema, key, value]).status();
            }
        }
        if let (Some(values), Some((_, w))) = (&s.kde, kde_tools()) {
            // ProxyType last.
            for (k, v) in values.iter().filter(|(k, _)| k != "ProxyType") {
                kde_write(w, k, v);
            }
            if let Some((_, v)) = values.iter().find(|(k, _)| k == "ProxyType") {
                kde_write(w, "ProxyType", v);
            }
            kde_notify();
        }
        Ok(())
    }

    pub fn disabled() -> Snapshot {
        Snapshot {
            gnome: Some(vec![(
                "org.gnome.system.proxy".into(),
                "mode".into(),
                "'none'".into(),
            )]),
            kde: Some(vec![("ProxyType".into(), "0".into())]),
            ..Default::default()
        }
    }

    pub fn points_to(host: &str, port: u16) -> bool {
        let gnome = gnome_available()
            && run("gsettings", &["get", "org.gnome.system.proxy", "mode"]).map(|m| gvariant_plain(&m)) == Some("manual".into())
            && run("gsettings", &["get", "org.gnome.system.proxy.http", "host"]).map(|v| gvariant_plain(&v)) == Some(host.into())
            && run("gsettings", &["get", "org.gnome.system.proxy.http", "port"]).map(|v| gvariant_plain(&v)) == Some(port.to_string());
        let kde = kde_tools()
            .map(|(r, _)| kde_read(r, "ProxyType") == "1" && kde_value_points_to(&kde_read(r, "httpProxy"), host, port))
            .unwrap_or(false);
        gnome || kde
    }

    pub fn describe() -> String {
        if gnome_available() {
            let mode = run("gsettings", &["get", "org.gnome.system.proxy", "mode"]).map(|m| gvariant_plain(&m)).unwrap_or_default();
            let host = run("gsettings", &["get", "org.gnome.system.proxy.http", "host"]).map(|v| gvariant_plain(&v)).unwrap_or_default();
            let port = run("gsettings", &["get", "org.gnome.system.proxy.http", "port"]).map(|v| gvariant_plain(&v)).unwrap_or_default();
            return match mode.as_str() {
                "manual" => format!("{host}:{port} · вкл"),
                "auto" => "автоматически (PAC)".into(),
                _ => "выкл".into(),
            };
        }
        if let Some((r, _)) = kde_tools() {
            let t = kde_read(r, "ProxyType");
            return if t == "1" { format!("{} · вкл", kde_read(r, "httpProxy")) } else { "выкл".into() };
        }
        "не поддерживается (задайте вручную)".into()
    }
}

#[cfg(not(any(windows, target_os = "linux")))]
mod imp {
    use super::*;
    pub fn snapshot() -> Result<Snapshot, String> { Err("системный прокси не поддерживается на этой ОС".into()) }
    pub fn apply(_: &str, _: u16) -> Result<(), String> { Err("системный прокси не поддерживается на этой ОС".into()) }
    pub fn restore(_: &Snapshot) -> Result<(), String> { Ok(()) }
    pub fn disabled() -> Snapshot { Snapshot::default() }
    pub fn points_to(_: &str, _: u16) -> bool { false }
    pub fn describe() -> String { "не поддерживается".into() }
}

pub use imp::{apply, describe, disabled, points_to, restore, snapshot};
