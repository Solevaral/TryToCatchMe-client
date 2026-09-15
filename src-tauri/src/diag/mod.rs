//! Network chain diagnostics.
//!
//! Checks each link of: PC -> gateway -> ISP -> VPN server -> (tunnel) -> target,
//! and localizes the break. Key distinction at the server hop:
//!   - ICMP ok but TCP to the proxy port fails (while the internet is reachable)
//!     => likely DPI / ТСПУ blocking this server/port.
//!   - ICMP + TCP both fail (internet ok) => server down / route dead.

use std::io::{Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::process::Command;
use std::time::{Duration, Instant};

use serde::Serialize;

use crate::config::CLASH_CONTROLLER;
use ttcm_core::gateway::{pick_gateway, RouteCandidate};
#[cfg(not(windows))]
use ttcm_core::gateway::parse_linux_routes;
#[cfg(windows)]
use ttcm_core::gateway::{parse_route_print, parse_windows_routes};

#[derive(Serialize, Clone)]
pub struct DiagStep {
    pub id: String,
    pub label: String,
    /// "ok" | "warn" | "fail" | "skip"
    pub status: String,
    pub detail: String,
    pub ms: Option<u64>,
}

#[derive(Serialize, Clone)]
pub struct DiagReport {
    pub steps: Vec<DiagStep>,
    pub verdict: String,
}

pub struct DiagInput {
    pub server: Option<(String, u16)>,
    pub core_running: bool,
    pub targets: Vec<String>, // hosts (optionally host:port)
}

fn step(id: &str, label: &str, status: &str, detail: impl Into<String>, ms: Option<u64>) -> DiagStep {
    DiagStep {
        id: id.into(),
        label: label.into(),
        status: status.into(),
        detail: detail.into(),
        ms,
    }
}

/// Run the full diagnostic chain (blocking; call via spawn_blocking).
pub fn run(input: DiagInput) -> DiagReport {
    let mut steps = Vec::new();
    let mut verdict = String::from("Всё в порядке");
    let mut decided = false;

    // 1. Local network / default gateway.
    let gw = default_gateway();
    match &gw {
        Some((ip, adapter)) => match icmp_ping(ip) {
            true => steps.push(step("local", "ПК → роутер / шлюз", "ok", format!("шлюз {ip}{adapter} отвечает"), None)),
            false => {
                steps.push(step("local", "ПК → роутер / шлюз", "fail", format!("шлюз {ip}{adapter} не отвечает"), None));
                verdict = "Обрыв на звене: локальная сеть / роутер".into();
                decided = true;
            }
        },
        None => steps.push(step("local", "ПК → роутер / шлюз", "warn", "не удалось определить шлюз", None)),
    }

    // 2. ISP / internet (direct, bypassing any proxy).
    let inet = tcp_connect("1.1.1.1:443", 3000).or_else(|| tcp_connect("8.8.8.8:443", 3000));
    match inet {
        Some(ms) => steps.push(step("isp", "Провайдер / интернет", "ok", "публичные узлы доступны", Some(ms))),
        None => {
            steps.push(step("isp", "Провайдер / интернет", "fail", "нет доступа к 1.1.1.1 / 8.8.8.8", None));
            if !decided {
                verdict = "Обрыв на звене: провайдер / канал".into();
                decided = true;
            }
        }
    }
    let internet_ok = inet.is_some();

    // 3. VPN server reachability (before the tunnel).
    match &input.server {
        None => steps.push(step("server", "VPN-сервер (до туннеля)", "skip", "профиль не выбран", None)),
        Some((host, port)) => {
            let icmp = icmp_ping(host);
            let tcp = tcp_connect(&format!("{host}:{port}"), 4000);
            match tcp {
                Some(ms) => steps.push(step("server", "VPN-сервер (до туннеля)", "ok", format!("{host}:{port} доступен"), Some(ms))),
                None => {
                    // Distinguish DPI/ТСПУ from a dead server.
                    let (detail, verdict_txt) = if icmp && internet_ok {
                        (
                            format!("ICMP до {host} проходит, но порт {port} закрыт/рвётся — вероятно ТСПУ/DPI блокирует сервер. Попробуйте сменить SNI/Reality-параметры, порт или протокол."),
                            "Похоже, ТСПУ/DPI блокирует ваш VPN-сервер",
                        )
                    } else {
                        (
                            format!("{host}:{port} недоступен (ICMP {}), — сервер лёг или маршрут закрыт", if icmp { "проходит" } else { "не проходит" }),
                            "VPN-сервер недоступен",
                        )
                    };
                    steps.push(step("server", "VPN-сервер (до туннеля)", "fail", detail, None));
                    if !decided {
                        verdict = verdict_txt.into();
                        decided = true;
                    }
                }
            }
        }
    }

    // 4. Tunnel health (after connect) via Clash API delay test.
    if input.core_running {
        match clash_delay("http://www.gstatic.com/generate_204", 5000) {
            Some(ms) => steps.push(step("tunnel", "Туннель (после connect)", "ok", "трафик реально идёт через прокси", Some(ms))),
            None => {
                steps.push(step("tunnel", "Туннель (после connect)", "fail", "прокси поднят, но запрос через него не проходит — проблема на стороне сервера или его аплинка", None));
                if !decided {
                    verdict = "Туннель поднят, но трафик не идёт (сервер / аплинк)".into();
                }
            }
        }
    } else {
        steps.push(step("tunnel", "Туннель (после connect)", "skip", "VPN выключен", None));
    }

    // 5. Target sites — direct vs through the VPN.
    // This is what catches the "everything green but the site won't load" case:
    // when connected, the target is probed THROUGH the proxy and a failure there
    // drives the verdict (a direct TCP probe alone would bypass the VPN and lie).
    for (i, raw) in input.targets.iter().enumerate() {
        let host = raw.split(':').next().unwrap_or(raw).trim().to_string();
        if host.is_empty() {
            continue;
        }
        let hostport = if raw.contains(':') {
            raw.clone()
        } else {
            format!("{host}:443")
        };
        let direct = tcp_connect(&hostport, 4000);
        let id = format!("target{i}");
        let label = format!("Цель: {host}");

        if input.core_running {
            let via = clash_delay(&format!("https://{host}/"), 5000)
                .or_else(|| clash_delay(&format!("http://{host}/"), 5000));
            match via {
                Some(ms) => steps.push(step(
                    &id,
                    &label,
                    "ok",
                    format!("доступен через VPN{}", direct.map(|d| format!(" · напрямую {d} ms")).unwrap_or_default()),
                    Some(ms),
                )),
                None => {
                    let detail = if direct.is_some() {
                        format!("{host} доступен напрямую, но НЕ открывается через VPN — трафик через сервер не проходит (grpc/аплинк сервера)")
                    } else {
                        format!("{host} недоступен ни через VPN, ни напрямую")
                    };
                    steps.push(step(&id, &label, "fail", detail, None));
                    if !decided {
                        verdict = format!("Цель «{host}» не открывается через VPN");
                        decided = true;
                    }
                }
            }
        } else {
            match direct {
                Some(ms) => steps.push(step(&id, &label, "ok", format!("{host} доступен напрямую"), Some(ms))),
                None => steps.push(step(&id, &label, "warn", format!("{host} недоступен напрямую (возможно, блокируется провайдером)"), None)),
            }
        }
    }

    let _ = decided;
    DiagReport { steps, verdict }
}

/// Connect to `host:port`, returning the elapsed milliseconds on success.
pub fn tcp_connect(addr: &str, timeout_ms: u64) -> Option<u64> {
    let start = Instant::now();
    let socket = addr.to_socket_addrs().ok()?.next()?;
    TcpStream::connect_timeout(&socket, Duration::from_millis(timeout_ms)).ok()?;
    Some(start.elapsed().as_millis() as u64)
}

/// One ICMP echo via the system `ping` tool (no raw-socket privileges needed).
fn icmp_ping(host: &str) -> bool {
    #[cfg(windows)]
    {
        run_quiet(Command::new("ping").args(["-n", "1", "-w", "1500", host]))
    }
    #[cfg(not(windows))]
    {
        run_quiet(Command::new("ping").args(["-c", "1", "-W", "2", host]))
    }
}

fn run_quiet(cmd: &mut Command) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        cmd.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
    }
    cmd.stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Ask the Clash API to time a request through the active proxy outbound.
pub fn clash_delay(test_url: &str, timeout_ms: u64) -> Option<u64> {
    clash_delay_via("proxy", test_url, timeout_ms)
}

/// Same, through a specific outbound tag (e.g. a profile a service is pinned to).
pub fn clash_delay_via(tag: &str, test_url: &str, timeout_ms: u64) -> Option<u64> {
    let enc = test_url.replace(':', "%3A").replace('/', "%2F");
    let path = format!("/proxies/{tag}/delay?timeout={timeout_ms}&url={enc}");
    let body = http_get_localhost(CLASH_CONTROLLER, &path, timeout_ms + 1000)?;
    // Response: {"delay": 123} on success; {"message": "..."} on failure.
    let v: serde_json::Value = serde_json::from_str(&body).ok()?;
    v.get("delay").and_then(|d| d.as_u64())
}

/// Minimal HTTP/1.0 GET against a localhost endpoint; returns the response body.
fn http_get_localhost(authority: &str, path: &str, timeout_ms: u64) -> Option<String> {
    let socket = authority.to_socket_addrs().ok()?.next()?;
    let mut stream =
        TcpStream::connect_timeout(&socket, Duration::from_millis(timeout_ms)).ok()?;
    stream.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    stream.set_write_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;
    let req = format!(
        "GET {path} HTTP/1.0\r\nHost: {authority}\r\nConnection: close\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).ok()?;
    let mut buf = String::new();
    stream.read_to_string(&mut buf).ok()?;
    // Split headers/body on the blank line.
    buf.split_once("\r\n\r\n").map(|(_, body)| body.to_string())
}

/// Format the adapter for messages: " (Ethernet)" or "".
fn adapter_suffix(r: &RouteCandidate) -> String {
    if r.adapter.is_empty() {
        String::new()
    } else {
        format!(" ({})", r.adapter)
    }
}

/// Windows: the real router among default routes — physical adapter, lowest metric —
/// so VPN/virtual adapters (Radmin VPN, Hamachi, Wintun, …) aren't mistaken for it.
#[cfg(windows)]
fn default_gateway() -> Option<(String, String)> {
    use std::os::windows::process::CommandExt;
    const QUERY: &str = "Get-NetRoute -DestinationPrefix 0.0.0.0/0 -AddressFamily IPv4 -ErrorAction SilentlyContinue | ForEach-Object { $a = Get-NetAdapter -InterfaceIndex $_.ifIndex -ErrorAction SilentlyContinue; '{0}|{1}|{2}|{3}' -f $_.NextHop, ($_.RouteMetric + $_.InterfaceMetric), $a.Name, $a.InterfaceDescription }";
    let mut ps = Command::new("powershell");
    ps.args(["-NoProfile", "-NonInteractive", "-Command", QUERY]);
    ps.creation_flags(0x0800_0000);
    let mut routes = ps
        .output()
        .map(|o| parse_windows_routes(&String::from_utf8_lossy(&o.stdout)))
        .unwrap_or_default();
    if routes.is_empty() {
        // Fallback without adapter names: `route print` (locale-independent rows).
        let mut rp = Command::new("route");
        rp.args(["print", "0.0.0.0"]);
        rp.creation_flags(0x0800_0000);
        routes = rp
            .output()
            .map(|o| parse_route_print(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default();
    }
    pick_gateway(&routes).map(|r| (r.gateway.clone(), adapter_suffix(r)))
}

/// Linux: `ip route show default`, skipping tun/wg/docker/… interfaces.
#[cfg(not(windows))]
fn default_gateway() -> Option<(String, String)> {
    let out = Command::new("ip").args(["route", "show", "default"]).output().ok()?;
    let routes = parse_linux_routes(&String::from_utf8_lossy(&out.stdout));
    pick_gateway(&routes).map(|r| (r.gateway.clone(), adapter_suffix(r)))
}

// ---------------------------------------------------------------------------
// Service availability through the active profile (async)
// ---------------------------------------------------------------------------

/// Countries where Gemini isn't offered: if Google geolocates the VPN exit here, Gemini
/// shows "not available in your country".
const GEMINI_BLOCKED: [&str; 9] = ["RU", "BY", "CN", "HK", "MO", "IR", "KP", "CU", "SY"];

async fn get_via(client: &reqwest::Client, url: &str) -> Result<(u16, String), String> {
    let resp = client.get(url).send().await.map_err(|e| crate::geo::describe_reqwest(&e))?;
    let code = resp.status().as_u16();
    let body = resp.text().await.unwrap_or_default();
    Ok((code, body))
}

/// Exit IP, the country Google assigns to it, and whether AI services accept it —
/// all forced through the active profile (the internal geo inbound always uses it).
pub async fn service_checks(proxy_port: u16) -> Vec<DiagStep> {
    let mut steps = Vec::new();
    let listen = crate::config::MIXED_LISTEN;
    // `active`: the internal inbound, always the active profile. `routed`: the normal
    // local proxy, so each service goes exactly where routing sends it (a service
    // pinned to another server is checked through that server).
    let make = |port: u16| {
        reqwest::Proxy::all(format!("http://{listen}:{port}")).and_then(|p| {
            reqwest::Client::builder()
                .proxy(p)
                .connect_timeout(Duration::from_secs(10))
                .timeout(Duration::from_secs(20))
                .user_agent("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126 Safari/537.36")
                .build()
        })
    };
    let (active, routed) = match (make(crate::config::geo_port(proxy_port)), make(proxy_port)) {
        (Ok(a), Ok(r)) => (a, r),
        (Err(e), _) | (_, Err(e)) => {
            steps.push(step("svc", "Сервисы через VPN", "skip", format!("не удалось создать клиент: {e}"), None));
            return steps;
        }
    };

    // 1. Exit IP of the active profile.
    let t = Instant::now();
    match get_via(&active, "https://api.ipify.org").await {
        Ok((200, ip)) => steps.push(step("exit-ip", "IP выхода (активный профиль)", "ok", ip.trim().to_string(), Some(t.elapsed().as_millis() as u64))),
        Ok((code, _)) => steps.push(step("exit-ip", "IP выхода (активный профиль)", "warn", format!("сервис ответил {code}"), None)),
        Err(e) => steps.push(step("exit-ip", "IP выхода (активный профиль)", "fail", format!("запрос через VPN не прошёл: {e}"), None)),
    }

    // 2. Country according to Google, along the Google route (www.google.com links
    //    carry it as utm_source=google-XX).
    let t = Instant::now();
    let label = "Страна по мнению Google (Google + Gemini)";
    match get_via(&routed, "https://www.google.com/?hl=en").await {
        Ok((_, body)) => match body.split("utm_source=google-").nth(1).and_then(|r| r.get(..2)).filter(|cc| cc.chars().all(|c| c.is_ascii_uppercase())) {
            Some(cc) if GEMINI_BLOCKED.contains(&cc) => steps.push(step(
                "google-country",
                label,
                "fail",
                format!("{cc} — Gemini покажет «недоступно в вашей стране». Закрепите сервис «Google + Gemini» за профилем, у которого Google видит другую страну (Маршрутизация → Google + Gemini → сервер)."),
                Some(t.elapsed().as_millis() as u64),
            )),
            Some(cc) => steps.push(step("google-country", label, "ok", format!("{cc} — Gemini доступен"), Some(t.elapsed().as_millis() as u64))),
            None => steps.push(step("google-country", label, "warn", "не удалось определить", None)),
        },
        Err(e) => steps.push(step("google-country", label, "fail", format!("Google не открывается: {e}"), None)),
    }

    // 3/4. AI APIs: 401 = reachable and region allowed (just no key); 403 = region blocked.
    for (id, label, url) in [
        ("claude", "Claude (Anthropic API)", "https://api.anthropic.com/v1/models"),
        ("openai", "ChatGPT (OpenAI API)", "https://api.openai.com/v1/models"),
    ] {
        let t = Instant::now();
        let ms = || Some(t.elapsed().as_millis() as u64);
        match get_via(&routed, url).await {
            Ok((401, _)) | Ok((200, _)) => steps.push(step(id, label, "ok", "доступен из этой страны", ms())),
            Ok((403, body)) => steps.push(step(
                id,
                label,
                "fail",
                format!("регион этого IP заблокирован сервисом{}", if body.contains("country") || body.contains("region") { "" } else { " (403)" }),
                ms(),
            )),
            Ok((code, _)) => steps.push(step(id, label, "warn", format!("ответ {code}"), ms())),
            Err(e) => steps.push(step(id, label, "fail", format!("не открывается через VPN: {e}"), None)),
        }
    }
    steps
}
