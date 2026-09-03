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
        Some(ip) => match icmp_ping(ip) {
            true => steps.push(step("local", "ПК → роутер / шлюз", "ok", format!("шлюз {ip} отвечает"), None)),
            false => {
                steps.push(step("local", "ПК → роутер / шлюз", "fail", format!("шлюз {ip} не отвечает"), None));
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
    let enc = test_url.replace(':', "%3A").replace('/', "%2F");
    let path = format!("/proxies/proxy/delay?timeout={timeout_ms}&url={enc}");
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

/// Windows: parse the default gateway from `route print 0.0.0.0` (locale-independent).
#[cfg(windows)]
fn default_gateway() -> Option<String> {
    let mut cmd = Command::new("route");
    cmd.args(["print", "0.0.0.0"]);
    use std::os::windows::process::CommandExt;
    cmd.creation_flags(0x0800_0000);
    let out = cmd.output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // "0.0.0.0  0.0.0.0  <gateway>  <iface>  <metric>"
        if cols.len() >= 3 && cols[0] == "0.0.0.0" && cols[1] == "0.0.0.0" {
            let gw = cols[2];
            if gw != "0.0.0.0" && gw.parse::<std::net::Ipv4Addr>().is_ok() {
                return Some(gw.to_string());
            }
        }
    }
    None
}

#[cfg(not(windows))]
fn default_gateway() -> Option<String> {
    // Linux: `ip route` -> "default via <gw> ..."
    let out = Command::new("ip").args(["route"]).output().ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        if line.starts_with("default via ") {
            return line.split_whitespace().nth(2).map(|s| s.to_string());
        }
    }
    None
}
