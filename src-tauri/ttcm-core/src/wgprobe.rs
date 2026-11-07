//! Is a WireGuard tunnel actually up when only its own networks go through it?
//!
//! sing-box reports no handshake time, and a home-network tunnel can't reach a test URL
//! on the internet. So the check asks hosts *behind* the tunnel: the first address of
//! each of its networks (the router / server, usually), on a few common ports, through
//! the core's local proxy (whose route sends those addresses into the tunnel).
//!
//! What the core does, checked against sing-box 1.14:
//! - it answers `CONNECT` with `200` at once and dials the target afterwards, so the
//!   `200` itself proves nothing;
//! - tunnel up: the remote host either accepts (and answers our request or greets us —
//!   SSH) or refuses, which closes the connection within a round trip;
//! - tunnel down (no handshake: wrong key, server off, UDP blocked): the dial hangs,
//!   the connection stays open and silent for well over the wait used here.
//!
//! So data or a quick close from any target = the tunnel answers; silence from all of
//! them = no answer through the tunnel.

use std::io::{ErrorKind, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use crate::config::bypass_cidr;
use crate::wireguard::WgTunnel;

/// Ports tried on each host: web UI, SSH, DNS — a router usually has one of them open,
/// and a closed one answers too (refuses).
pub const PROBE_PORTS: [u16; 4] = [80, 443, 22, 53];

/// At most this many hosts are asked (one per network, in the file's order).
const MAX_HOSTS: usize = 3;

/// How long to wait for a target to answer. The core keeps dialing a dead tunnel for
/// much longer, while a live one answers within a round trip.
pub const PROBE_WAIT: Duration = Duration::from_secs(4);

/// What one target did after the proxy accepted the `CONNECT`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reply {
    /// Sent something back (our HTTP request answered, an SSH greeting).
    Data,
    /// Closed or reset the connection — the target refused: it is reachable.
    Closed,
    /// Nothing within the wait: no answer through the tunnel.
    Silent,
    /// The local proxy itself didn't take the request (core down, wrong port, error
    /// status) — says nothing about the tunnel.
    ProxyError,
}

impl Reply {
    /// The target answered from behind the tunnel.
    pub fn answered(self) -> bool {
        matches!(self, Reply::Data | Reply::Closed)
    }
}

fn host_in(cidr: &str, own: &[IpAddr]) -> Option<IpAddr> {
    let c = bypass_cidr(cidr)?;
    let (ip, prefix) = c.split_once('/')?;
    let ip: IpAddr = ip.parse().ok()?;
    let prefix: u32 = prefix.parse().ok()?;
    let pick = |candidates: Vec<IpAddr>| candidates.into_iter().find(|h| !own.contains(h));
    match ip {
        IpAddr::V4(v4) => {
            if prefix < 2 {
                return None; // a catch-all half, not a network behind the tunnel
            }
            if prefix >= 31 {
                return pick(vec![ip]);
            }
            let mask = u32::MAX << (32 - prefix);
            let net = u32::from(v4) & mask;
            pick(vec![IpAddr::V4(Ipv4Addr::from(net + 1)), IpAddr::V4(Ipv4Addr::from(net + 2))])
        }
        IpAddr::V6(v6) => {
            if prefix < 2 {
                return None;
            }
            if prefix >= 127 {
                return pick(vec![ip]);
            }
            let mask = u128::MAX << (128 - prefix);
            let net = u128::from(v6) & mask;
            pick(vec![IpAddr::V6(Ipv6Addr::from(net + 1)), IpAddr::V6(Ipv6Addr::from(net + 2))])
        }
    }
}

/// The hosts to ask: the first address of each network the tunnel carries (the
/// catch-all ranges left out, the client's own tunnel address skipped).
pub fn probe_hosts(t: &WgTunnel) -> Vec<IpAddr> {
    let own: Vec<IpAddr> = t
        .interface
        .addresses
        .iter()
        .filter_map(|a| a.split('/').next()?.trim().parse().ok())
        .collect();
    let mut out = Vec::new();
    for c in t.peers.iter().flat_map(|p| p.allowed_ips.iter()) {
        if let Some(h) = host_in(c, &own) {
            if !out.contains(&h) {
                out.push(h);
            }
        }
        if out.len() == MAX_HOSTS {
            break;
        }
    }
    out
}

/// Every (host, port) to try, hosts first-to-last, ports in `PROBE_PORTS` order.
pub fn probe_targets(t: &WgTunnel) -> Vec<SocketAddr> {
    probe_hosts(t)
        .into_iter()
        .flat_map(|h| PROBE_PORTS.iter().map(move |&p| SocketAddr::new(h, p)))
        .collect()
}

/// Ask one target through the local HTTP proxy `proxy`.
pub fn probe_one(proxy: SocketAddr, target: SocketAddr, wait: Duration) -> Reply {
    let deadline = Instant::now() + wait;
    let Ok(mut s) = TcpStream::connect_timeout(&proxy, Duration::from_secs(2)) else {
        return Reply::ProxyError;
    };
    let _ = s.set_nodelay(true);
    let _ = s.set_write_timeout(Some(Duration::from_secs(2)));
    let req = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return Reply::ProxyError;
    }

    // The proxy's own reply first: "HTTP/1.x 200 ...\r\n\r\n".
    let mut head = Vec::new();
    let mut buf = [0u8; 512];
    let rest = loop {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Reply::ProxyError;
        }
        let _ = s.set_read_timeout(Some(left));
        match s.read(&mut buf) {
            Ok(0) => return Reply::ProxyError,
            Ok(n) => {
                head.extend_from_slice(&buf[..n]);
                if let Some(end) = head.windows(4).position(|w| w == b"\r\n\r\n") {
                    let status_ok = head.starts_with(b"HTTP/1.1 200") || head.starts_with(b"HTTP/1.0 200");
                    if !status_ok {
                        return Reply::ProxyError;
                    }
                    break head[end + 4..].to_vec();
                }
                if head.len() > 8192 {
                    return Reply::ProxyError;
                }
            }
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => return Reply::ProxyError,
            Err(_) => return Reply::ProxyError,
        }
    };
    if !rest.is_empty() {
        return Reply::Data;
    }

    // Then the target: a server that speaks first (SSH) greets us, a closed port is
    // refused — both within a round trip. Only if it stays quiet do we send an HTTP
    // request (a web UI answers it), so an SSH server never gets garbage to log.
    let greeting_until = Instant::now() + greeting_wait(wait);
    let mut asked = false;
    loop {
        let now = Instant::now();
        if now >= deadline {
            return Reply::Silent;
        }
        if !asked && now >= greeting_until {
            asked = true;
            let head = format!("HEAD / HTTP/1.0\r\nHost: {}\r\n\r\n", target.ip());
            if s.write_all(head.as_bytes()).is_err() {
                return Reply::Closed;
            }
        }
        let until = if asked { deadline } else { greeting_until.min(deadline) };
        let _ = s.set_read_timeout(Some(until.saturating_duration_since(now).max(Duration::from_millis(1))));
        return match s.read(&mut buf) {
            Ok(0) => Reply::Closed,
            Ok(_) => Reply::Data,
            Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut | ErrorKind::Interrupted) => {
                continue
            }
            // Reset / aborted: the target (or the core on its behalf) refused.
            Err(_) => Reply::Closed,
        };
    }
}

/// How long a target gets to speak first before we send our HTTP request.
fn greeting_wait(wait: Duration) -> Duration {
    (wait / 3).min(Duration::from_millis(1500))
}

/// The result of asking all targets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Probe {
    /// This target answered through the tunnel.
    Answered(SocketAddr),
    /// The proxy took the requests, nothing behind the tunnel answered.
    Silent,
    /// The local proxy didn't take any request — the check couldn't run.
    NoProxy,
    /// The tunnel has no networks to ask (only catch-all ranges).
    NoTargets,
}

/// Ask the targets in parallel (`first`, the one that answered last time, alone first:
/// one connection per check while it keeps answering) and return once one answers.
///
/// A target that answers with data is preferred over one that refused: the caller asks
/// the returned one alone next time, and every refusal is an error line in the core's
/// log (once every 15 s, forever, if a refusing port were remembered).
pub fn probe(proxy: SocketAddr, targets: &[SocketAddr], first: Option<SocketAddr>, wait: Duration) -> Probe {
    if targets.is_empty() {
        return Probe::NoTargets;
    }
    if let Some(f) = first.filter(|f| targets.contains(f)) {
        if probe_one(proxy, f, wait).answered() {
            return Probe::Answered(f);
        }
    }
    let (tx, rx) = mpsc::channel();
    for &t in targets {
        let tx = tx.clone();
        std::thread::spawn(move || {
            let _ = tx.send((t, probe_one(proxy, t, wait)));
        });
    }
    drop(tx);
    let mut proxy_errors = 0;
    let mut refused: Option<SocketAddr> = None;
    let mut deadline = Instant::now() + wait + Duration::from_secs(3);
    while let Ok((t, r)) = rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
        match r {
            Reply::Data => return Probe::Answered(t),
            Reply::Closed => {
                if refused.is_none() {
                    refused = Some(t);
                    // The tunnel is up; give a talking target (a greeting, or an answer to
                    // our HTTP request) a moment more before settling for this one.
                    deadline = deadline.min(Instant::now() + greeting_wait(wait) + Duration::from_millis(800));
                }
            }
            Reply::ProxyError => proxy_errors += 1,
            Reply::Silent => {}
        }
    }
    if let Some(t) = refused {
        Probe::Answered(t)
    } else if proxy_errors == targets.len() {
        Probe::NoProxy
    } else {
        Probe::Silent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wireguard::{WgInterface, WgPeer};
    use std::net::TcpListener;

    fn tunnel(addresses: &[&str], allowed: &[&str]) -> WgTunnel {
        WgTunnel {
            id: "t".into(),
            name: "t".into(),
            interface: WgInterface {
                private_key: "k".into(),
                addresses: addresses.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            },
            peers: vec![WgPeer {
                public_key: "p".into(),
                endpoint: Some("46.138.253.10:51820".into()),
                allowed_ips: allowed.iter().map(|s| s.to_string()).collect(),
                ..Default::default()
            }],
        }
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn hosts_are_first_address_of_each_network() {
        let t = tunnel(
            &["10.6.0.3/32"],
            &["10.6.0.0/24", "192.168.10.0/24", "192.168.20.0/24", "46.138.253.10/32"],
        );
        assert_eq!(probe_hosts(&t), vec![ip("10.6.0.1"), ip("192.168.10.1"), ip("192.168.20.1")]);
    }

    #[test]
    fn host_bits_in_the_entry_are_masked() {
        let t = tunnel(&[], &["192.168.10.77/24"]);
        assert_eq!(probe_hosts(&t), vec![ip("192.168.10.1")]);
    }

    #[test]
    fn single_addresses_are_asked_as_is() {
        let t = tunnel(&["10.6.0.3/32"], &["46.138.253.10/32", "10.0.0.8/31"]);
        assert_eq!(probe_hosts(&t), vec![ip("46.138.253.10"), ip("10.0.0.8")]);
    }

    #[test]
    fn own_address_is_skipped() {
        let t = tunnel(&["10.6.0.1/24"], &["10.6.0.0/24"]);
        assert_eq!(probe_hosts(&t), vec![ip("10.6.0.2")]);
    }

    #[test]
    fn catch_all_ranges_have_no_hosts() {
        let t = tunnel(&["10.6.0.3/32"], &["0.0.0.0/0", "::/0", "0.0.0.0/1", "128.0.0.0/1"]);
        assert!(probe_hosts(&t).is_empty());
        assert!(probe_targets(&t).is_empty());
    }

    #[test]
    fn full_tunnel_with_extra_network_still_has_a_host() {
        let t = tunnel(&["10.6.0.3/32"], &["0.0.0.0/0", "10.6.0.0/24"]);
        assert_eq!(probe_hosts(&t), vec![ip("10.6.0.1")]);
    }

    #[test]
    fn ipv6_networks() {
        let t = tunnel(&["fd00::3/128"], &["fd00::/64"]);
        assert_eq!(probe_hosts(&t), vec![ip("fd00::1")]);
    }

    #[test]
    fn invalid_entries_are_ignored_and_duplicates_merged() {
        let t = tunnel(&[], &["garbage", "10.6.0.0/24", "10.6.0.0/24", "10.6.0.5/24", "10.6.0.0/40"]);
        assert_eq!(probe_hosts(&t), vec![ip("10.6.0.1")]);
    }

    #[test]
    fn at_most_three_hosts() {
        let t = tunnel(&[], &["10.1.0.0/24", "10.2.0.0/24", "10.3.0.0/24", "10.4.0.0/24"]);
        assert_eq!(probe_hosts(&t).len(), 3);
        assert_eq!(probe_targets(&t).len(), 3 * PROBE_PORTS.len());
        assert_eq!(probe_targets(&t)[0], "10.1.0.1:80".parse().unwrap());
    }

    /// A stand-in for the core's mixed inbound: answers CONNECT with 200 at once (like
    /// sing-box), then behaves as `target` does.
    #[derive(Clone, Copy)]
    enum Fake {
        /// Speaks first (SSH).
        Greets,
        /// Refuses (a closed port).
        Refuses,
        /// Quiet until asked, then answers (a web UI).
        AnswersHttp,
        /// Nothing at all (no handshake).
        Hangs,
        Rejects,
        DropsBeforeReply,
        /// Like a MikroTik: 22 greets, 80/443 refuse, the rest hang.
        Router,
    }

    use std::sync::{Arc, Mutex};

    /// Bytes each connection sent after its CONNECT, per target port.
    type Sent = Arc<Mutex<Vec<(u16, Vec<u8>)>>>;

    fn fake_proxy(mode: Fake) -> SocketAddr {
        fake_proxy_recording(mode).0
    }

    fn fake_proxy_recording(mode: Fake) -> (SocketAddr, Sent) {
        let l = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = l.local_addr().unwrap();
        let sent: Sent = Arc::default();
        let sent2 = sent.clone();
        std::thread::spawn(move || {
            for s in l.incoming() {
                let Ok(mut s) = s else { continue };
                let sent = sent2.clone();
                std::thread::spawn(move || {
                    let mut buf = [0u8; 1024];
                    let n = s.read(&mut buf).unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]).to_string();
                    let port: u16 = req
                        .split_whitespace()
                        .nth(1)
                        .and_then(|t| t.rsplit(':').next())
                        .and_then(|p| p.parse().ok())
                        .unwrap_or(0);
                    let mode = match (mode, port) {
                        (Fake::Router, 22) => Fake::Greets,
                        (Fake::Router, 80 | 443) => Fake::Refuses,
                        (Fake::Router, _) => Fake::Hangs,
                        (m, _) => m,
                    };
                    match mode {
                        Fake::DropsBeforeReply => return,
                        Fake::Rejects => {
                            let _ = s.write_all(b"HTTP/1.1 502 Bad Gateway\r\n\r\n");
                            return;
                        }
                        _ => {}
                    }
                    let _ = s.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
                    let mut after = Vec::new();
                    let _ = s.set_read_timeout(Some(Duration::from_millis(100)));
                    fn collect(s: &mut TcpStream, after: &mut Vec<u8>, for_ms: u64) {
                        let mut buf = [0u8; 1024];
                        let until = Instant::now() + Duration::from_millis(for_ms);
                        while Instant::now() < until {
                            match s.read(&mut buf) {
                                Ok(0) => break,
                                Ok(n) => after.extend_from_slice(&buf[..n]),
                                Err(_) => {}
                            }
                        }
                    }
                    match mode {
                        Fake::Greets => {
                            std::thread::sleep(Duration::from_millis(50));
                            let _ = s.write_all(b"SSH-2.0-ROSSSH\r\n");
                            collect(&mut s, &mut after, 400);
                        }
                        Fake::Refuses => std::thread::sleep(Duration::from_millis(50)),
                        Fake::AnswersHttp => {
                            let until = Instant::now() + Duration::from_secs(3);
                            while Instant::now() < until && !after.windows(4).any(|w| w == b"\r\n\r\n") {
                                collect(&mut s, &mut after, 100);
                            }
                            let _ = s.write_all(b"HTTP/1.0 200 OK\r\n\r\n");
                        }
                        Fake::Hangs => collect(&mut s, &mut after, 3000),
                        _ => {}
                    }
                    sent.lock().unwrap().push((port, after));
                });
            }
        });
        (addr, sent)
    }

    fn target() -> SocketAddr {
        "10.6.0.1:22".parse().unwrap()
    }

    const WAIT: Duration = Duration::from_millis(700);

    #[test]
    fn greeting_means_answered() {
        assert_eq!(probe_one(fake_proxy(Fake::Greets), target(), WAIT), Reply::Data);
    }

    #[test]
    fn a_server_that_speaks_first_gets_no_request() {
        let (proxy, sent) = fake_proxy_recording(Fake::Greets);
        assert_eq!(probe_one(proxy, target(), WAIT), Reply::Data);
        std::thread::sleep(Duration::from_millis(500));
        let sent = sent.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert!(sent[0].1.is_empty(), "sent to SSH: {:?}", String::from_utf8_lossy(&sent[0].1));
    }

    #[test]
    fn a_quiet_server_is_asked_over_http() {
        let (proxy, sent) = fake_proxy_recording(Fake::AnswersHttp);
        let t: SocketAddr = "10.6.0.1:80".parse().unwrap();
        assert_eq!(probe_one(proxy, t, WAIT), Reply::Data);
        std::thread::sleep(Duration::from_millis(200));
        let sent = sent.lock().unwrap();
        assert!(String::from_utf8_lossy(&sent[0].1).starts_with("HEAD / HTTP/1.0"));
    }

    #[test]
    fn a_target_that_talks_is_preferred_over_one_that_refuses() {
        let targets = probe_targets(&tunnel(&[], &["10.6.0.0/24", "192.168.10.0/24"]));
        // 80/443 refuse at once, 22 greets a little later: 22 is the one to remember.
        match probe(fake_proxy(Fake::Router), &targets, None, WAIT) {
            Probe::Answered(t) => assert_eq!(t.port(), 22, "remembered {t}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn only_refusals_still_mean_the_tunnel_is_up() {
        let targets = probe_targets(&tunnel(&[], &["10.6.0.0/24"]));
        let start = Instant::now();
        assert!(matches!(probe(fake_proxy(Fake::Refuses), &targets, None, WAIT), Probe::Answered(_)));
        assert!(start.elapsed() < WAIT * 3, "took {:?}", start.elapsed());
    }

    #[test]
    fn quick_close_means_refused_and_answered() {
        let r = probe_one(fake_proxy(Fake::Refuses), target(), WAIT);
        assert_eq!(r, Reply::Closed);
        assert!(r.answered());
    }

    #[test]
    fn silence_after_200_means_no_answer() {
        let r = probe_one(fake_proxy(Fake::Hangs), target(), WAIT);
        assert_eq!(r, Reply::Silent);
        assert!(!r.answered());
    }

    #[test]
    fn proxy_errors_say_nothing_about_the_tunnel() {
        assert_eq!(probe_one(fake_proxy(Fake::Rejects), target(), WAIT), Reply::ProxyError);
        assert_eq!(probe_one(fake_proxy(Fake::DropsBeforeReply), target(), WAIT), Reply::ProxyError);
        // Nothing listening.
        let free = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        assert_eq!(probe_one(free, target(), WAIT), Reply::ProxyError);
        assert!(!Reply::ProxyError.answered());
    }

    #[test]
    fn probe_reports_the_target_that_answered() {
        let targets = probe_targets(&tunnel(&[], &["10.6.0.0/24"]));
        assert!(matches!(probe(fake_proxy(Fake::Greets), &targets, None, WAIT), Probe::Answered(_)));
    }

    #[test]
    fn probe_silent_and_fast() {
        let targets = probe_targets(&tunnel(&[], &["10.6.0.0/24", "192.168.10.0/24"]));
        let start = Instant::now();
        assert_eq!(probe(fake_proxy(Fake::Hangs), &targets, None, WAIT), Probe::Silent);
        // Parallel: about one wait, not one per target.
        assert!(start.elapsed() < WAIT * 3, "took {:?}", start.elapsed());
    }

    #[test]
    fn probe_without_proxy_or_targets() {
        let free = TcpListener::bind("127.0.0.1:0").unwrap().local_addr().unwrap();
        let targets = probe_targets(&tunnel(&[], &["10.6.0.0/24"]));
        assert_eq!(probe(free, &targets, None, WAIT), Probe::NoProxy);
        assert_eq!(probe(free, &[], None, WAIT), Probe::NoTargets);
    }

    /// Against a running core: `TTCM_PROBE_PROXY=127.0.0.1:2080 TTCM_PROBE_NETS=10.6.0.0/24
    /// cargo test -p ttcm-core live_probe -- --ignored --nocapture`.
    #[test]
    #[ignore]
    fn live_probe() {
        let proxy: SocketAddr = std::env::var("TTCM_PROBE_PROXY").unwrap().parse().unwrap();
        let nets = std::env::var("TTCM_PROBE_NETS").unwrap();
        let t = tunnel(&[], &nets.split(',').collect::<Vec<_>>());
        for target in probe_targets(&t) {
            println!("{target}: {:?}", probe_one(proxy, target, PROBE_WAIT));
        }
        println!("probe: {:?}", probe(proxy, &probe_targets(&t), None, PROBE_WAIT));
    }

    #[test]
    fn remembered_target_is_tried_first() {
        let targets = probe_targets(&tunnel(&[], &["10.6.0.0/24"]));
        let first = targets[2];
        assert_eq!(probe(fake_proxy(Fake::Greets), &targets, Some(first), WAIT), Probe::Answered(first));
        // A remembered target that's no longer in the list is ignored.
        let stale: SocketAddr = "1.2.3.4:80".parse().unwrap();
        assert!(matches!(probe(fake_proxy(Fake::Greets), &targets, Some(stale), WAIT), Probe::Answered(t) if t != stale));
    }
}
