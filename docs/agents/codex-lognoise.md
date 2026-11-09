Task: stop known-harmless sing-box errors from flooding the log. Follow AGENTS.md.
No git. Report in Russian.

Real log of the user (470 lines, ~90% noise). Core error kinds and counts:
- 135+135 `dns: lookup failed for ipv6.msftconnecttest.com: empty result` and the paired
  `router: lookup ipv6.msftconnecttest.com: empty result` (also for
  brunhild.challenges.cloudflare.com). Cause: "IPv4 only" mode — AAAA-only names get no
  answer. Harmless (Windows connectivity check).
- 95+14 `connection: connection upload closed: raw-read tcp 127.0.0.1:2080->127.0.0.1:62765: An existing connection was forcibly closed by the remote host.`
  (and `download closed: raw-read tcp 192.168.31.132:64205->4.150.223.112:443: ...`).
  Cause: the browser/app or the remote side reset a connection that was already open.
  Harmless. Same class: `connection reset by peer`, `broken pipe`,
  `use of closed network connection`, `EOF` in an `upload closed` / `download closed` line.
- 18 `connection: open connection to 10.6.0.1:80 using outbound/wireguard[wg]: connect tcp 10.6.0.1:80: connection was refused`
  (also 192.168.20.1:443). Cause: OUR OWN WireGuard reachability probe
  (`ttcm-core/src/wgprobe.rs`, `PROBE_PORTS`) — "refused" is exactly the answer it wants.
- Keep: NXDOMAIN, i/o timeout, `dial tcp ... i/o timeout`, TLS/handshake/reality errors,
  everything else — those are real signals.

## What to do
1. `ttcm-core/src/logfile.rs`: add `pub fn is_noise(text: &str, probe_targets: &[SocketAddr]) -> bool`
   (pure) covering the three classes above. For the WG class, hide a refused line only when
   its target `ip:port` is one of `probe_targets` (a real user connection that is refused
   must still show). Use it in `lines_for_event` (add the parameter, or a second function
   — your choice, keep the existing callers compiling). Tests with the exact lines above
   plus lines that must be kept.
2. App side (`src-tauri/src/applog/mod.rs`, `wireguard/mod.rs`): pass the current probe
   targets (the probe already knows them / `last_target`; expose what's needed).
3. Don't lose the information entirely: count hidden lines and once per 10 minutes
   (only if the count > 0) write one `[app]` line like
   `Скрыто типовых сообщений ядра за 10 мин: 270 (IPv6-запросы в режиме «только IPv4», обрывы соединений клиентом, проверки WireGuard)`.
   Counting/flush logic as a pure struct in ttcm-core with tests.
4. The Logs page (`src/pages/LogsPage.tsx`) — check whether it shows live `clash://log`
   events directly besides the file; if yes, apply the same filter there (the backend can
   filter before emitting, preferred) so the page and the file agree.

## Checks
`cd src-tauri && cargo test -p ttcm-core` and `cargo test -p trytocatchme --lib`,
`npx.cmd tsc --noEmit -p .` — all pass, no new warnings.
