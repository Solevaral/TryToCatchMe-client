# TryToCatchMe

A cross-platform VPN / proxy client built on **Tauri 2 + Rust + React**, using
[**sing-box**](https://github.com/SagerNet/sing-box) 1.14 as its core engine (run as a
bundled sidecar and controlled through its Clash API).

Windows and Linux are supported today. Downloads are on the
[Releases](https://github.com/Solevaral/TryToCatchMe-client/releases) page: a Windows
installer and a Linux AppImage.

## Features

### Profiles
- **Import from clipboard** — paste `vless://`, `vmess://`, `ss://`, `trojan://` links
  or a base64 subscription blob and get ready-to-use profiles.
- VLESS + Reality / TLS, VMess, Trojan, Shadowsocks (SIP002) with TCP, WebSocket,
  gRPC, HTTP/2, HTTPUpgrade and QUIC transports.
- Latency test per profile, one active profile, links kept for re-parsing.
- **Auto-failover** — switches to the next profile when the active server stops
  passing traffic.

### Routing
- **Global / Direct / Rule** modes.
- **Services** — an additive, editable catalog (Google + Gemini, YouTube, Cloudflare,
  Telegram, Discord, Steam, Netflix, …) plus a searchable library of 30 more
  (ChatGPT, Claude, X, Instagram, Spotify, GitHub, …). Each service is
  *through VPN*, *direct* or *blocked*, and you can add or remove its domains/IPs.
- **Community lists behind services** — Google, OpenAI and Anthropic are also backed
  by the sing-geosite lists, so new subdomains are covered without manual edits.
- **A server per service** — pin any service to a specific profile while everything
  else uses the active one (e.g. YouTube over a gRPC server, Google + Gemini over a
  server that Google doesn't geolocate to a blocked country). Each pinned server gets
  its own DNS-over-HTTPS resolver, so a site is resolved and opened in the same
  country.
- **Order-independent rules** — narrower services always match before broader ones,
  whatever order they were added in.
- **Region lists** — geosite/geoip by region (e.g. RU sites direct). Lists are
  downloaded by the app itself (through the VPN first, then directly), validated, and
  kept if a later update fails, so a blocked download never breaks connecting.
- Private/LAN addresses always go direct.

### Traffic capture
- **System proxy** — the app owns the OS proxy setting: it remembers yours, points
  the system at its local port and restores the original on disconnect, even after a
  crash. Windows (WinINet) and Linux (GNOME / KDE). If another app takes the proxy
  over, you are told and can re-apply it in one click.
- **TUN** — captures all traffic, including apps that ignore the proxy (needs admin
  rights; the app offers to relaunch elevated). The system proxy is pointed at the app
  in TUN mode too, so apps that read it (Electron apps, browsers) can't be sent past
  the tunnel by a proxy another client left behind.
- Copy-ready `HTTP_PROXY` / `HTTPS_PROXY` commands for PowerShell, cmd and bash/zsh,
  for CLI tools that ignore the system proxy.
- Configurable local proxy port.

### Security
- DNS follows routing: proxied domains are resolved via DoH inside the tunnel,
  direct ones via the system resolver — no DNS leaks to the ISP, and a broken proxy
  can't take down direct sites.
- Optional QUIC / UDP 443 block, so traffic falls back to TLS over TCP.
- Warns when another VPN client (Hiddify, v2rayN, Clash, NekoBox, …) is running and
  may fight over the system proxy or routes.

### Diagnostics
- **Network chain check** — PC → gateway → ISP → VPN server → tunnel → targets, with a
  verdict on where it breaks, telling DPI/throttling apart from a dead server.
- Targets are checked both directly and *through* the tunnel.
- **Service checks along the real route** — the active exit IP, the country Google
  sees for Google + Gemini, and whether Claude and ChatGPT accept that region.
- **Tunnel warm-up** after connecting (active and pinned servers), shown in the
  sidebar, so the first page doesn't hang.

### App
- Live up/down speed and a real-time, filterable log console (core + app events).
- **Quiet by default** — the core only reports warnings and errors; a "verbose logs"
  switch streams every connection for troubleshooting (thousands of lines a second in
  TUN mode, so the UI batches them and drops the overflow).
- Connect / disconnect / restart from the sidebar; connect, disconnect and diagnostics
  from the tray, whose icon reflects the connection state; close-to-tray; autostart;
  dark theme.

## Repository layout

```
src/                     React + TypeScript frontend (pages, store, api)
src-tauri/               Rust backend (Tauri 2)
  src/
    core/                sing-box sidecar lifecycle, warm-up
    clash/               Clash API client (traffic / logs)
    routing/             service catalog, routing store, migrations
    profiles/            profile storage
    settings/            persisted settings
    geo/                 geosite / geoip list downloads
    sysproxy/            OS system proxy (snapshot / apply / restore)
    diag/                network chain and service diagnostics
    monitor/             auto-failover
    tray/                system tray
    platform/            OS-specific integration
  ttcm-core/             pure, platform-independent logic (link parsing, config
                         generation, routing model, gateway and proxy parsing)
                         with unit tests
  resources/             built-in service presets and library
scripts/                 helper scripts (fetch core, dev, build)
.github/workflows/       release CI (Windows + Linux)
```

The `ttcm-core` crate has no Tauri/OS dependencies, so its parsers and config
generator are unit-tested in isolation:

```bash
cd src-tauri && cargo test -p ttcm-core
```

## Building from source

### Prerequisites

- **Node.js** 18+ and npm
- **Rust** (stable)
- On Windows without Visual Studio Build Tools, use the GNU toolchain and MinGW-w64:
  `rustup default stable-x86_64-pc-windows-gnu` and install MSYS2 at `C:\msys64`
  (the linker path is set in `src-tauri/.cargo/config.toml`).
- On Linux: `libwebkit2gtk-4.1-dev`, `librsvg2-dev`, `libssl-dev`,
  `libayatana-appindicator3-dev` (see the release workflow for the full list).

### Fetch the sing-box core

The core binary is not committed. Fetch it once:

```bash
# Windows (PowerShell)
./scripts/fetch-core.ps1
# Linux
bash ./scripts/fetch-core.sh
```

### Install and run

```bash
npm install
npm run tauri dev
```

On Windows, make sure MinGW is on `PATH` (`scripts/dev.ps1` does this for you).

### Package a release build

```bash
npm run tauri build
```

Installers/binaries are written to `src-tauri/target/release/bundle/`.

## Releases

Pushing a `v*` tag triggers the GitHub Actions workflow, which builds and publishes a
Windows installer and a Linux AppImage to the GitHub Release.

## License

MIT — see [LICENSE](LICENSE).
