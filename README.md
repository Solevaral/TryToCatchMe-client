# TryToCatchMe

A cross-platform VPN / proxy client built on **Tauri 2 + Rust + React**, using
[**sing-box**](https://github.com/SagerNet/sing-box) as its core engine (run as a
bundled sidecar and controlled through its Clash API).

Supported protocols (via sing-box): WireGuard, Shadowsocks, VLESS + Reality, Trojan,
VMess. Windows and Linux are supported today.

## Features

- **Import from clipboard** — paste `vless://`, `vmess://`, `ss://`, `trojan://` links
  or a base64 subscription blob and get ready-to-use profiles.
- **Routing** — Global / Direct / Rule modes, per-domain and per-IP rules, and an
  additive, editable catalog of services (Cloudflare, Steam, YouTube, …) plus a large
  built-in library (ChatGPT, Claude, Facebook, Instagram, X, …). Optional
  geosite/geoip rule-sets by region.
- **Live traffic + log console** — real-time up/down speed and a filterable log stream
  from the core.
- **Network diagnostics** — probes the whole chain (PC → router → ISP → VPN server →
  tunnel → target) and localizes where the break is, distinguishing DPI/throttling from
  a dead server. Targets are checked *through* the tunnel, so a broken proxy path is
  reported honestly.
- **Security** — DNS-over-HTTPS through the tunnel (anti-leak) and an optional QUIC block.
- **Auto-failover** — switch to the next profile automatically when the active server
  stops responding.
- System tray with connection-state icon, close-to-tray, autostart, dark theme.

## Repository layout

```
src/                     React + TypeScript frontend (pages, store, api)
src-tauri/               Rust backend (Tauri 2)
  src/
    core/                sing-box sidecar lifecycle
    clash/               Clash API client (traffic / logs)
    routing/             service catalog + routing store
    profiles/            profile storage
    settings/            persisted settings
    diag/                network chain diagnostics
    monitor/             auto-failover
    platform/            OS-specific integration
  ttcm-core/             pure, platform-independent logic (link parsing,
                         config generation, routing model) with unit tests
scripts/                 helper scripts (fetch core, dev, build)
.github/workflows/       release CI (Windows + Linux)
```

The `ttcm-core` crate has no Tauri/OS dependencies, so its parsers and config
generator are unit-tested in isolation and easy to reuse.

## Building from source

### Prerequisites

- **Node.js** 18+ and npm
- **Rust** (stable)
- On Windows without Visual Studio Build Tools, use the GNU toolchain and MinGW-w64:
  `rustup default stable-x86_64-pc-windows-gnu` and install MSYS2 at `C:\msys64`
  (the linker path is set in `src-tauri/.cargo/config.toml`).

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
Windows installer + portable `.exe` and a Linux AppImage to the GitHub Release.

## License

MIT — see [LICENSE](LICENSE).
