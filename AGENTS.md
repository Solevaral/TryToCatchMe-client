# Rules for coding agents (Codex)

TryToCatchMe (TTCM): a Tauri 2 desktop VPN client. Frontend: React + TypeScript (`src/`).
Backend: Rust (`src-tauri/src/`, the app) and `src-tauri/ttcm-core/` (pure logic, no Tauri,
no OS calls — everything here must be unit-testable). The VPN engine is sing-box 1.14.

## Hard rules
- Do not run git. Do not touch network, VPN, proxy, firewall or system settings, and do
  not start, stop or kill any process (especially `sing-box.exe` / `TryToCatchMe.exe` —
  the user's internet runs through them).
- Do not read or print files under `%APPDATA%`, `.env`, keys or profile links.
- Only change the files the task names; ask in your report if more seems needed.
- UI text is Russian; code comments and identifiers are English.

## Checks before you finish
- `cd src-tauri && cargo test -p ttcm-core` — all pass, no new warnings.
- `npx tsc --noEmit -p .` — no errors.
- Report in Russian: what you changed (files), what you tested, anything unsure.

## Style
- Rust: small pure functions with `#[cfg(test)]` tests next to them; serde for JSON;
  `serde_json::json!` for sing-box config objects. Follow existing modules
  (`ttcm-core/src/wgprobe.rs` is a good example).
- TypeScript: typed wrappers in `src/api/backend.ts`, pages in `src/pages/`, existing
  `btn` / `muted` / `card` classes, CSS variables `--ok`, `--warn`, `--err`.
