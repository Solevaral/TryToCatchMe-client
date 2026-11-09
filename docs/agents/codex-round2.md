Task: round 2 — fix the known bugs below, then make every status in the UI truthful,
fresh, and add small QOL improvements. Follow AGENTS.md. No git. Report in Russian into
`docs/agents/codex-round2-report.md`. Long task: work through every part, don't stop early.

You may edit any file under `src-tauri/ttcm-core/src/`, `src-tauri/src/` and `src/`
(overrides "only the named files"). No new dependencies, don't touch Cargo.toml,
package.json, CI, scripts, icons, `tauri.conf.json`. Your previous report is
`docs/agents/codex-bughunt-report.md` — it describes these bugs in more detail.

## Part A — known bugs (all must be fixed, each with a test)

A1. **Duplicate import** (`src-tauri/src/profiles/mod.rs` ~104). Importing the same link
    again creates a duplicate profile with a new id. Rule: a manually imported profile
    is a duplicate when its outbound is identical to an existing manual profile ignoring
    the `tag` and the display name. Duplicates are skipped and the import result tells
    the UI how many were skipped (show "Пропущено дубликатов: N" on ProfilesPage).
    Subscription profiles are not affected (they are replaced by their subscription).
    Put the identity comparison in a pure function with tests.

A2. **Diagnostics target with IPv6 / port** (`src-tauri/src/diag/mod.rs` ~140). Splitting
    on the first `:` breaks `[2001:db8::1]:443` and `2001:db8::1`; a user-given port is
    lost in the "через VPN" URL. Write one pure parser in ttcm-core (host, optional port,
    optional scheme/path; accepts `host`, `host:port`, `[v6]`, `[v6]:port`, bare v6,
    `https://host:port/path`) with tests, and use it everywhere diag parses a target.
    Do not change HY2/UDP probing semantics beyond reporting in the text that a TCP
    probe of a UDP-only protocol (hysteria2) is not meaningful.

A3. **Reserved ports**. Proxy port can be set to 9090 (Clash API) or to a value where
    port+1 (geo inbound) / port+2 (Linux PAC) collides with Clash API or exceeds 65535.
    Add a pure validator in ttcm-core (`fn validate_ports(proxy_port, clash_port, ...)
    -> Result<(), String>` with Russian messages), call it in the settings save command
    (reject with an error), show the error in SettingsPage next to the field, and when
    loading old saved settings with an invalid port fall back to the default port (log
    it). Turn the existing ignored test `proxy_port_must_not_collide_with_controller`
    into a passing test.

A4. **Swallowed save errors** (`settings/mod.rs` ~188, `profiles/mod.rs` ~104/139, and the
    routing/wireguard stores if they do the same). Store saves must return
    `Result<(), String>`, write atomically (write `*.tmp` next to the file, then rename;
    on Windows rename-over must work — remove/replace correctly), and commands must
    propagate the error to the UI instead of reporting success. If the save fails, the
    in-memory state must not claim the change was saved (either roll back or report
    clearly — pick one and say which). UI pages show the error text.

A5. **Restart is not atomic** (`src-tauri/src/core/mod.rs` ~708, `monitor/mod.rs` ~34/42,
    `core/mod.rs` ~97). Restart takes the `op` lock separately for stop and start, so
    another apply/stop can run in between. Make restart hold one critical section for
    stop+start. Also fix the monitor deadlock risk: apply must never join the monitor
    thread while holding `op` if the monitor can itself wait for `op` (signal it to stop
    and detach/join outside the lock, or make the monitor use try-lock and skip its
    action when an operation is in progress). Keep the existing `ApplyQueue` semantics
    and its 5 tests passing. Extract any decision logic you add into pure functions
    with tests. Be careful: this is the core lifecycle; keep the change minimal and
    explain it in the report step by step.

A6. **Sysproxy backup lost** (`src-tauri/src/sysproxy/mod.rs` ~104/123). The backup is
    deleted even when restoring failed. Keep the backup until restore succeeds; a
    later restore attempt (next start/exit) must still be able to use it. Also Linux
    `sysproxy/os.rs` ~345/390: return errors when gsettings/kwriteconfig exit non-zero.
    Test the backup decision logic as a pure function (no registry/OS calls in tests).

## Part B — truthful and fresh UI (main focus after Part A)

The user's main complaint: the app says "connected / works" when there is actually no
connection. Go through EVERY status indicator in the UI (App.tsx sidebar and header,
tray state, ProfilesPage active profile, WireGuardPage, SysProxyLine, SettingsPage,
DiagnosticsPage, LogsPage) and for each one write down in the report: what it shows,
where the value comes from, when it updates, and in which real situations it lies.
Then fix the lies. Situations to handle at minimum:
- sing-box process exits or crashes after a successful start → UI must leave
  "connected" within a few seconds (backend event or status poll), tray too;
- core is running but the active proxy is unreachable (the monitor already checks
  health — make its result visible: "подключено, но сервер не отвечает");
- system proxy mode: another program removed/changed the OS proxy → show it;
- TUN mode requested but the adapter isn't up / start partly failed;
- WireGuard: never "подключён" without a passed check (already partly done);
- status loaded once on page mount and never refreshed (refresh on window focus /
  after related actions / on backend events);
- profile list, ping results, subscription info stale after import/update/delete.
Prefer backend events (`app.emit`) for changes that originate in the backend, with
the listener cleaned up in the UI. Keep polling light (no more than once per 3-5 s,
and only while the window is visible).

## Part C — QOL (small, safe, in Russian)
Implement the ones that are cheap and clearly useful, list the rest as proposals:
- profiles: filter/search box when there are more than ~8 profiles; sort by last
  ping; show last ping result until the next ping; "copy link" for a profile if the
  original link is stored; double-click a profile to make it active;
- show which profile is active and since when in the sidebar; uptime of connection;
- error messages: one consistent dismissible error banner per page instead of silent
  failures; Escape closes modals; confirm before destructive actions everywhere;
- diagnostics: "скопировать отчёт" button (text summary, no secrets/links/keys);
- anything else you notice that is a 5-30 line improvement.
Do not redesign pages, do not change colours/layout globally.

## Rules
- Bug fix → test that fails without it (Rust). UI → TypeScript must compile; you may
  verify logic with local mocks like last time, but add no test framework.
- No behaviour changes that aren't bugs or the QOL above. No refactors of untouched code.
- Never start the app or sing-box, never touch network/VPN/proxy/system settings, never
  kill a process. Tests offline, fast, no real registry/gsettings calls.

## Checks before you finish
- `cd src-tauri && cargo test -p ttcm-core` and `cargo test -p trytocatchme --lib` — all
  pass, no new warnings.
- `npx.cmd tsc --noEmit -p .` — no errors.

## Report (Russian) in docs/agents/codex-round2-report.md
1. Part A: per item — what was wrong, what you changed (files), tests.
2. Part B: the table of indicators (shows / source / updates / lied when / fixed how).
3. Part C: implemented QOL and proposals not done.
4. Anything risky the reviewer must look at closely.
5. Check results.
