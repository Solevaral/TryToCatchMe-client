Task: a deep bug hunt across the whole project, plus unit tests. Follow AGENTS.md.
No git. Report in Russian into the output file. This is a long task: take your time,
go module by module, and do not stop after the first few findings.

Goal: find real bugs in logic and UI, fix the small obvious ones with a test that fails
without the fix, and cover untested pure logic with meaningful tests. Quality over
quantity: a test that only restates the code is worthless; a test must pin behaviour a
user would notice (a broken link import, a wrong sing-box config, a wrong status text).

You may edit any file under `src-tauri/ttcm-core/src/`, `src-tauri/src/` and `src/` for
this task (this overrides "only the named files" in AGENTS.md). Do not add dependencies,
do not touch Cargo.toml/package.json, CI, scripts, icons, or `tauri.conf.json`.

## Phase 1 — ttcm-core (pure logic, main target, most tests go here)
Read each module fully, list risky spots, then test them. Specific things to check:

1. `links.rs` — share-link parsing (vless, vmess base64 JSON, trojan, ss SIP002 and
   legacy base64, hysteria2/hy2, tuic if present):
   - IPv6 hosts `[2001:db8::1]:443`, ports 0/65535/missing/non-numeric;
   - percent-encoded and Unicode names in `#fragment`, `+` vs `%20`, emoji flags;
   - params: `security=reality` with `pbk`/`sid`/`spx`/`fp`, `type=ws|grpc|httpupgrade|xhttp`
     with `path`/`host`/`serviceName`, `flow=xtls-rprx-vision`, `alpn=h2,http/1.1`,
     `sni` vs `peer`, `allowInsecure=1`/`insecure=1`, `headerType`;
   - case of scheme (`VLESS://`), trailing spaces/CR/LF, several links in one paste
     (newline, spaces, CRLF), duplicate params, empty values;
   - ss: base64 with/without padding, URL-safe base64, `plugin=` param, password with `:`;
   - vmess: `aid` as string vs number, `port` as string, `net`/`tls` empty strings;
   - the generated outbound JSON must be valid for sing-box 1.14 (field names, types).
2. `subscription.rs` — base64 body (std/url-safe, with/without padding, with line
   breaks), plain-text list, Clash/sing-box JSON if supported, BOM, empty lines,
   comments, one bad line among good ones (must not drop the whole list), headers like
   `subscription-userinfo` parsing (upload/download/total/expire, missing fields).
3. `routing.rs` — rules and service merge: duplicate domains/CIDRs across services,
   a user rule that conflicts with a service rule (which wins, is it intended), empty
   service lists, `domain_suffix` vs `domain` vs `domain_keyword`, CIDR validation
   (`/0`, `/32`, `/33`, IPv6 CIDRs, bare IP without mask), process-name rules,
   ordering stability (same input → identical JSON).
4. `config.rs` — sing-box config generation (largest module, 1300 lines). Check every
   combination of: TUN on/off, system proxy on/off, rule mode vs global vs direct,
   WireGuard endpoint present/absent and its split modes, Clash API port, DNS settings,
   `geo-in` inbound, IPv6 on/off. For each combination assert:
   - every outbound/endpoint tag referenced by a rule, `route.final`, DNS `detour`,
     `domain_resolver` or selector actually exists;
   - no duplicate tags across inbounds/outbounds/endpoints;
   - no duplicate listen ports;
   - rule order is the intended one (sniff/hijack-dns before routing, private IPs
     direct before proxy rules, WireGuard AllowedIPs routed to `wg`);
   - no fields removed in sing-box 1.12+ (legacy `dns` outbound, `geoip`/`geosite`
     in rules, inbound `sniff` fields, `block` outbound) — use `rule actions` style.
   Write a helper in the test module that walks a config and checks tag references, and
   run it over a matrix of settings.
5. `wireguard.rs` — `.conf` parse/export: comments (`#`, `;`), CRLF, keys with `=`
   padding, several `Address`/`AllowedIPs` lines vs comma lists, IPv6 addresses,
   `PersistentKeepalive`, `MTU`, `DNS` with search domains, `Endpoint` with IPv6 and
   hostnames, missing PublicKey/PrivateKey (must be an error, not a panic),
   export → parse round-trip equality, `0.0.0.0/0` + `::/0` detection of "full tunnel".
6. `pac.rs` — PAC text: domains with dots/wildcards, escaping of quotes/backslashes in
   generated JS, empty lists, CIDR → `isInNet` mask conversion (/0, /8, /32), IPv6.
7. `sysproxy.rs` — bypass list formatting (`<local>`, `;` vs `,`), duplicates, ports.
8. `gateway.rs` — Windows/Linux route parsing: localized adapter names, extra spaces,
   missing columns, metric overflow, IPv6 default routes mixed in.
9. `wgprobe.rs`, `pingall.rs` — already tested; only look for missed edge cases
   (classification of partial/fail, config built with `uplink=None`, zero profiles,
   profiles whose outbound lacks fields). Do not rewrite them.
10. `logfile.rs` — rotation/truncation boundaries, UTF-8 multibyte at a cut point.

Panics are bugs: any `unwrap()`/indexing on user input (links, subscriptions, .conf
files, settings JSON) that can panic — find it and prove it with a test.

## Phase 2 — app crate `src-tauri/src/` (read for bugs; test what is pure)
- `routing/mod.rs` sync/merge, `library.rs` parsing, `settings/mod.rs` defaults and
  migration of old saved JSON (missing new fields must get serde defaults, unknown
  fields must not fail loading), `profiles/mod.rs` (dedupe on import, id stability,
  delete of the active profile, rename), `subscription/mod.rs` (update replaces only
  that subscription's profiles, keeps the active one if it still exists).
- `core/mod.rs` (apply queue, start/stop/restart), `monitor/mod.rs`, `wireguard/mod.rs`,
  `sysproxy/*`, `pingall.rs`, `diag/mod.rs`: read for logic bugs — races, a lock held
  across a blocking call or sleep, an error swallowed so the UI shows success, state not
  restored after a failed start, a temp file or child process not cleaned up on an
  error path, a status that can stay stale. Report these; fix only if small and clearly
  correct, and add a test when the logic can be extracted into a pure function
  (extracting a pure helper into ttcm-core is fine).
- To run app-crate tests: `cd src-tauri && cargo test -p trytocatchme --lib` (slow to
  build; run it once at the end, not after each change). Tests must never start
  sing-box, touch the system proxy, the registry, routes or the network.

## Phase 3 — React UI `src/` (no test framework: read, report, fix small things)
Go through every page and component: App.tsx, ProfilesPage, RoutingPage, SettingsPage,
WireGuardPage, DiagnosticsPage, LogsPage, ListEditor, SysProxyLine, useConnection,
stores, `api/backend.ts`. Check:
- every `invoke` wrapper in backend.ts matches the Rust command name and argument
  names (Tauri converts camelCase args ↔ snake_case: verify each one against the
  `#[tauri::command]` signature) and the TS types match the Rust structs (field names,
  optional vs required, enum string values with serde `rename_all`);
- every command registered in `lib.rs` that the UI uses exists, and no UI call targets
  a removed command;
- buttons enabled when the action can't run; double clicks starting two operations;
  `busy` flags not reset in `finally`; missing `await`/`catch` (unhandled rejection
  leaves the UI stuck); errors shown as success;
- stale data after a change (list not reloaded after add/delete/import, status not
  refreshed after connect/disconnect), effects without cleanup (intervals, listeners
  from `listen()` not unlistened), state updates after unmount;
- texts that contradict what the code does; Russian text with typos or mixed languages.
Small, clearly-correct UI fixes are allowed; `npx tsc --noEmit -p .` must stay clean.

## How to work
- Bug found and the fix is small and obvious: fix it and add a test that fails without
  the fix. Otherwise do not fix: add the test marked `#[ignore = "BUG: <short>"]` and
  describe it in the report.
- Do not change behaviour that isn't a bug, no refactoring, no reformatting of
  untouched code, no renames of public items.
- Tests must be offline, fast and deterministic (no sleeps longer than ~100 ms, no
  real network, no temp files outside `std::env::temp_dir()`, cleaned up after).
- Never start the app, sing-box or anything networked. Never kill any process.

## Checks before you finish
- `cd src-tauri && cargo test -p ttcm-core` — all pass (ignored BUG tests allowed), no
  new warnings.
- `cd src-tauri && cargo test -p trytocatchme --lib` — all pass.
- `npx tsc --noEmit -p .` — no errors.

## Report (Russian), at the end
1. Bugs fixed: file:line, input → wrong output before, the test that covers it.
2. Bugs found but not fixed (ignored tests or UI/logic notes): file:line, scenario,
   why not fixed, suggested fix.
3. Suspicious places you weren't sure about.
4. Tests added: per file, count and what they cover.
5. Summary of the three check commands (pass/fail counts).
