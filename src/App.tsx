import { useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { useAppStore, type Page } from "./store/appStore";
import { useLogStore } from "./store/logStore";
import { coreStatus, relaunchAdmin, settingsPatch, wgRestart, wgStatus, type WgStatus } from "./api/backend";
import { useConnection } from "./hooks/useConnection";
import { useFreshData } from "./hooks/useFreshData";
import ErrorBanner from "./components/ErrorBanner";
import type { CoreStatus } from "./api/backend";
import SysProxyLine from "./components/SysProxyLine";
import ProfilesPage from "./pages/ProfilesPage";
import RoutingPage from "./pages/RoutingPage";
import WireGuardPage from "./pages/WireGuardPage";
import DiagnosticsPage from "./pages/DiagnosticsPage";
import LogsPage from "./pages/LogsPage";
import SettingsPage from "./pages/SettingsPage";

const NAV: { id: Page; label: string; icon: string }[] = [
  { id: "profiles", label: "Профили", icon: "🖧" },
  { id: "routing", label: "Маршрутизация", icon: "⇄" },
  { id: "wireguard", label: "WireGuard", icon: "⛓" },
  { id: "diagnostics", label: "Диагностика", icon: "🩺" },
  { id: "logs", label: "Логи", icon: "▤" },
  { id: "settings", label: "Настройки", icon: "⚙" },
];

const STATUS_LABEL: Record<string, string> = {
  disconnected: "Отключено",
  connecting: "Подключение…",
  connected: "Подключено",
  error: "Ошибка",
};

function connectionLabel(status: string, core: CoreStatus | null): string {
  if (status !== "connected") return STATUS_LABEL[status];
  if (core?.tun && core.tun_up !== true) return "Ядро запущено, TUN не подтверждён";
  if (core?.capture_up !== true) return "Ядро запущено, перехват не подтверждён";
  if (core.health === false) return "Подключено, но сервер не отвечает";
  return core.health === true ? "Связь проверена" : "Ядро запущено, проверяю связь…";
}

function fmtSpeed(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${bytesPerSec} B/s`;
  const kb = bytesPerSec / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB/s`;
  return `${(kb / 1024).toFixed(2)} MB/s`;
}

export default function App() {
  // Narrow selectors: a traffic tick (once a second) must not re-render the page.
  const page = useAppStore((s) => s.page);
  const setPage = useAppStore((s) => s.setPage);
  const status = useAppStore((s) => s.status);
  const setStatus = useAppStore((s) => s.setStatus);
  const setTraffic = useAppStore((s) => s.setTraffic);
  const lastError = useAppStore((s) => s.lastError);
  const setLastError = useAppStore((s) => s.setLastError);
  const warm = useAppStore((s) => s.warm);
  const setWarm = useAppStore((s) => s.setWarm);

  const [core, setCore] = useState<CoreStatus | null>(null);
  useFreshData(async () => {
    try {
      const s = await coreStatus();
      setCore(s);
      if (useAppStore.getState().status !== "connecting") {
        setStatus(s.vpn ? "connected" : useAppStore.getState().status === "error" ? "error" : "disconnected");
      }
      if (!s.running || Date.now() - useAppStore.getState().lastTrafficAt > 5000) setTraffic(0, 0);
      if (!s.running) setWarm("");
      if (s.health === true) setWarm("");
    } catch (e) { setCore(null); setStatus("error"); setTraffic(0, 0); setLastError(String(e)); }
  }, ["core://status", "vpn://state"], 4000);
  useEffect(() => {
    const handler = (event: PromiseRejectionEvent) => { setLastError(String(event.reason)); event.preventDefault(); };
    window.addEventListener("unhandledrejection", handler);
    return () => window.removeEventListener("unhandledrejection", handler);
  }, [setLastError]);

  // Global backend event listeners (tray actions, traffic, vpn state).
  useEffect(() => {
    const unlisteners: Array<Promise<() => void>> = [];

    unlisteners.push(
      listen<string>("vpn://state", (e) => {
        const s = e.payload;
        setStatus(
          s === "connected" ? "connected" : s === "error" ? "error" : s === "connecting" ? "connecting" : "disconnected"
        );
        if (s === "connected" || s === "idle") setLastError(null);
      })
    );
    // Tunnel warm-up right after connecting (the first request can take seconds).
    unlisteners.push(
      listen<string>("vpn://warm", (e) => {
        setWarm(e.payload === "start" ? "warming" : e.payload === "fail" ? "fail" : "");
      })
    );
    // Step-by-step progress of connecting (profile, capture mode, config, core start).
    unlisteners.push(
      listen<string>("app://log", (e) => {
        useLogStore.getState().add("app", e.payload);
      })
    );
    // TUN is on but the app isn't elevated: offer the two ways out instead of a bare error.
    unlisteners.push(
      listen<string>("app://needs-admin", async () => {
        const relaunch = window.confirm(
          [
            "Включён режим перехвата TUN, а приложение запущено без прав администратора.",
            "",
            "OK — перезапустить от имени администратора.",
            "Отмена — выключить TUN (перехват через системный прокси) и подключиться так.",
          ].join("\n")
        );
        if (relaunch) {
          await relaunchAdmin();
          return;
        }
        try {
          await settingsPatch({ capture_tun: false });
          useLogStore.getState().add("app", "TUN выключен — используется системный прокси. Нажмите «Подключить» ещё раз.");
        } catch (e) {
          setLastError(String(e));
        }
      })
    );
    unlisteners.push(
      listen("app://run-diagnostics", () => {
        useAppStore.getState().requestDiagnostics();
        setPage("diagnostics");
        window.dispatchEvent(new CustomEvent("ttcm:run-diagnostics"));
      })
    );
    // The core sends log lines in batches (one event per line floods the webview).
    unlisteners.push(
      listen<string>("clash://log", (e) => {
        try {
          const batch = JSON.parse(e.payload) as Array<{ type?: string; payload?: string }>;
          useLogStore.getState().addMany(
            (Array.isArray(batch) ? batch : [batch]).map((l) => ({
              level: l.type ?? "info",
              msg: l.payload ?? "",
            }))
          );
        } catch {
          useLogStore.getState().add("info", e.payload);
        }
      })
    );
    unlisteners.push(
      listen<string>("app://error", (e) => {
        useLogStore.getState().add("error", e.payload);
        setLastError(e.payload);
      })
    );
    unlisteners.push(
      listen<string>("clash://traffic", (e) => {
        try {
          const t = JSON.parse(e.payload) as { up: number; down: number };
          setTraffic(t.up ?? 0, t.down ?? 0);
        } catch {
          /* ignore malformed frame */
        }
      })
    );

    return () => {
      unlisteners.forEach((p) => p.then((un) => un()).catch(() => {}));
    };
  }, [setStatus, setPage, setTraffic, setLastError, setWarm]);

  const dotClass =
    status === "connected"
      ? core?.health === true && core.capture_up === true ? "dot ok" : "dot warn"
      : status === "error"
      ? "dot err"
      : status === "connecting"
      ? "dot warn"
      : "dot";

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          Try<span>ToCatch</span>Me
        </div>
        {NAV.map((n) => (
          <div
            key={n.id}
            className={`nav-item ${page === n.id ? "active" : ""}`}
            onClick={() => setPage(n.id)}
          >
            <span className="icon">{n.icon}</span>
            <span>{n.label}</span>
          </div>
        ))}
        <div className="sidebar-footer">
          <ConnControls />
          <div className="conn-pill">
            <span className={dotClass} />
            <span>{connectionLabel(status, core)}</span>
          </div>
          {status === "error" && lastError && (
            <div
              onClick={() => setPage("logs")}
              title="Открыть логи"
              style={{
                fontSize: 11,
                marginTop: 8,
                color: "var(--err)",
                cursor: "pointer",
                maxHeight: 120,
                overflow: "auto",
                wordBreak: "break-word",
              }}
            >
              {lastError}
            </div>
          )}
          {status === "connected" && warm === "warming" && (
            <div style={{ fontSize: 11, marginTop: 6, color: "var(--warn)" }}>Прогрев туннеля…</div>
          )}
          {status === "connected" && warm === "fail" && (
            <div
              style={{ fontSize: 11, marginTop: 6, color: "var(--err)", cursor: "pointer" }}
              onClick={() => setPage("diagnostics")}
              title="Открыть диагностику"
            >
              Трафик через сервер не проходит — проверьте профиль
            </div>
          )}
          {status === "connected" && core?.profile_name && (
            <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>
              {core.profile_name} · с {new Date(Date.now() - (core.uptime ?? 0) * 1000).toLocaleTimeString()}
              {" · "}{Math.floor((core.uptime ?? 0) / 60)} мин {(core.uptime ?? 0) % 60} с
            </div>
          )}
          {status === "connected" && core?.checked_ago != null && (
            <div className="muted" style={{ fontSize: 11 }}>Последняя проверка связи · {core.checked_ago} с назад</div>
          )}
          <SysProxyLine connected={status === "connected"} tun={core?.tun ?? false} />
          {status === "connected" && <Speed />}
        </div>
      </aside>

      <MainContent page={page} />
    </div>
  );
}

/** Own component so the once-a-second traffic tick re-renders only these two numbers. */
function Speed() {
  const up = useAppStore((s) => s.up);
  const down = useAppStore((s) => s.down);
  return (
    <div className="muted" style={{ fontSize: 11, marginTop: 8, display: "flex", gap: 10 }}>
      <span>↑ {fmtSpeed(up)}</span>
      <span>↓ {fmtSpeed(down)}</span>
    </div>
  );
}

function ConnControls() {
  const { connected, busy, toggle, restart } = useConnection();
  // The built-in WireGuard tunnel runs separately from the VPN: its own restart button,
  // shown only while it's up (or held off by a watchdog).
  const [wg, setWg] = useState<WgStatus | null>(null);
  const [wgBusy, setWgBusy] = useState(false);
  useEffect(() => {
    let alive = true;
    const tick = () => { if (document.hidden) return; return wgStatus(true).then((s) => alive && setWg(s)).catch(() => alive && setWg(null)); };
    tick();
    const t = setInterval(tick, 3000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);
  async function restartWg() {
    setWgBusy(true);
    try {
      await wgRestart();
      setWg(await wgStatus(true));
    } catch (e) {
      useAppStore.getState().setLastError(String(e));
    } finally {
      setWgBusy(false);
    }
  }
  return (
    <div style={{ display: "flex", flexDirection: "column", gap: 6, marginBottom: 10 }}>
      <button
        className={`btn ${connected ? "" : "primary"}`}
        style={{ width: "100%" }}
        disabled={busy}
        onClick={() => toggle().catch(() => {})}
      >
        {connected ? "Отключить" : busy ? "Подключение…" : "Подключить"}
      </button>
      <button
        className="btn"
        style={{ width: "100%", padding: "5px 10px" }}
        disabled={!connected || busy}
        onClick={() => restart().catch(() => {})}
        title="Перезапустить VPN (применить изменения)"
      >
        ↻ Перезапустить VPN
      </button>
      {(wg?.running || wg?.suspended) && (
        <button
          className="btn"
          style={{ width: "100%", padding: "5px 10px" }}
          disabled={wgBusy || busy}
          onClick={restartWg}
          title={wg?.suspended ? `Туннель приостановлен: ${wg.suspended}` : "Перезапустить туннель WireGuard (применить изменения)"}
        >
          {wgBusy ? "Перезапуск…" : "↻ Перезапустить WG"}
        </button>
      )}
      {wg?.running && wg.alive === false && (
        <div style={{ fontSize: 11, color: "var(--err)" }} title={wg.detail ?? undefined}>
          WireGuard: нет связи через туннель
        </div>
      )}
    </div>
  );
}

function MainContent({ page }: { page: Page }) {
  const error = useAppStore((s) => s.lastError);
  return (
    <main className="content">
      <ErrorBanner text={error} dismiss={() => useAppStore.getState().setLastError(null)} />
      {page === "profiles" && <ProfilesPage />}
      {page === "routing" && <RoutingPage />}
      {page === "wireguard" && <WireGuardPage />}
      {page === "diagnostics" && <DiagnosticsPage />}
      {page === "logs" && <LogsPage />}
      {page === "settings" && <SettingsPage />}
    </main>
  );
}
