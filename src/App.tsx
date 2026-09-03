import { useEffect } from "react";
import { listen } from "@tauri-apps/api/event";
import { useAppStore, type Page } from "./store/appStore";
import { useLogStore } from "./store/logStore";
import { coreStatus, traySetState } from "./api/backend";
import { useConnection } from "./hooks/useConnection";
import ProfilesPage from "./pages/ProfilesPage";
import RoutingPage from "./pages/RoutingPage";
import DiagnosticsPage from "./pages/DiagnosticsPage";
import LogsPage from "./pages/LogsPage";
import SettingsPage from "./pages/SettingsPage";

const NAV: { id: Page; label: string; icon: string }[] = [
  { id: "profiles", label: "Профили", icon: "🖧" },
  { id: "routing", label: "Маршрутизация", icon: "⇄" },
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

function fmtSpeed(bytesPerSec: number): string {
  if (bytesPerSec < 1024) return `${bytesPerSec} B/s`;
  const kb = bytesPerSec / 1024;
  if (kb < 1024) return `${kb.toFixed(1)} KB/s`;
  return `${(kb / 1024).toFixed(2)} MB/s`;
}

export default function App() {
  const { page, setPage, status, setStatus, up, down, setTraffic } = useAppStore();

  // Sync status from the core at startup (window may have been reopened from tray).
  useEffect(() => {
    coreStatus()
      .then((s) => {
        if (s.running) {
          setStatus("connected");
          traySetState("connected").catch(() => {});
        }
      })
      .catch(() => {});
  }, [setStatus]);

  // Global backend event listeners (tray actions, traffic, vpn state).
  useEffect(() => {
    const unlisteners: Array<Promise<() => void>> = [];

    unlisteners.push(
      listen<string>("vpn://state", (e) => {
        const s = e.payload;
        setStatus(s === "connected" ? "connected" : s === "error" ? "error" : "disconnected");
      })
    );
    unlisteners.push(
      listen("app://run-diagnostics", () => {
        setPage("diagnostics");
        window.dispatchEvent(new CustomEvent("ttcm:run-diagnostics"));
      })
    );
    unlisteners.push(
      listen<string>("clash://log", (e) => {
        try {
          const l = JSON.parse(e.payload) as { type?: string; payload?: string };
          useLogStore.getState().add(l.type ?? "info", l.payload ?? e.payload);
        } catch {
          useLogStore.getState().add("info", e.payload);
        }
      })
    );
    unlisteners.push(
      listen<string>("app://error", (e) => {
        useLogStore.getState().add("error", e.payload);
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
  }, [setStatus, setPage, setTraffic]);

  const dotClass =
    status === "connected"
      ? "dot ok"
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
            <span>{STATUS_LABEL[status]}</span>
          </div>
          {status === "connected" && (
            <div
              className="muted"
              style={{ fontSize: 11, marginTop: 8, display: "flex", gap: 10 }}
            >
              <span>↑ {fmtSpeed(up)}</span>
              <span>↓ {fmtSpeed(down)}</span>
            </div>
          )}
        </div>
      </aside>

      <MainContent page={page} />
    </div>
  );
}

function ConnControls() {
  const { connected, busy, toggle, restart } = useConnection();
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
        title="Перезапустить туннель (применить изменения)"
      >
        ↻ Перезапустить
      </button>
    </div>
  );
}

function MainContent({ page }: { page: Page }) {
  return (
    <main className="content">
      {page === "profiles" && <ProfilesPage />}
      {page === "routing" && <RoutingPage />}
      {page === "diagnostics" && <DiagnosticsPage />}
      {page === "logs" && <LogsPage />}
      {page === "settings" && <SettingsPage />}
    </main>
  );
}
