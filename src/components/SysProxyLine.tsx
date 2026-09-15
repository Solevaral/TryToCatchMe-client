import { useCallback, useEffect, useState } from "react";
import { listen } from "@tauri-apps/api/event";
import { sysproxyReapply, sysproxyStatus, type SysProxyStatus } from "../api/backend";

/**
 * Sidebar line with the real OS system-proxy state while connected. Warns (with a
 * one-click fix) when another program — e.g. another VPN client — took the single
 * system-proxy slot over.
 */
export default function SysProxyLine({ connected }: { connected: boolean }) {
  const [st, setSt] = useState<SysProxyStatus | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(() => {
    sysproxyStatus().then(setSt).catch(() => setSt(null));
  }, []);

  useEffect(() => {
    if (!connected) {
      setSt(null);
      return;
    }
    refresh();
    const t = setInterval(refresh, 3000);
    const un = listen("sysproxy://overwritten", refresh);
    return () => {
      clearInterval(t);
      un.then((f) => f()).catch(() => {});
    };
  }, [connected, refresh]);

  if (!connected || !st) return null;

  if (st.applied_port === null) {
    return (
      <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>
        Системный прокси не используется (режим TUN)
      </div>
    );
  }

  if (st.ours) {
    return (
      <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>
        Системный прокси: 127.0.0.1:{st.applied_port} · вкл
      </div>
    );
  }

  return (
    <div style={{ fontSize: 11, marginTop: 6, color: "var(--warn)" }}>
      Системный прокси перехвачен другой программой (сейчас: {st.current}) — браузеры идут мимо VPN.
      <button
        className="btn"
        style={{ width: "100%", marginTop: 6, padding: "4px 8px", fontSize: 12 }}
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          try {
            await sysproxyReapply();
          } catch {
            /* the error is logged by the backend */
          }
          setBusy(false);
          refresh();
        }}
      >
        Применить снова
      </button>
    </div>
  );
}
