import { useCallback, useState } from "react";
import { useFreshData } from "../hooks/useFreshData";
import { useAppStore } from "../store/appStore";
import { sysproxyReapply, sysproxyStatus, type SysProxyStatus } from "../api/backend";

/**
 * Sidebar line with the real OS system-proxy state while connected. Warns (with a
 * one-click fix) when another program — e.g. another VPN client — took the single
 * system-proxy slot over.
 */
export default function SysProxyLine({ connected, tun }: { connected: boolean; tun: boolean }) {
  const [st, setSt] = useState<SysProxyStatus | null>(null);
  const [busy, setBusy] = useState(false);

  const refresh = useCallback(async () => {
    if (!connected) { setSt(null); return; }
    await sysproxyStatus().then(setSt).catch(() => setSt(null));
  }, [connected]);

  useFreshData(async () => { await refresh(); }, ["sysproxy://overwritten", "vpn://state"], 4000);

  if (!connected) return null;
  if (!st) return <div className="muted" style={{ fontSize: 11 }}>Состояние системного прокси неизвестно</div>;

  if (st.applied_port === null) {
    return (
      <div className="muted" style={{ fontSize: 11, marginTop: 6 }}>
        {tun ? "Перехват TUN · системный прокси приложением не управляется" : "Системный прокси не применён — браузеры могут идти мимо VPN"}
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
      Системный прокси изменён или недоступен для проверки (сейчас: {st.current}). Перехват через него не подтверждён.
      <button
        className="btn"
        style={{ width: "100%", marginTop: 6, padding: "4px 8px", fontSize: 12 }}
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          try {
            await sysproxyReapply();
          } catch (e) {
            useAppStore.getState().setLastError(String(e));
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
