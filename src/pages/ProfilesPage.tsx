import { useEffect, useState, useCallback } from "react";
import { readText } from "@tauri-apps/plugin-clipboard-manager";
import { useLogStore } from "../store/logStore";
import { useConnection } from "../hooks/useConnection";
import {
  profilesList,
  profilesActive,
  profilesImport,
  profilesRemove,
  profilesSetActive,
  profilePing,
  type Profile,
} from "../api/backend";

const PROTO_ICON: Record<string, string> = {
  vless: "🛡",
  vmess: "🔷",
  shadowsocks: "🧦",
  trojan: "🐴",
  wireguard: "🔺",
};

/** "tcp · reality · vision" — what the profile actually uses, at a glance. */
function transportLabel(p: Profile): string {
  const ob = p.outbound;
  const parts = [ob?.transport?.type ?? "tcp"];
  if (ob?.tls?.reality?.enabled) parts.push("reality");
  else if (ob?.tls?.enabled) parts.push("tls");
  if (ob?.flow) parts.push(ob.flow.replace("xtls-rprx-", ""));
  return parts.join(" · ");
}

export default function ProfilesPage() {
  const { status, toggle, restart, connected, busy } = useConnection();
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [notice, setNotice] = useState<string>("");
  const [pings, setPings] = useState<Record<string, number | null | "...">>({});

  async function pingOne(id: string) {
    setPings((p) => ({ ...p, [id]: "..." }));
    try {
      const ms = await profilePing(id);
      setPings((p) => ({ ...p, [id]: ms }));
    } catch {
      setPings((p) => ({ ...p, [id]: null }));
    }
  }

  const refresh = useCallback(async () => {
    const [list, active] = await Promise.all([profilesList(), profilesActive()]);
    setProfiles(list);
    setActiveId(active);
  }, []);

  useEffect(() => {
    refresh().catch((e) => setNotice(String(e)));
  }, [refresh]);

  async function importText(text: string) {
    if (!text || !text.trim()) {
      setNotice("Буфер обмена пуст или не содержит ссылок");
      return;
    }
    try {
      const res = await profilesImport(text);
      await refresh();
      const log = useLogStore.getState().add;
      res.added.forEach((p) => log("app", `Импортирован профиль «${p.name}» (${transportLabel(p)})`));
      res.errors.forEach((err) => log("warning", `Ссылка не импортирована — ${err}`));
      const parts: string[] = [];
      if (res.added.length) parts.push(`Добавлено: ${res.added.length}`);
      if (res.errors.length)
        parts.push(`Не импортировано: ${res.errors.length} — первая причина: ${res.errors[0]} (все причины — во вкладке «Логи»)`);
      setNotice(parts.join(" · ") || "Ничего не найдено");
    } catch (e) {
      setNotice(String(e));
    }
  }

  async function pasteFromClipboard() {
    try {
      const text = await readText();
      await importText(text ?? "");
    } catch (e) {
      setNotice("Не удалось прочитать буфер: " + String(e));
    }
  }

  async function addManual() {
    const text = window.prompt("Вставьте ссылку подключения (vless:// vmess:// ss:// trojan://):");
    if (text) await importText(text);
  }

  async function selectActive(id: string) {
    if (id === activeId) return;
    await profilesSetActive(id);
    setActiveId(id);
    // Apply immediately — otherwise the tunnel keeps using the old server.
    if (connected) await restart();
  }

  async function remove(id: string) {
    await profilesRemove(id);
    await refresh();
  }

  const active = profiles.find((p) => p.id === activeId) || null;

  return (
    <div>
      <h1 className="page-title">Профили</h1>

      <div className="card" style={{ marginBottom: 18 }}>
        <div
          style={{
            display: "flex",
            alignItems: "center",
            justifyContent: "space-between",
            gap: 16,
          }}
        >
          <div>
            <div style={{ fontWeight: 600, marginBottom: 4 }}>Активное подключение</div>
            <div className="muted">
              {active
                ? `${PROTO_ICON[active.protocol] ?? "•"} ${active.name} — ${active.server}:${active.port} (${transportLabel(active)})`
                : "Профиль не выбран — добавьте сервер или вставьте ссылку из буфера"}
            </div>
          </div>
          <button
            className={`btn ${connected ? "" : "primary"}`}
            onClick={() => toggle()}
            disabled={busy || (!active && !connected)}
            title={status === "error" ? "Причина ошибки — под статусом слева и во вкладке «Логи»" : undefined}
          >
            {connected ? "Отключить" : busy ? "Подключение…" : "Подключить"}
          </button>
        </div>
      </div>

      <div style={{ display: "flex", gap: 10, marginBottom: 12 }}>
        <button className="btn" onClick={addManual}>
          ＋ Добавить сервер
        </button>
        <button className="btn" onClick={pasteFromClipboard}>
          📋 Вставить ссылку из буфера
        </button>
      </div>

      {notice && (
        <div className="muted" style={{ marginBottom: 12, fontSize: 13 }}>
          {notice}
        </div>
      )}

      <div className="card" style={{ padding: profiles.length ? 6 : 18 }}>
        {profiles.length === 0 ? (
          <div className="placeholder">
            Список профилей пуст. Скопируйте ссылку подключения и нажмите «Вставить из буфера».
          </div>
        ) : (
          profiles.map((p) => (
            <div
              key={p.id}
              onClick={() => selectActive(p.id)}
              style={{
                display: "flex",
                alignItems: "center",
                gap: 12,
                padding: "10px 12px",
                borderRadius: 8,
                cursor: "pointer",
                background: p.id === activeId ? "var(--bg-2)" : "transparent",
                border:
                  p.id === activeId ? "1px solid var(--accent)" : "1px solid transparent",
              }}
            >
              <span style={{ width: 20, textAlign: "center" }}>
                {PROTO_ICON[p.protocol] ?? "•"}
              </span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 550 }}>{p.name}</div>
                <div className="muted" style={{ fontSize: 12 }}>
                  {p.protocol} · {p.server}:{p.port} · {transportLabel(p)}
                </div>
              </div>
              <span
                className="muted"
                style={{ fontSize: 12, minWidth: 62, textAlign: "right" }}
              >
                {pings[p.id] === "..."
                  ? "…"
                  : pings[p.id] === null
                  ? "недоступ."
                  : typeof pings[p.id] === "number"
                  ? `${pings[p.id]} ms`
                  : ""}
              </span>
              <button
                className="btn"
                style={{ padding: "4px 10px" }}
                onClick={(e) => {
                  e.stopPropagation();
                  pingOne(p.id);
                }}
              >
                Пинг
              </button>
              <button
                className="btn"
                style={{ padding: "4px 10px" }}
                onClick={(e) => {
                  e.stopPropagation();
                  remove(p.id);
                }}
              >
                Удалить
              </button>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
