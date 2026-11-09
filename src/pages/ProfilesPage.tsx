import { useState, useCallback, useRef } from "react";
import { readText, writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useFreshData } from "../hooks/useFreshData";
import { useLogStore } from "../store/logStore";
import { useConnection } from "../hooks/useConnection";
import {
  profilesList,
  profilesActive,
  profilesImport,
  profilesRemove,
  profilesSetActive,
  profilesPingAll,
  subscriptionsList,
  subscriptionUpdate,
  subscriptionRemove,
  type Profile,
  type Subscription,
  type ImportResult,
  type PingResult,
} from "../api/backend";

const PROTO_ICON: Record<string, string> = {
  vless: "🛡",
  vmess: "🔷",
  shadowsocks: "🧦",
  trojan: "🐴",
  hysteria2: "⚡",
  wireguard: "🔺",
};

// Keep the latest measurements across page switches, keyed by the measured outbound.
let pingCache: Record<string, PingResult> = {};
let pingFingerprints: Record<string, string> = {};
let pingTimestamp: number | null = null;

/** "tcp · reality · vision" — what the profile actually uses, at a glance. */
function transportLabel(p: Profile): string {
  const ob = p.outbound;
  const parts = [ob?.transport?.type ?? (p.protocol === "hysteria2" ? "quic" : "tcp")];
  if (ob?.tls?.reality?.enabled) parts.push("reality");
  else if (ob?.tls?.enabled) parts.push("tls");
  if (ob?.flow) parts.push(ob.flow.replace("xtls-rprx-", ""));
  return parts.join(" · ");
}

function formatBytes(n: number): string {
  const gb = n / 1024 ** 3;
  return gb >= 1 ? `${gb.toFixed(1)} ГБ` : `${(n / 1024 ** 2).toFixed(0)} МБ`;
}

/** "Использовано 107.2 ГБ из ∞ · до 30.04.2027 · обновлено 14:05" */
function subscriptionLabel(s: Subscription, count: number): string {
  const parts = [`серверов: ${count}`];
  if (s.info) {
    const used = formatBytes(s.info.upload + s.info.download);
    parts.push(`трафик ${used} из ${s.info.total ? formatBytes(s.info.total) : "∞"}`);
    if (s.info.expire) parts.push(`до ${new Date(s.info.expire * 1000).toLocaleDateString()}`);
  }
  if (s.updated_at) parts.push(`обновлено ${new Date(s.updated_at * 1000).toLocaleString()}`);
  return parts.join(" · ");
}

export default function ProfilesPage() {
  const { status, toggle, restart, connected, busy } = useConnection();
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [subscriptions, setSubscriptions] = useState<Subscription[]>([]);
  const selecting = useRef(false);
  const [updating, setUpdating] = useState<string | null>(null);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [notice, setNotice] = useState<string>("");
  const [pings, setPings] = useState<Record<string, PingResult>>(pingCache);
  const [pinging, setPinging] = useState(false);
  const [search, setSearch] = useState("");
  const [sortPing, setSortPing] = useState(false);
  const [pingAt, setPingAt] = useState<number | null>(pingTimestamp);

  async function pingAll() {
    setPinging(true);
    setNotice("");
    try {
      const measured = Object.fromEntries(profiles.map((p) => [p.id, JSON.stringify(p.outbound)]));
      const results = await profilesPingAll();
      const current = await profilesList();
      pingCache = Object.fromEntries(current
        .filter((p) => measured[p.id] === JSON.stringify(p.outbound) && results[p.id])
        .map((p) => [p.id, results[p.id]]));
      pingFingerprints = measured;
      pingTimestamp = Date.now();
      setPings(pingCache);
      setPingAt(pingTimestamp);
    } catch (e) {
      setNotice(String(e));
    } finally {
      setPinging(false);
    }
  }

  const refresh = useCallback(async () => {
    const [list, active, subs] = await Promise.all([
      profilesList(),
      profilesActive(),
      subscriptionsList(),
    ]);
    pingCache = Object.fromEntries(list
      .filter((p) => pingFingerprints[p.id] === JSON.stringify(p.outbound) && pingCache[p.id])
      .map((p) => [p.id, pingCache[p.id]]));
    setPings(pingCache);
    setProfiles(list);
    setActiveId(active);
    setSubscriptions(subs);
  }, []);

  /** Log and summarize an import / subscription update; reconnect if the active server changed. */
  async function report(res: ImportResult) {
    await refresh();
    const log = useLogStore.getState().add;
    res.added.forEach((p) => log("app", `Импортирован профиль «${p.name}» (${transportLabel(p)})`));
    res.errors.forEach((err) => log("warning", `Ссылка не импортирована — ${err}`));
    const parts: string[] = [];
    if (res.skipped_duplicates) parts.push(`Пропущено дубликатов: ${res.skipped_duplicates}`);
    if (res.added.length) parts.push(`Добавлено: ${res.added.length}`);
    if (res.errors.length)
      parts.push(`Не импортировано: ${res.errors.length} — первая причина: ${res.errors[0]} (все причины — во вкладке «Логи»)`);
    setNotice(parts.join(" · ") || "Ничего не найдено");
    // The active server's settings changed or it left the list — apply right away.
    if (res.active_changed && connected) await restart();
  }

  useFreshData(async () => { await refresh().catch((e) => setNotice(String(e))); }, ["profiles://changed"]);

  async function importText(text: string) {
    if (!text || !text.trim()) {
      setNotice("Буфер обмена пуст или не содержит ссылок");
      return;
    }
    try {
      if (/^\s*https?:\/\/\S+\s*$/.test(text)) setNotice("Скачиваю подписку…");
      await report(await profilesImport(text));
    } catch (e) {
      setNotice(String(e));
    }
  }

  async function updateSubscription(id: string) {
    setUpdating(id);
    setNotice("Обновляю подписку…");
    try {
      await report(await subscriptionUpdate(id));
    } catch (e) {
      setNotice(String(e));
    } finally {
      setUpdating(null);
    }
  }

  async function removeSubscription(s: Subscription) {
    if (!window.confirm(`Удалить подписку «${s.name}» вместе с её серверами?`)) return;
    try {
      const removesActive = profiles.some((p) => p.id === activeId && p.subscription === s.id);
      await subscriptionRemove(s.id);
      await refresh();
      if (removesActive && connected) await restart();
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
    const text = window.prompt(
      "Вставьте ссылку подключения (vless:// vmess:// ss:// trojan:// hysteria2://) или ссылку на подписку (https://…):",
    );
    if (text) await importText(text);
  }

  async function selectActive(id: string) {
    if (id === activeId || busy || selecting.current) return;
    selecting.current = true;
    try {
      await profilesSetActive(id);
      setActiveId(id);
      // Apply immediately — otherwise the tunnel keeps using the old server.
      if (connected) await restart();
    } catch (e) {
      setNotice(String(e));
    } finally { selecting.current = false; }
  }

  async function remove(id: string) {
    if (!window.confirm("Удалить профиль?")) return;
    try {
      await profilesRemove(id);
      await refresh();
      if (id === activeId && connected) await restart();
    } catch (e) {
      setNotice(String(e));
    }
  }

  const active = profiles.find((p) => p.id === activeId) || null;
  const filtered = profiles.filter((p) => `${p.name} ${p.protocol} ${p.server}`.toLowerCase().includes(search.toLowerCase()));
  const pingMs = (p: Profile) => {
    const result = pings[p.id];
    return result && result.status !== "fail" ? result.ms : Number.MAX_SAFE_INTEGER;
  };
  if (sortPing) filtered.sort((a, b) => pingMs(a) - pingMs(b));

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
            <div style={{ fontWeight: 600, marginBottom: 4 }}>Выбранный профиль</div>
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
        <button className="btn" onClick={pingAll} disabled={pinging || profiles.length === 0}>
          {pinging ? "Пинг…" : "📶 Пинг"}
        </button>
      </div>

      {pinging && (
        <div className="muted" style={{ marginBottom: 12, fontSize: 13 }}>
          Проверяю каждый сервер напрямую, мимо активного VPN (до ~15 с)…
        </div>
      )}

      {notice && (
        <div className="muted" style={{ marginBottom: 12, fontSize: 13 }}>
          {notice} <button className="btn" onClick={() => setNotice("")} aria-label="Закрыть сообщение">✕</button>
        </div>
      )}

      {subscriptions.length > 0 && (
        <div className="card" style={{ padding: 6, marginBottom: 12 }}>
          {subscriptions.map((s) => (
            <div
              key={s.id}
              style={{ display: "flex", alignItems: "center", gap: 12, padding: "10px 12px" }}
            >
              <span style={{ width: 20, textAlign: "center" }}>🔗</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ fontWeight: 550 }}>{s.name}</div>
                <div className="muted" style={{ fontSize: 12 }}>
                  {subscriptionLabel(s, profiles.filter((p) => p.subscription === s.id).length)}
                </div>
              </div>
              <button
                className="btn"
                style={{ padding: "4px 10px" }}
                disabled={updating !== null}
                onClick={() => updateSubscription(s.id)}
              >
                {updating === s.id ? "Обновление…" : "Обновить"}
              </button>
              <button
                className="btn"
                style={{ padding: "4px 10px" }}
                onClick={() => removeSubscription(s)}
              >
                Удалить
              </button>
            </div>
          ))}
        </div>
      )}

      {profiles.length > 8 && <input placeholder="Поиск профиля…" value={search} onChange={(e) => setSearch(e.target.value)} />}
      {profiles.length > 1 && <button className="btn" onClick={() => setSortPing((v) => !v)}>{sortPing ? "Исходный порядок" : "По последнему пингу"}</button>}
      {pingAt && <div className="muted">Последний пинг · {new Date(pingAt).toLocaleTimeString()}{pinging ? " · обновляю…" : ""}</div>}
      <div className="card" style={{ padding: profiles.length ? 6 : 18 }}>
        {profiles.length === 0 ? (
          <div className="placeholder">
            Список профилей пуст. Скопируйте ссылку подключения или подписки и нажмите «Вставить из буфера».
          </div>
        ) : (
          filtered.map((p) => {
            const result = pings[p.id];
            return (
              <div
                key={p.id}
                onClick={() => selectActive(p.id)}
                onDoubleClick={() => selectActive(p.id)}
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
                  style={{
                    fontSize: 12,
                    minWidth: 62,
                    textAlign: "right",
                    color: pinging || !result ? undefined
                      : result.status === "ok" ? "var(--ok)"
                      : result.status === "partial" ? "var(--warn)" : "var(--err)",
                  }}
                  title={pinging || !result ? undefined
                    : result.status === "partial" ? result.note
                    : result.status === "fail" ? result.reason : undefined}
                >
                  {!result && pinging
                    ? "…"
                    : result?.status === "ok"
                    ? `${result.ms} ms`
                    : result?.status === "partial"
                    ? `${result.ms} ms ⚠`
                    : result?.status === "fail"
                    ? "нет связи"
                    : ""}
                </span>
                {p.link && <button className="btn" onClick={(e) => { e.stopPropagation(); writeText(p.link!).catch((err) => setNotice(String(err))); }}>Копировать ссылку</button>}
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
            );
          })
        )}
      </div>
    </div>
  );
}
