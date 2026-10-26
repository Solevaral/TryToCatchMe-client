import { useCallback, useEffect, useRef, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import {
  settingsGet,
  settingsSet,
  wgCheck,
  wgExport,
  wgImport,
  wgList,
  wgMigrate,
  wgMigrationOffer,
  wgRemove,
  wgSetActive,
  wgStatus,
  wgUpdate,
  wgUpdateConf,
  type Settings,
  type WgMigration,
  type WgStatus,
  type WgStore,
  type WgTunnel,
} from "../api/backend";
import ListEditor, { fieldStyle } from "../components/ListEditor";
import { errorText, useConnection } from "../hooks/useConnection";

function bytes(n: number): string {
  if (n < 1024) return `${n} Б`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} КБ`;
  if (n < 1024 * 1024 * 1024) return `${(n / 1024 / 1024).toFixed(1)} МБ`;
  return `${(n / 1024 / 1024 / 1024).toFixed(2)} ГБ`;
}

const endpointOf = (t: WgTunnel) => t.peers.find((p) => p.endpoint)?.endpoint ?? "—";

export default function WireGuardPage() {
  const { connected, connect, restart, busy } = useConnection();
  const [store, setStore] = useState<WgStore | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);
  const [status, setStatus] = useState<WgStatus | null>(null);
  const [migration, setMigration] = useState<WgMigration | null>(null);
  const [msg, setMsg] = useState<{ ok: boolean; text: string } | null>(null);
  const [paste, setPaste] = useState("");
  const [showPaste, setShowPaste] = useState(false);
  const [editing, setEditing] = useState<WgTunnel | null>(null);
  const [exported, setExported] = useState<{ name: string; text: string } | null>(null);
  const [check, setCheck] = useState<string>("");
  const fileInput = useRef<HTMLInputElement>(null);

  const reload = useCallback(async () => {
    setStore(await wgList());
    setSettings(await settingsGet());
    setMigration(await wgMigrationOffer());
  }, []);

  useEffect(() => {
    reload().catch((e) => setMsg({ ok: false, text: errorText(e) }));
  }, [reload]);

  // Live status while the page is open.
  useEffect(() => {
    let alive = true;
    const tick = () => wgStatus().then((s) => alive && setStatus(s)).catch(() => {});
    tick();
    const t = setInterval(tick, 2000);
    return () => {
      alive = false;
      clearInterval(t);
    };
  }, []);

  async function run(f: () => Promise<unknown>, ok?: string) {
    try {
      await f();
      await reload();
      if (ok) setMsg({ ok: true, text: ok });
    } catch (e) {
      setMsg({ ok: false, text: errorText(e) });
    }
  }

  async function patch(p: Partial<Settings>) {
    if (!settings) return;
    const next = { ...settings, ...p };
    await run(() => settingsSet(next), "Сохранено — применится при следующем подключении (или «Перезапустить»)");
  }

  async function importText(text: string, name: string) {
    await run(async () => {
      const t = await wgImport(text, name);
      setPaste("");
      setShowPaste(false);
      setMsg({ ok: true, text: `Туннель «${t.name}» добавлен` });
    });
  }

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const f = e.target.files?.[0];
    e.target.value = "";
    if (f) await importText(await f.text(), f.name);
  }

  // Connect / disconnect: the tunnel lives inside the core, so a change restarts it
  // (or starts the client when it's off).
  async function activate(id: string | null) {
    await run(() => wgSetActive(id));
    if (connected) await restart();
    else if (id) await connect();
  }

  async function doExport(t: WgTunnel) {
    await run(async () => setExported({ name: t.name, text: await wgExport(t.id) }));
  }

  async function doCheck() {
    setCheck("проверяю…");
    try {
      setCheck(`связь есть, ${await wgCheck()} мс`);
    } catch (e) {
      setCheck(errorText(e));
    }
  }

  if (!store || !settings) {
    return (
      <div>
        <h1 className="page-title">WireGuard</h1>
        <div className="muted">Загрузка…</div>
      </div>
    );
  }

  const active = store.tunnels.find((t) => t.id === store.active) ?? null;
  const running = status?.running ? store.tunnels.find((t) => t.id === status.running) : null;

  return (
    <div>
      <h1 className="page-title">WireGuard</h1>

      {migration && (
        <div className="card" style={{ marginBottom: 18, borderColor: "var(--warn)" }}>
          <div style={{ fontWeight: 600, marginBottom: 6 }}>Перейти на встроенный туннель?</div>
          <div className="muted" style={{ fontSize: 13 }}>
            Сейчас прямой трафик идёт через внешний интерфейс «{migration.interface}»
            {migration.vpn_over_tunnel ? ", и VPN-трафик тоже" : ""}. Встроенный туннель
            заменяет эту настройку: прямой трафик — через туннель
            {migration.vpn_over_tunnel ? ", VPN поверх туннеля" : ""}
            {migration.provider_list.length > 0
              ? `, адреса из «Пропускать мимо TUN» — в список «Через провайдера»`
              : ""}
            . Перед подключением выключите внешний WireGuard «{migration.interface}»: один и
            тот же ключ не может работать в двух местах одновременно.
          </div>
          <button className="btn" style={{ marginTop: 10 }} onClick={() => run(wgMigrate, "Перенесено. Выберите туннель и подключите его.")}>
            Перейти
          </button>
        </div>
      )}

      <div className="card" style={{ marginBottom: 18 }}>
        <div style={{ fontWeight: 600, marginBottom: 10 }}>Туннели</div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap", marginBottom: 10 }}>
          <button className="btn" onClick={() => fileInput.current?.click()}>
            Импорт .conf
          </button>
          <input ref={fileInput} type="file" accept=".conf,text/plain" onChange={onFile} style={{ display: "none" }} />
          <button className="btn" onClick={() => setShowPaste(!showPaste)}>
            Вставить текст
          </button>
        </div>
        {showPaste && (
          <div style={{ marginBottom: 12 }}>
            <textarea
              value={paste}
              onChange={(e) => setPaste(e.target.value)}
              placeholder={"[Interface]\nPrivateKey = …\nAddress = …\n\n[Peer]\nPublicKey = …\nEndpoint = …"}
              rows={8}
              style={{ ...fieldStyle, width: "100%", fontFamily: "monospace", fontSize: 12 }}
            />
            <button className="btn" style={{ marginTop: 6 }} disabled={!paste.trim()} onClick={() => importText(paste, "")}>
              Добавить
            </button>
          </div>
        )}
        {store.tunnels.length === 0 && <div className="muted">Туннелей нет — импортируйте .conf из своего WireGuard.</div>}
        <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
          {store.tunnels.map((t) => {
            const isActive = t.id === store.active;
            return (
              <div
                key={t.id}
                style={{
                  ...fieldStyle,
                  display: "flex",
                  gap: 10,
                  alignItems: "center",
                  flexWrap: "wrap",
                  borderColor: isActive ? "var(--ok)" : "var(--border)",
                }}
              >
                <div style={{ flex: 1, minWidth: 180 }}>
                  <div style={{ fontWeight: 600 }}>
                    {t.name}
                    {isActive && <span style={{ color: "var(--ok)", fontWeight: 400, fontSize: 12 }}> · активный</span>}
                  </div>
                  <div className="muted" style={{ fontSize: 12 }}>
                    {endpointOf(t)} · {t.interface.addresses.join(", ")}
                  </div>
                </div>
                {isActive ? (
                  <button className="btn" disabled={busy} onClick={() => activate(null)}>
                    Отключить
                  </button>
                ) : (
                  <button className="btn" disabled={busy} onClick={() => activate(t.id)}>
                    Подключить
                  </button>
                )}
                <button className="btn" onClick={() => setEditing(structuredClone(t))}>
                  Изменить
                </button>
                <button className="btn" onClick={() => doExport(t)}>
                  Экспорт
                </button>
                <button
                  className="btn"
                  onClick={() => confirm(`Удалить туннель «${t.name}»?`) && run(() => wgRemove(t.id))}
                >
                  Удалить
                </button>
              </div>
            );
          })}
        </div>
        {msg && (
          <div style={{ fontSize: 12, marginTop: 8, color: msg.ok ? "var(--ok)" : "var(--err)", whiteSpace: "pre-wrap" }}>
            {msg.text}
          </div>
        )}
        <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>
          Туннель работает внутри ядра клиента (без программы WireGuard), поэтому подключение
          туннеля запускает или перезапускает клиент. Если этот же туннель открыт в программе
          WireGuard — выключите его там.
        </div>
      </div>

      {editing && <TunnelEditor tunnel={editing} onClose={() => setEditing(null)} onSaved={reload} />}

      {exported && (
        <div className="card" style={{ marginBottom: 18 }}>
          <div style={{ fontWeight: 600, marginBottom: 6 }}>Экспорт «{exported.name}»</div>
          <textarea
            readOnly
            value={exported.text}
            rows={10}
            style={{ ...fieldStyle, width: "100%", fontFamily: "monospace", fontSize: 12 }}
          />
          <div style={{ display: "flex", gap: 8, marginTop: 6 }}>
            <button className="btn" onClick={() => writeText(exported.text).then(() => setMsg({ ok: true, text: "Скопировано" }))}>
              Копировать
            </button>
            <button className="btn" onClick={() => setExported(null)}>
              Закрыть
            </button>
          </div>
          <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
            Содержит приватный ключ — не публикуйте.
          </div>
        </div>
      )}

      <div className="card" style={{ marginBottom: 18 }}>
        <div style={{ fontWeight: 600, marginBottom: 10 }}>Статус</div>
        {running ? (
          <>
            <div>
              <span style={{ color: "var(--ok)" }}>● Подключён</span> — «{running.name}», сервер {status?.endpoint ?? "—"}
            </div>
            <div className="muted" style={{ fontSize: 13, marginTop: 4 }}>
              Сейчас через туннель: {status?.connections ?? 0} соединений, ↑ {bytes(status?.upload ?? 0)} ↓{" "}
              {bytes(status?.download ?? 0)}
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginTop: 8 }}>
              <button className="btn" onClick={doCheck}>
                Проверить связь
              </button>
              <span className="muted" style={{ fontSize: 13 }}>{check}</span>
            </div>
          </>
        ) : active ? (
          <div className="muted">
            «{active.name}» выбран, но не подключён{connected ? " — нажмите «Перезапустить», чтобы применить" : " — подключите клиент"}.
          </div>
        ) : (
          <div className="muted">Встроенный WireGuard выключен.</div>
        )}
        <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>
          Ядро не сообщает время последнего рукопожатия — «Проверить связь» делает запрос через
          туннель: ответ означает, что туннель работает.
        </div>
      </div>

      <div className="card" style={{ marginBottom: 18 }}>
        <div style={{ fontWeight: 600, marginBottom: 10 }}>Использование туннеля</div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          <button
            className={`btn ${settings.wg_direct_via_tunnel ? "primary" : ""}`}
            onClick={() => patch({ wg_direct_via_tunnel: true })}
          >
            Прямой трафик — через туннель
          </button>
          <button
            className={`btn ${!settings.wg_direct_via_tunnel ? "primary" : ""}`}
            onClick={() => patch({ wg_direct_via_tunnel: false })}
          >
            Прямой трафик — через провайдера
          </button>
        </div>
        <div className="muted" style={{ fontSize: 12, margin: "6px 0 12px" }}>
          «Прямой» — всё, что не идёт через VPN: сайты не из сервисов, российские сайты, игры.
          Локальная сеть всегда остаётся локальной. Сервисы «через VPN» работают как раньше.
        </div>
        <label style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
          <input
            type="checkbox"
            checked={settings.wg_vpn_over_tunnel}
            onChange={(e) => patch({ wg_vpn_over_tunnel: e.target.checked })}
          />
          <span>
            VPN поверх туннеля
            <div className="muted" style={{ fontSize: 12 }}>
              Подключение к VPN-серверу идёт через туннель. Помогает, если ваш провайдер блокирует
              сам VPN-сервер. Медленнее (лишний участок).
            </div>
          </span>
        </label>
      </div>

      <div className="card" style={{ marginBottom: 18 }}>
        <div style={{ fontWeight: 600, marginBottom: 6 }}>Через провайдера</div>
        <div className="muted" style={{ fontSize: 12, marginBottom: 8 }}>
          Эти сайты идут напрямую через провайдера — мимо туннеля и мимо VPN (например, игровые
          серверы, которым важен пинг). Домен включает свои поддомены. Работает и без туннеля.
        </div>
        <ListEditor
          label="Сайты и адреса"
          placeholder="warframe.com, 1.2.3.4 или 10.0.0.0/8"
          items={settings.provider_list}
          onChange={(v) => patch({ provider_list: v })}
        />
      </div>
    </div>
  );
}

/** Edit a tunnel: the common fields as a form, everything as `.conf` text. */
function TunnelEditor(props: { tunnel: WgTunnel; onClose: () => void; onSaved: () => Promise<void> }) {
  const [t, setT] = useState<WgTunnel>(props.tunnel);
  const [asText, setAsText] = useState(false);
  const [text, setText] = useState("");
  const [err, setErr] = useState("");
  const peer = t.peers[0];

  useEffect(() => {
    if (asText) wgExport(t.id).then(setText).catch((e) => setErr(errorText(e)));
  }, [asText, t.id]);

  async function save() {
    setErr("");
    try {
      if (asText) {
        await wgUpdateConf(t.id, text);
        // The name is edited in the form, keep it in sync.
        if (t.name !== props.tunnel.name) {
          const fresh = await wgList();
          const cur = fresh.tunnels.find((x) => x.id === t.id);
          if (cur) await wgUpdate({ ...cur, name: t.name });
        }
      } else {
        await wgUpdate(t);
      }
      await props.onSaved();
      props.onClose();
    } catch (e) {
      setErr(errorText(e));
    }
  }

  const row = (label: string, el: React.ReactNode) => (
    <label style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 6 }}>
      <span style={{ width: 150, fontSize: 13 }}>{label}</span>
      {el}
    </label>
  );
  const input = (value: string, onChange: (v: string) => void, placeholder = "") => (
    <input
      value={value}
      placeholder={placeholder}
      onChange={(e) => onChange(e.target.value)}
      style={{ ...fieldStyle, flex: 1, minWidth: 0 }}
    />
  );
  const list = (v: string) => v.split(",").map((s) => s.trim()).filter(Boolean);
  const num = (v: string) => (v.trim() === "" ? null : Number(v.replace(/\D/g, "")));
  const setPeer = (p: Partial<typeof peer>) => setT({ ...t, peers: [{ ...peer, ...p }, ...t.peers.slice(1)] });

  return (
    <div className="card" style={{ marginBottom: 18 }}>
      <div style={{ fontWeight: 600, marginBottom: 10 }}>Туннель «{props.tunnel.name}»</div>
      {row("Имя", input(t.name, (v) => setT({ ...t, name: v })))}
      <label style={{ display: "flex", gap: 8, alignItems: "center", margin: "6px 0 10px", fontSize: 13 }}>
        <input type="checkbox" checked={asText} onChange={(e) => setAsText(e.target.checked)} />
        Редактировать как текст .conf (все поля, включая ключи)
      </label>
      {asText ? (
        <textarea
          value={text}
          onChange={(e) => setText(e.target.value)}
          rows={14}
          style={{ ...fieldStyle, width: "100%", fontFamily: "monospace", fontSize: 12 }}
        />
      ) : (
        <>
          {row("Endpoint", input(peer?.endpoint ?? "", (v) => setPeer({ endpoint: v.trim() || null }), "адрес:порт"))}
          {row("Address", input(t.interface.addresses.join(", "), (v) => setT({ ...t, interface: { ...t.interface, addresses: list(v) } })))}
          {row("DNS", input(t.interface.dns.join(", "), (v) => setT({ ...t, interface: { ...t.interface, dns: list(v) } }), "например 10.6.0.1"))}
          {row("MTU", input(t.interface.mtu?.toString() ?? "", (v) => setT({ ...t, interface: { ...t.interface, mtu: num(v) } }), "по умолчанию"))}
          {row("AllowedIPs", input(peer?.allowed_ips.join(", ") ?? "", (v) => setPeer({ allowed_ips: list(v) })))}
          {row(
            "PersistentKeepalive",
            input(peer?.persistent_keepalive?.toString() ?? "", (v) => setPeer({ persistent_keepalive: num(v) }), "выкл."),
          )}
          {t.peers.length > 1 && (
            <div className="muted" style={{ fontSize: 12 }}>
              Пиров: {t.peers.length}. В форме — первый; остальные — в режиме «как текст».
            </div>
          )}
        </>
      )}
      {err && <div style={{ fontSize: 12, marginTop: 6, color: "var(--err)", whiteSpace: "pre-wrap" }}>{err}</div>}
      <div style={{ display: "flex", gap: 8, marginTop: 10 }}>
        <button className="btn primary" onClick={save}>
          Сохранить
        </button>
        <button className="btn" onClick={props.onClose}>
          Отмена
        </button>
      </div>
      <div className="muted" style={{ fontSize: 12, marginTop: 6 }}>
        Применится при следующем подключении (или «Перезапустить»).
      </div>
    </div>
  );
}
