import { useEffect, useState } from "react";
import {
  routingGet,
  routingSetConfig,
  serviceUpsert,
  serviceRemove,
  servicesReset,
  servicesLibrary,
  coreRestart,
  geoRefresh,
  settingsGet,
  settingsSet,
  isAdmin,
  relaunchAdmin,
  type RoutingConfig,
  type Service,
  type RuleAction,
  type Settings,
} from "../api/backend";
import { useAppStore } from "../store/appStore";

const ACTIONS: RuleAction[] = ["proxy", "direct", "block"];
const ACTION_LABEL: Record<RuleAction, string> = {
  proxy: "через VPN",
  direct: "напрямую",
  block: "блок",
};

export default function RoutingPage() {
  const status = useAppStore((s) => s.status);
  const [config, setConfig] = useState<RoutingConfig | null>(null);
  const [catalog, setCatalog] = useState<Service[]>([]);
  const [editing, setEditing] = useState<Service | null>(null);
  const [showLibrary, setShowLibrary] = useState(false);
  const [reloadState, setReloadState] = useState<"" | "..." | "ok" | "off">("");
  const [geoState, setGeoState] = useState<"" | "..." | "ok">("");
  const [settings, setSettings] = useState<Settings | null>(null);

  async function reload() {
    const snap = await routingGet();
    setConfig(snap.config);
    setCatalog(snap.catalog);
  }
  useEffect(() => {
    reload().catch(console.error);
    settingsGet().then(setSettings).catch(() => setSettings(null));
  }, []);

  async function setCapture(tun: boolean) {
    if (!settings) return;
    if (tun && !settings.capture_tun) {
      const admin = await isAdmin();
      if (!admin) {
        const ok = window.confirm(
          "Режим TUN перехватывает ВЕСЬ трафик системы (включая приложения, которые игнорируют прокси — например Claude), но требует прав администратора.\n\nПерезапустить приложение от имени администратора?"
        );
        if (ok) {
          await settingsSet({ ...settings, capture_tun: true }); // remember the choice
          await relaunchAdmin(); // app exits and relaunches elevated
        }
        return;
      }
    }
    const next = { ...settings, capture_tun: tun };
    setSettings(next);
    await settingsSet(next);
    if (status === "connected") await reloadProfile();
  }

  async function persist(next: RoutingConfig) {
    setConfig(next);
    await routingSetConfig(next);
  }

  // Apply routing/service changes to the running tunnel without leaving the page.
  async function reloadProfile() {
    if (status !== "connected") {
      setReloadState("off");
      setTimeout(() => setReloadState(""), 1800);
      return;
    }
    setReloadState("...");
    try {
      await coreRestart();
      setReloadState("ok");
    } catch {
      setReloadState("");
    }
    setTimeout(() => setReloadState(""), 1800);
  }

  if (!config) return <div className="placeholder">Загрузка…</div>;

  const setMode = (mode: string) => persist({ ...config, mode });
  const serviceEnabled = (id: string) => config.services.some((s) => s.id === id);
  const serviceAction = (id: string): RuleAction =>
    config.services.find((s) => s.id === id)?.action ?? "proxy";

  function toggleService(id: string) {
    const exists = serviceEnabled(id);
    const services = exists
      ? config!.services.filter((s) => s.id !== id)
      : [...config!.services, { id, action: "proxy" as RuleAction }];
    persist({ ...config!, services });
  }
  function setServiceAction(id: string, action: RuleAction) {
    const services = config!.services.map((s) => (s.id === id ? { ...s, action } : s));
    persist({ ...config!, services });
  }

  async function saveService(svc: Service) {
    await serviceUpsert(svc);
    setEditing(null);
    await reload();
  }
  async function addFromLibrary(svc: Service) {
    await serviceUpsert(svc);
    await reload();
  }
  async function removeFromCatalog(id: string) {
    await serviceRemove(id);
    await reload();
  }

  const reloadLabel =
    reloadState === "..."
      ? "Применяю…"
      : reloadState === "ok"
      ? "Применено ✓"
      : reloadState === "off"
      ? "VPN выключен"
      : "↻ Перезагрузить профиль";

  return (
    <div>
      <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between" }}>
        <h1 className="page-title">Маршрутизация</h1>
        <button
          className="btn"
          onClick={reloadProfile}
          disabled={reloadState === "..."}
          title="Применить изменения сервисов/правил к активному подключению"
        >
          {reloadLabel}
        </button>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ fontWeight: 600, marginBottom: 10 }}>Режим</div>
        <div style={{ display: "flex", gap: 10 }}>
          {[
            { v: "global", l: "Global — всё через VPN" },
            { v: "direct", l: "Direct — всё напрямую" },
            { v: "rule", l: "Rule — по правилам" },
          ].map((m) => (
            <button
              key={m.v}
              className={`btn ${config.mode === m.v ? "primary" : ""}`}
              onClick={() => setMode(m.v)}
            >
              {m.l}
            </button>
          ))}
        </div>
        <div className="muted" style={{ fontSize: 11, marginTop: 8 }}>
          Что реально попадёт в туннель, зависит от «Перехвата трафика» ниже.
        </div>
      </div>

      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ fontWeight: 600, marginBottom: 10 }}>Перехват трафика</div>
        <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
          <button
            className={`btn ${settings && !settings.capture_tun ? "primary" : ""}`}
            onClick={() => setCapture(false)}
          >
            Системный прокси
          </button>
          <button
            className={`btn ${settings && settings.capture_tun ? "primary" : ""}`}
            onClick={() => setCapture(true)}
          >
            TUN — весь трафик
          </button>
        </div>
        <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>
          <b>Системный прокси</b> — через VPN идут только приложения, читающие системный
          прокси (браузеры и т.п.). <b>TUN</b> — виртуальная сетевая карта ловит ВЕСЬ трафик,
          включая упрямые приложения (Claude, Telegram, игры). TUN требует прав администратора
          (запрос появится при включении).
        </div>
      </div>

      {config.mode === "rule" && (
        <>
          {/* Services */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <div style={{ fontWeight: 600 }}>Сервисы</div>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn" style={{ padding: "4px 10px" }} onClick={() => setShowLibrary(true)}>
                  📚 Из библиотеки
                </button>
                <button className="btn" style={{ padding: "4px 10px" }} onClick={() => setEditing({ id: "", name: "", icon: "🔧", domains: [], ip_cidrs: [] })}>
                  ＋ Свой сервис
                </button>
                <button className="btn" style={{ padding: "4px 10px" }} onClick={async () => { await servicesReset(); await reload(); }}>
                  Сброс
                </button>
              </div>
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fill, minmax(230px, 1fr))", gap: 10 }}>
              {catalog.map((svc) => {
                const on = serviceEnabled(svc.id);
                return (
                  <div
                    key={svc.id}
                    style={{
                      border: on ? "1px solid var(--accent)" : "1px solid var(--border)",
                      background: on ? "var(--bg-2)" : "var(--bg-1)",
                      borderRadius: 10,
                      padding: 10,
                    }}
                  >
                    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
                      <span style={{ fontSize: 18 }}>{svc.icon}</span>
                      <span style={{ fontWeight: 550, flex: 1 }}>{svc.name}</span>
                      <input type="checkbox" checked={on} onChange={() => toggleService(svc.id)} />
                    </div>
                    <div className="muted" style={{ fontSize: 11, margin: "6px 0" }}>
                      {svc.domains.length} доменов · {svc.ip_cidrs.length} IP
                    </div>
                    <div style={{ display: "flex", gap: 6 }}>
                      <select
                        value={serviceAction(svc.id)}
                        disabled={!on}
                        onChange={(e) => setServiceAction(svc.id, e.target.value as RuleAction)}
                        style={selStyle}
                      >
                        {ACTIONS.map((a) => (
                          <option key={a} value={a}>{ACTION_LABEL[a]}</option>
                        ))}
                      </select>
                      <button className="btn" style={{ padding: "3px 8px" }} onClick={() => setEditing(svc)}>
                        Изм.
                      </button>
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Region / geo */}
          <div className="card" style={{ marginBottom: 16 }}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 10 }}>
              <div style={{ fontWeight: 600 }}>Российские сайты</div>
              <button
                className="btn"
                style={{ padding: "4px 10px" }}
                disabled={!config.region || geoState === "..."}
                onClick={async () => {
                  setGeoState("...");
                  try { await geoRefresh(); setGeoState("ok"); } catch { setGeoState(""); }
                  setTimeout(() => setGeoState(""), 1800);
                }}
                title="Сбросить кэш и перекачать списки geosite/geoip"
              >
                {geoState === "..." ? "Обновляю…" : geoState === "ok" ? "Обновлено ✓" : "↻ Обновить списки"}
              </button>
            </div>
            <label style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
              <input
                type="checkbox"
                checked={config.region === "ru"}
                onChange={(e) =>
                  persist({ ...config, region: e.target.checked ? "ru" : null, geo_action: "direct" })
                }
              />
              <span>
                Российские сайты — мимо VPN (напрямую)
                <div className="muted" style={{ fontSize: 12 }}>
                  Банки, госуслуги и прочие RU-ресурсы идут в обход туннеля (списки
                  geosite-category-ru / geoip-ru). Остальной трафик — по правилу ниже.
                  Списки скачиваются через VPN и кэшируются (обновляются раз в сутки).
                </div>
              </span>
            </label>
          </div>

          {/* Unmatched */}
          <div className="card">
            <div style={{ display: "flex", gap: 10, alignItems: "center" }}>
              <span style={{ fontWeight: 600 }}>Остальной трафик:</span>
              <select value={config.final_action} onChange={(e) => persist({ ...config, final_action: e.target.value as RuleAction })} style={selStyle}>
                {ACTIONS.filter((a) => a !== "block").map((a) => (
                  <option key={a} value={a}>{ACTION_LABEL[a]}</option>
                ))}
              </select>
            </div>
          </div>
        </>
      )}

      {editing && (
        <ServiceEditor
          initial={editing}
          onCancel={() => setEditing(null)}
          onSave={saveService}
          onDelete={editing.id ? async () => { await serviceRemove(editing.id); setEditing(null); await reload(); } : undefined}
        />
      )}

      {showLibrary && (
        <LibraryModal
          catalog={catalog}
          onAdd={addFromLibrary}
          onRemove={removeFromCatalog}
          onClose={() => setShowLibrary(false)}
        />
      )}
    </div>
  );
}

const selStyle: React.CSSProperties = {
  background: "var(--bg-2)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  color: "var(--text-0)",
  padding: "6px 8px",
};
const inputStyle: React.CSSProperties = { ...selStyle };

function LibraryModal({
  catalog,
  onAdd,
  onRemove,
  onClose,
}: {
  catalog: Service[];
  onAdd: (s: Service) => void;
  onRemove: (id: string) => void;
  onClose: () => void;
}) {
  const [lib, setLib] = useState<Service[]>([]);
  const [q, setQ] = useState("");

  useEffect(() => {
    servicesLibrary().then(setLib).catch(console.error);
  }, []);

  const catalogIds = new Set(catalog.map((s) => s.id));
  const needle = q.trim().toLowerCase();
  const match = (s: Service) =>
    !needle ||
    s.name.toLowerCase().includes(needle) ||
    s.domains.some((d) => d.toLowerCase().includes(needle));

  // Added services (removable) go on top; the rest of the library below.
  const added = catalog.filter(match);
  const addable = lib.filter((s) => !catalogIds.has(s.id) && match(s));

  const row = (s: Service, isAdded: boolean) => (
    <div
      key={(isAdded ? "a-" : "l-") + s.id}
      style={{
        display: "flex",
        alignItems: "center",
        gap: 10,
        padding: "8px 10px",
        border: "1px solid var(--border)",
        borderRadius: 8,
      }}
    >
      <span style={{ fontSize: 18 }}>{s.icon}</span>
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 550 }}>{s.name}</div>
        <div className="muted" style={{ fontSize: 11 }}>
          {s.domains.slice(0, 3).join(", ")}
          {s.domains.length > 3 ? "…" : ""}
        </div>
      </div>
      {isAdded ? (
        <button
          className="btn"
          style={{ padding: "4px 12px", color: "var(--err)", borderColor: "var(--err)" }}
          onClick={() => onRemove(s.id)}
        >
          Убрать
        </button>
      ) : (
        <button className="btn primary" style={{ padding: "4px 12px" }} onClick={() => onAdd(s)}>
          Добавить
        </button>
      )}
    </div>
  );

  return (
    <div style={overlay}>
      <div className="card" style={{ width: 560, maxHeight: "86vh", display: "flex", flexDirection: "column" }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
          <div style={{ fontWeight: 600 }}>Библиотека сервисов</div>
          <button className="btn" style={{ padding: "3px 10px" }} onClick={onClose}>✕</button>
        </div>
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Поиск по названию или домену…"
          style={{ ...inputStyle, width: "100%", marginBottom: 12 }}
          autoFocus
        />
        <div style={{ overflow: "auto", display: "flex", flexDirection: "column", gap: 6 }}>
          {added.length > 0 && (
            <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 0.5 }}>
              Добавленные
            </div>
          )}
          {added.map((s) => row(s, true))}
          {addable.length > 0 && (
            <div className="muted" style={{ fontSize: 11, textTransform: "uppercase", letterSpacing: 0.5, marginTop: 6 }}>
              Библиотека
            </div>
          )}
          {addable.map((s) => row(s, false))}
          {added.length === 0 && addable.length === 0 && (
            <div className="muted" style={{ padding: 20 }}>Ничего не найдено.</div>
          )}
        </div>
      </div>
    </div>
  );
}

function ServiceEditor({
  initial,
  onCancel,
  onSave,
  onDelete,
}: {
  initial: Service;
  onCancel: () => void;
  onSave: (s: Service) => void;
  onDelete?: () => void;
}) {
  const [name, setName] = useState(initial.name);
  const [icon, setIcon] = useState(initial.icon);
  const [domains, setDomains] = useState(initial.domains.join("\n"));
  const [ips, setIps] = useState(initial.ip_cidrs.join("\n"));

  function save() {
    const id = initial.id || name.trim().toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "") || `svc-${Date.now()}`;
    onSave({
      id,
      name: name.trim() || id,
      icon: icon.trim() || "🔧",
      domains: domains.split("\n").map((s) => s.trim()).filter(Boolean),
      ip_cidrs: ips.split("\n").map((s) => s.trim()).filter(Boolean),
    });
  }

  return (
    <div style={overlay}>
      <div className="card" style={{ width: 520, maxHeight: "86vh", overflow: "auto" }}>
        <div style={{ fontWeight: 600, marginBottom: 12 }}>
          {initial.id ? "Редактирование сервиса" : "Новый сервис"}
        </div>
        <div style={{ display: "flex", gap: 8, marginBottom: 10 }}>
          <input value={icon} onChange={(e) => setIcon(e.target.value)} style={{ ...inputStyle, width: 60, textAlign: "center" }} />
          <input value={name} onChange={(e) => setName(e.target.value)} placeholder="Название" style={{ ...inputStyle, flex: 1 }} />
        </div>
        <div className="muted" style={{ fontSize: 12, marginBottom: 4 }}>Домены (по одному в строке):</div>
        <textarea value={domains} onChange={(e) => setDomains(e.target.value)} style={{ ...inputStyle, width: "100%", height: 140, fontFamily: "Consolas, monospace" }} />
        <div className="muted" style={{ fontSize: 12, margin: "10px 0 4px" }}>IP / CIDR (по одному в строке):</div>
        <textarea value={ips} onChange={(e) => setIps(e.target.value)} style={{ ...inputStyle, width: "100%", height: 90, fontFamily: "Consolas, monospace" }} />
        <div style={{ display: "flex", gap: 8, marginTop: 14, justifyContent: "flex-end" }}>
          {onDelete && <button className="btn" style={{ marginRight: "auto" }} onClick={onDelete}>Удалить</button>}
          <button className="btn" onClick={onCancel}>Отмена</button>
          <button className="btn primary" onClick={save}>Сохранить</button>
        </div>
      </div>
    </div>
  );
}

const overlay: React.CSSProperties = {
  position: "fixed",
  inset: 0,
  background: "rgba(0,0,0,0.5)",
  display: "flex",
  alignItems: "center",
  justifyContent: "center",
  zIndex: 50,
};
