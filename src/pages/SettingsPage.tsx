import { useEffect, useState } from "react";
import { enable, disable, isEnabled } from "@tauri-apps/plugin-autostart";
import {
  getVersion,
  settingsGet,
  settingsSet,
  type Settings,
} from "../api/backend";

export default function SettingsPage() {
  const [version, setVersion] = useState<string>("…");
  const [autostart, setAutostart] = useState<boolean | null>(null);
  const [settings, setSettings] = useState<Settings | null>(null);

  useEffect(() => {
    getVersion().then(setVersion).catch(() => setVersion("н/д"));
    isEnabled().then(setAutostart).catch(() => setAutostart(null));
    settingsGet().then(setSettings).catch(() => setSettings(null));
  }, []);

  async function toggleAutostart() {
    try {
      if (autostart) {
        await disable();
        setAutostart(false);
      } else {
        await enable();
        setAutostart(true);
      }
    } catch (e) {
      console.error(e);
    }
  }

  async function patch(p: Partial<Settings>) {
    if (!settings) return;
    const next = { ...settings, ...p };
    setSettings(next);
    await settingsSet(next);
  }

  return (
    <div>
      <h1 className="page-title">Настройки</h1>

      <div className="card" style={{ marginBottom: 18 }}>
        <div style={{ fontWeight: 600, marginBottom: 10 }}>Запуск</div>
        <label style={{ display: "flex", gap: 10, alignItems: "center" }}>
          <input
            type="checkbox"
            checked={!!autostart}
            disabled={autostart === null}
            onChange={toggleAutostart}
          />
          Запускать при входе в Windows (свёрнуто в трей)
        </label>
      </div>

      <div className="card" style={{ marginBottom: 18 }}>
        <div style={{ fontWeight: 600, marginBottom: 10 }}>Безопасность</div>
        {settings ? (
          <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
            <label style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
              <input
                type="checkbox"
                checked={settings.dns_doh}
                onChange={(e) => patch({ dns_doh: e.target.checked })}
              />
              <span>
                DNS-over-HTTPS через VPN (анти-leak)
                <div className="muted" style={{ fontSize: 12 }}>
                  DNS-запросы шифруются и идут в туннель, а не к провайдеру.
                </div>
              </span>
            </label>
            <label style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
              <input
                type="checkbox"
                checked={settings.block_quic}
                onChange={(e) => patch({ block_quic: e.target.checked })}
              />
              <span>
                Блокировать QUIC / UDP:443
                <div className="muted" style={{ fontSize: 12 }}>
                  Трафик уходит на TLS/TCP — надёжнее работают правила по SNI/Reality.
                </div>
              </span>
            </label>
            <label style={{ display: "flex", gap: 10, alignItems: "flex-start" }}>
              <input
                type="checkbox"
                checked={settings.auto_switch}
                onChange={(e) => patch({ auto_switch: e.target.checked })}
              />
              <span>
                Авто-переключение профиля при сбое
                <div className="muted" style={{ fontSize: 12 }}>
                  Если активный сервер перестаёт отвечать — автоматически переключаюсь на
                  следующий профиль. Не помогает, если недоступен сам сайт при живом VPN.
                </div>
              </span>
            </label>
          </div>
        ) : (
          <div className="muted">Загрузка…</div>
        )}
        <div className="muted" style={{ fontSize: 12, marginTop: 12 }}>
          Изменения применяются при следующем подключении (или кнопкой «Перезапустить»).
        </div>
      </div>

      <div className="card" style={{ marginBottom: 18 }}>
        <div style={{ fontWeight: 600, marginBottom: 10 }}>Перехват трафика</div>
        <div className="muted">
          Режим перехвата (Системный прокси / TUN) переключается на вкладке
          «Маршрутизация». TUN ловит весь трафик (включая приложения, игнорирующие прокси)
          и требует прав администратора — запрос появится при включении.
        </div>
      </div>

      <div className="card">
        <div style={{ fontWeight: 600, marginBottom: 6 }}>О приложении</div>
        <div className="muted">TryToCatchMe · версия {version}</div>
        <div className="muted">Ядро: sing-box 1.14 (sidecar) · тема: тёмная</div>
      </div>
    </div>
  );
}
