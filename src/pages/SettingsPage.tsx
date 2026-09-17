import { useEffect, useState } from "react";
import { enable, disable, isEnabled } from "@tauri-apps/plugin-autostart";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
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

  const [copied, setCopied] = useState<string>("");

  async function copyEnv(kind: "ps" | "cmd" | "sh") {
    if (!settings) return;
    const url = `http://127.0.0.1:${settings.proxy_port}`;
    const text =
      kind === "ps"
        ? `$env:HTTP_PROXY="${url}"; $env:HTTPS_PROXY="${url}"; $env:NO_PROXY="localhost,127.0.0.1"`
        : kind === "cmd"
        ? `set HTTP_PROXY=${url}\nset HTTPS_PROXY=${url}\nset NO_PROXY=localhost,127.0.0.1`
        : `export HTTP_PROXY=${url} HTTPS_PROXY=${url} NO_PROXY=localhost,127.0.0.1`;
    try {
      await writeText(text);
      setCopied(kind);
      setTimeout(() => setCopied(""), 1500);
    } catch {
      /* ignore */
    }
  }

  const [portDraft, setPortDraft] = useState<string>("");
  const [portMsg, setPortMsg] = useState<{ ok: boolean; text: string } | null>(null);

  useEffect(() => {
    if (settings) setPortDraft(String(settings.proxy_port));
  }, [settings?.proxy_port]); // eslint-disable-line react-hooks/exhaustive-deps

  async function patch(p: Partial<Settings>) {
    if (!settings) return;
    const next = { ...settings, ...p };
    await settingsSet(next);
    setSettings(next);
  }

  async function savePort() {
    const port = Number(portDraft);
    if (!Number.isInteger(port) || port < 1024 || port > 65534) {
      setPortMsg({ ok: false, text: "Порт должен быть целым числом от 1024 до 65534" });
      return;
    }
    try {
      await patch({ proxy_port: port });
      setPortMsg({ ok: true, text: "Сохранено — применится при следующем подключении (или «Перезапустить»)" });
    } catch (e) {
      setPortMsg({ ok: false, text: String(e) });
    }
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
          Запускать при входе в систему (свёрнуто в трей)
        </label>
      </div>

      <div className="card" style={{ marginBottom: 18 }}>
        <div style={{ fontWeight: 600, marginBottom: 10 }}>Системный прокси</div>
        {settings ? (
          <>
            <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
              <span>Порт: 127.0.0.1:</span>
              <input
                value={portDraft}
                onChange={(e) => setPortDraft(e.target.value.replace(/\D/g, ""))}
                onKeyDown={(e) => e.key === "Enter" && savePort()}
                style={{
                  width: 90,
                  background: "var(--bg-2)",
                  border: "1px solid var(--border)",
                  borderRadius: 8,
                  color: "var(--text-0)",
                  padding: "6px 8px",
                }}
              />
              <button className="btn" onClick={savePort} disabled={portDraft === String(settings.proxy_port)}>
                Сохранить
              </button>
            </div>
            {portMsg && (
              <div style={{ fontSize: 12, marginTop: 6, color: portMsg.ok ? "var(--ok)" : "var(--err)" }}>
                {portMsg.text}
              </div>
            )}
            <div className="muted" style={{ fontSize: 12, marginTop: 8 }}>
              При подключении приложение запоминает твои настройки прокси и направляет системный
              прокси на этот порт; при отключении (и после аварийного завершения) возвращает их
              обратно. Порт + 1 занят служебной загрузкой гео-списков.
            </div>
            <div style={{ marginTop: 12, fontWeight: 550 }}>Программы, которые игнорируют системный прокси</div>
            <div className="muted" style={{ fontSize: 12, margin: "4px 0 8px" }}>
              Консольные утилиты (например Claude Code, git, npm) и часть приложений не читают
              системный прокси. Либо включите TUN, либо задайте им переменные окружения —
              скопируйте и выполните в терминале перед запуском программы:
            </div>
            <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
              <button className="btn" onClick={() => copyEnv("ps")}>{copied === "ps" ? "Скопировано ✓" : "PowerShell"}</button>
              <button className="btn" onClick={() => copyEnv("cmd")}>{copied === "cmd" ? "Скопировано ✓" : "cmd"}</button>
              <button className="btn" onClick={() => copyEnv("sh")}>{copied === "sh" ? "Скопировано ✓" : "bash / zsh"}</button>
            </div>
          </>
        ) : (
          <div className="muted">Загрузка…</div>
        )}
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
                checked={settings.verbose_logs}
                onChange={(e) => patch({ verbose_logs: e.target.checked })}
              />
              <span>
                Подробные логи ядра
                <div className="muted" style={{ fontSize: 12 }}>
                  В «Логи» попадёт каждое соединение. В режиме TUN это тысячи строк в
                  секунду: ядро сильнее грузит процессор, а окно приложения — память.
                  Включайте только для разбора проблемы. Обычно достаточно
                  предупреждений и ошибок, они пишутся всегда.
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
