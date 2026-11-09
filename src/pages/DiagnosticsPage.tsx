import { useEffect, useRef, useState } from "react";
import { diagRun, type DiagReport, type DiagStep } from "../api/backend";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useAppStore } from "../store/appStore";

const STATUS_DOT: Record<string, string> = {
  ok: "dot ok",
  warn: "dot warn",
  fail: "dot err",
  skip: "dot",
};
const STATUS_TEXT: Record<string, string> = {
  ok: "OK",
  warn: "внимание",
  fail: "ошибка",
  skip: "пропущено",
};

const STEP_NAMES: Record<string, string> = {
  local: "Локальная сеть", isp: "Прямой интернет", server: "VPN-сервер", tunnel: "Запрос через VPN",
  svc: "Сервисы", "exit-ip": "IP выхода", "google-country": "Страна Google", claude: "Claude API", openai: "OpenAI API",
};

const STORE_KEY = "ttcm.diag.targets";

function loadTargets(): string[] {
  try {
    const raw = localStorage.getItem(STORE_KEY);
    if (raw) {
      const arr = JSON.parse(raw);
      if (Array.isArray(arr) && arr.length) return arr;
    }
  } catch {
    /* ignore */
  }
  return ["www.google.com"];
}

export default function DiagnosticsPage() {
  const requested = useAppStore((s) => s.diagnosticsRequested);
  const [checkedAt, setCheckedAt] = useState<number | null>(null);
  const [targets, setTargets] = useState<string[]>(loadTargets);
  const [draft, setDraft] = useState("");
  const [report, setReport] = useState<DiagReport | null>(null);
  const [running, setRunning] = useState(false);
  const runningRef = useRef(false);

  // Persist targets across tab switches / restarts.
  useEffect(() => {
    try {
      localStorage.setItem(STORE_KEY, JSON.stringify(targets));
    } catch {
      /* ignore */
    }
  }, [targets]);

  function addTarget() {
    const t = draft.trim();
    if (t && !targets.includes(t)) setTargets([...targets, t]);
    setDraft("");
  }
  function removeTarget(t: string) {
    if (!window.confirm("Удалить цель диагностики?")) return;
    setTargets(targets.filter((x) => x !== t));
  }

  async function run() {
    if (runningRef.current) return;
    runningRef.current = true;
    setRunning(true);
    setReport(null);
    try {
      const r = await diagRun(targets);
      setReport(r);
      setCheckedAt(Date.now());
    } catch (e) {
      useAppStore.getState().setLastError(String(e));
      setReport(null);
      setCheckedAt(null);
    } finally {
      setRunning(false);
      runningRef.current = false;
    }
  }

  // Auto-run when triggered from the tray "Диагностика" action.
  useEffect(() => {
    if (requested) { useAppStore.getState().consumeDiagnostics(); void run(); }
    const h = () => run();
    window.addEventListener("ttcm:run-diagnostics", h);
    return () => window.removeEventListener("ttcm:run-diagnostics", h);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [targets, requested]);

  const verdictColor =
    report && /в порядке/i.test(report.verdict) ? "var(--ok)" : report ? "var(--warn)" : "var(--text-1)";

  return (
    <div>
      <h1 className="page-title">Диагностика сети</h1>

      <div className="card" style={{ marginBottom: 16 }}>
        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap", marginBottom: 10 }}>
          <button className="btn primary" onClick={run} disabled={running}>
            {running ? "Проверка…" : "Проверить сеть"}
          </button>
          <input
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && addTarget()}
            placeholder="добавить целевой адрес (например discord.com)"
            style={inputStyle}
          />
          <button className="btn" onClick={addTarget}>＋</button>
        </div>
        <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
          {targets.map((t) => (
            <span key={t} style={chip}>
              {t}
              <span style={{ cursor: "pointer", opacity: 0.7 }} onClick={() => removeTarget(t)}>✕</span>
            </span>
          ))}
          {targets.length === 0 && <span className="muted">Добавьте хотя бы один адрес.</span>}
        </div>
      </div>

      {report && <div className="muted">Снимок проверки · {checkedAt ? new Date(checkedAt).toLocaleString() : "время неизвестно"}. После смены подключения выполните проверку снова.
        <button className="btn" onClick={async () => {
          try {
            // Details and labels can contain user input. Export only fixed identifiers and outcomes.
            const summary = report.steps.map((s) => `${STEP_NAMES[s.id] ?? (s.id.startsWith("target") ? "Целевой адрес" : "Дополнительная проверка")} — ${STATUS_TEXT[s.status] ?? s.status}${s.ms == null ? "" : ` · ${s.ms} мс`}`).join("\n");
            await writeText(`Диагностика TTCM · ${checkedAt ? new Date(checkedAt).toLocaleString() : ""}\n${summary}`);
          } catch (e) { useAppStore.getState().setLastError(String(e)); }
        }}>Скопировать отчёт</button>
      </div>}
      {report && (
        <div className="card" style={{ marginBottom: 16, borderColor: verdictColor }}>
          <div style={{ fontWeight: 650, color: verdictColor }}>Вердикт: {report.verdict}</div>
        </div>
      )}

      <div className="card">
        {(report?.steps ?? placeholderSteps()).map((s) => (
          <StepRow key={s.id} s={s} pending={running && !report} />
        ))}
        {!report && !running && (
          <div className="placeholder">
            Нажмите «Проверить сеть» — проверю цепочку ПК → роутер → провайдер → VPN-сервер →
            туннель → цели и покажу, где обрыв. При включённом VPN цели проверяются именно
            через туннель.
          </div>
        )}
      </div>
    </div>
  );
}

function StepRow({ s, pending }: { s: DiagStep; pending: boolean }) {
  return (
    <div
      style={{
        display: "flex",
        alignItems: "flex-start",
        gap: 12,
        padding: "12px 0",
        borderBottom: "1px solid var(--border)",
      }}
    >
      <span className={pending ? "dot warn" : STATUS_DOT[s.status]} style={{ marginTop: 5 }} />
      <div style={{ flex: 1 }}>
        <div style={{ fontWeight: 550 }}>{s.label}</div>
        {s.detail && (
          <div className="muted" style={{ fontSize: 12.5, marginTop: 2 }}>
            {s.detail}
          </div>
        )}
      </div>
      <div className="muted" style={{ fontSize: 12, whiteSpace: "nowrap", textAlign: "right" }}>
        <div>{STATUS_TEXT[s.status] ?? ""}</div>
        {s.ms != null && <div>{s.ms} ms</div>}
      </div>
    </div>
  );
}

function placeholderSteps(): DiagStep[] {
  return [
    { id: "local", label: "ПК → роутер / шлюз", status: "skip", detail: "", ms: null },
    { id: "isp", label: "Провайдер / интернет", status: "skip", detail: "", ms: null },
    { id: "server", label: "VPN-сервер (до туннеля)", status: "skip", detail: "", ms: null },
    { id: "tunnel", label: "Туннель (после connect)", status: "skip", detail: "", ms: null },
    { id: "target0", label: "Целевой сайт / сервер", status: "skip", detail: "", ms: null },
  ];
}

const inputStyle: React.CSSProperties = {
  background: "var(--bg-2)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  color: "var(--text-0)",
  padding: "6px 10px",
  minWidth: 240,
  flex: 1,
};

const chip: React.CSSProperties = {
  display: "inline-flex",
  gap: 8,
  alignItems: "center",
  background: "var(--bg-2)",
  border: "1px solid var(--border)",
  borderRadius: 16,
  padding: "4px 12px",
  fontSize: 13,
};
