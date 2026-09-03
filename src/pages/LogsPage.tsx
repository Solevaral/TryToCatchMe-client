import { useEffect, useMemo, useRef, useState } from "react";
import { writeText } from "@tauri-apps/plugin-clipboard-manager";
import { useLogStore } from "../store/logStore";

const LEVELS = ["all", "info", "warning", "error", "debug"] as const;
type Level = (typeof LEVELS)[number];

const LEVEL_COLOR: Record<string, string> = {
  info: "var(--text-1)",
  warning: "var(--warn)",
  error: "var(--err)",
  debug: "var(--text-2)",
  app: "var(--accent)",
};

function ts(t: number): string {
  const d = new Date(t);
  return d.toLocaleTimeString("ru-RU", { hour12: false }) +
    "." + String(d.getMilliseconds()).padStart(3, "0");
}

export default function LogsPage() {
  const logs = useLogStore((s) => s.logs);
  const clear = useLogStore((s) => s.clear);
  const [level, setLevel] = useState<Level>("all");
  const [q, setQ] = useState("");
  const [autoscroll, setAutoscroll] = useState(true);
  const boxRef = useRef<HTMLDivElement>(null);

  const filtered = useMemo(() => {
    const needle = q.trim().toLowerCase();
    return logs.filter((l) => {
      if (level !== "all" && l.level !== level) return false;
      if (needle && !l.msg.toLowerCase().includes(needle)) return false;
      return true;
    });
  }, [logs, level, q]);

  useEffect(() => {
    if (autoscroll && boxRef.current) {
      boxRef.current.scrollTop = boxRef.current.scrollHeight;
    }
  }, [filtered, autoscroll]);

  async function copyAll() {
    const text = filtered.map((l) => `${ts(l.t)} [${l.level}] ${l.msg}`).join("\n");
    try {
      await writeText(text);
    } catch {
      /* ignore */
    }
  }

  return (
    <div>
      <h1 className="page-title">Логи</h1>

      <div style={{ display: "flex", gap: 8, marginBottom: 12, flexWrap: "wrap" }}>
        {LEVELS.map((lv) => (
          <button
            key={lv}
            className={`btn ${level === lv ? "primary" : ""}`}
            style={{ padding: "5px 10px" }}
            onClick={() => setLevel(lv)}
          >
            {lv}
          </button>
        ))}
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Поиск…"
          style={{
            flex: 1,
            minWidth: 140,
            background: "var(--bg-2)",
            border: "1px solid var(--border)",
            borderRadius: 8,
            color: "var(--text-0)",
            padding: "6px 10px",
          }}
        />
        <button
          className={`btn ${autoscroll ? "primary" : ""}`}
          style={{ padding: "5px 10px" }}
          onClick={() => setAutoscroll((v) => !v)}
        >
          Автоскролл
        </button>
        <button className="btn" style={{ padding: "5px 10px" }} onClick={copyAll}>
          Копировать
        </button>
        <button className="btn" style={{ padding: "5px 10px" }} onClick={clear}>
          Очистить
        </button>
      </div>

      <div
        ref={boxRef}
        className="card"
        style={{
          fontFamily: "Consolas, monospace",
          fontSize: 12.5,
          lineHeight: 1.5,
          height: "calc(100vh - 190px)",
          overflow: "auto",
          background: "var(--bg-0)",
          padding: 12,
        }}
      >
        {filtered.length === 0 ? (
          <div className="muted">
            Логов пока нет. Подключитесь — здесь появится живой поток от ядра sing-box.
          </div>
        ) : (
          filtered.map((l, i) => (
            <div key={i} style={{ whiteSpace: "pre-wrap", wordBreak: "break-word" }}>
              <span className="muted">{ts(l.t)}</span>{" "}
              <span style={{ color: LEVEL_COLOR[l.level] ?? "var(--text-1)" }}>
                [{l.level}]
              </span>{" "}
              <span>{l.msg}</span>
            </div>
          ))
        )}
      </div>
    </div>
  );
}
