import { useState } from "react";

export const fieldStyle: React.CSSProperties = {
  background: "var(--bg-2)",
  border: "1px solid var(--border)",
  borderRadius: 8,
  color: "var(--text-0)",
  padding: "6px 8px",
};

/** Editable list of strings: chips with ×, plus an input to add one. */
export default function ListEditor(props: {
  label: string;
  placeholder: string;
  items: string[];
  onChange: (items: string[]) => void;
}) {
  const [draft, setDraft] = useState("");
  function add() {
    const v = draft.trim();
    if (v && !props.items.includes(v)) props.onChange([...props.items, v]);
    setDraft("");
  }
  return (
    <div style={{ marginBottom: 10 }}>
      <div style={{ fontSize: 13, marginBottom: 4 }}>{props.label}</div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 6 }}>
        {props.items.map((item) => (
          <span key={item} style={{ ...fieldStyle, padding: "2px 4px 2px 8px", fontSize: 12 }}>
            {item}
            <button
              className="btn"
              style={{ padding: "0 6px", marginLeft: 4 }}
              title="Удалить"
              onClick={() => props.onChange(props.items.filter((i) => i !== item))}
            >
              ×
            </button>
          </span>
        ))}
        {props.items.length === 0 && <span className="muted" style={{ fontSize: 12 }}>пусто</span>}
      </div>
      <div style={{ display: "flex", gap: 8 }}>
        <input
          value={draft}
          placeholder={props.placeholder}
          onChange={(e) => setDraft(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && add()}
          style={{ ...fieldStyle, width: 260 }}
        />
        <button className="btn" onClick={add} disabled={!draft.trim()}>
          Добавить
        </button>
      </div>
    </div>
  );
}

