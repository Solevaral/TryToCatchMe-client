export default function ErrorBanner({ text, dismiss }: { text: string | null; dismiss: () => void }) {
  if (!text) return null;
  return <div role="alert" className="card" style={{ marginBottom: 12, color: "var(--err)", overflowWrap: "anywhere" }}>
    {text}
    <button className="btn" style={{ marginLeft: 8 }} onClick={dismiss} aria-label="Закрыть сообщение">✕</button>
  </div>;
}
