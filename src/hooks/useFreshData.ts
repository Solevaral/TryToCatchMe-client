import { useEffect, useRef } from "react";
import { listen } from "@tauri-apps/api/event";
import { useAppStore } from "../store/appStore";

/** Refresh visible pages on focus, backend changes, and optional light polling. */
export function useFreshData(refresh: () => Promise<unknown>, events: string[] = [], interval?: number) {
  const latest = useRef(refresh);
  latest.current = refresh;
  const key = events.join("|");
  useEffect(() => {
    let disposed = false;
    let busy = false;
    let again = false;
    const run = async () => {
      if (disposed || document.hidden) return;
      if (busy) { again = true; return; }
      busy = true;
      try { await latest.current(); } catch (e) { if (!disposed) useAppStore.getState().setLastError(String(e)); }
      finally {
        busy = false;
        if (again) { again = false; void run(); }
      }
    };
    void run();
    window.addEventListener("focus", run);
    document.addEventListener("visibilitychange", run);
    const subscriptions = key ? key.split("|").map((event) => listen(event, run)) : [];
    const timer = interval ? setInterval(run, interval) : undefined;
    return () => {
      disposed = true;
      clearInterval(timer);
      window.removeEventListener("focus", run);
      document.removeEventListener("visibilitychange", run);
      subscriptions.forEach((p) => p.then((off) => off()).catch(() => {}));
    };
  }, [key, interval]);
}
