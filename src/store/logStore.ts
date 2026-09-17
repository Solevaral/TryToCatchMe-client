import { create } from "zustand";

export interface LogEntry {
  level: string; // info | warning | error | debug | app
  msg: string;
  t: number; // epoch ms
}

/** Kept in memory for the log console. The core can emit thousands of lines a
 *  second, so entries arrive in batches and the oldest ones are dropped. */
const CAP = 1000;

interface LogState {
  logs: LogEntry[];
  add: (level: string, msg: string) => void;
  addMany: (entries: Array<{ level: string; msg: string }>) => void;
  clear: () => void;
}

function append(logs: LogEntry[], entries: Array<{ level: string; msg: string }>): LogEntry[] {
  const t = Date.now();
  const next = logs.concat(entries.map((e) => ({ level: e.level.toLowerCase(), msg: e.msg, t })));
  return next.length > CAP ? next.slice(next.length - CAP) : next;
}

export const useLogStore = create<LogState>((set) => ({
  logs: [],
  add: (level, msg) => set((s) => ({ logs: append(s.logs, [{ level, msg }]) })),
  addMany: (entries) =>
    set((s) => (entries.length === 0 ? s : { logs: append(s.logs, entries) })),
  clear: () => set({ logs: [] }),
}));
