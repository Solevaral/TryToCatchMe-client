import { create } from "zustand";

export interface LogEntry {
  level: string; // info | warning | error | debug | app
  msg: string;
  t: number; // epoch ms
}

const CAP = 2000;

interface LogState {
  logs: LogEntry[];
  add: (level: string, msg: string) => void;
  clear: () => void;
}

export const useLogStore = create<LogState>((set) => ({
  logs: [],
  add: (level, msg) =>
    set((s) => {
      const next = s.logs.length >= CAP ? s.logs.slice(s.logs.length - CAP + 1) : s.logs.slice();
      next.push({ level: level.toLowerCase(), msg, t: Date.now() });
      return { logs: next };
    }),
  clear: () => set({ logs: [] }),
}));
