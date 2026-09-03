import { create } from "zustand";

export type ConnStatus = "disconnected" | "connecting" | "connected" | "error";

export type Page =
  | "profiles"
  | "routing"
  | "diagnostics"
  | "logs"
  | "settings";

interface AppState {
  page: Page;
  setPage: (p: Page) => void;

  status: ConnStatus;
  setStatus: (s: ConnStatus) => void;

  activeProfileId: string | null;
  setActiveProfile: (id: string | null) => void;

  // live traffic (bytes/s)
  up: number;
  down: number;
  setTraffic: (up: number, down: number) => void;
}

export const useAppStore = create<AppState>((set) => ({
  page: "profiles",
  setPage: (page) => set({ page }),

  status: "disconnected",
  setStatus: (status) => set({ status }),

  activeProfileId: null,
  setActiveProfile: (activeProfileId) => set({ activeProfileId }),

  up: 0,
  down: 0,
  setTraffic: (up, down) => set({ up, down }),
}));
