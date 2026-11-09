import { useCallback } from "react";
import { useAppStore } from "../store/appStore";
import { coreStart, coreStop, coreRestart, traySetState } from "../api/backend";

/** Turn whatever `invoke` rejected with into readable text. */
export function errorText(e: unknown): string {
  if (typeof e === "string") return e;
  if (e instanceof Error) return e.message;
  try {
    return JSON.stringify(e);
  } catch {
    return String(e);
  }
}

/**
 * Shared connect/disconnect/restart controller used by both the sidebar and the
 * Profiles page, so connection state, the tray icon, the status pill and the
 * last-error text stay in sync no matter where the user clicks. The backend writes
 * the detailed reason to the log console; here we keep it visible in the UI too.
 */
export function useConnection() {
  const status = useAppStore((s) => s.status);
  const setStatus = useAppStore((s) => s.setStatus);
  const setLastError = useAppStore((s) => s.setLastError);

  const fail = useCallback(
    async (e: unknown) => {
      setStatus("error");
      setLastError(errorText(e));
      await traySetState("error").catch(() => {});
    },
    [setStatus, setLastError]
  );

  const connect = useCallback(async () => {
    if (useAppStore.getState().status === "connecting") return;
    setStatus("connecting");
    setLastError(null);
    try {
      await coreStart();
      setStatus("connected");
      await traySetState("connected").catch(() => {});
    } catch (e) {
      await fail(e);
    }
  }, [setStatus, setLastError, fail]);

  // No "connecting" guard: Disconnect must also abort a connect that hangs.
  const disconnect = useCallback(async () => {
    setStatus("disconnected");
    setLastError(null);
    try {
      await coreStop();
      setStatus("disconnected");
      await traySetState("idle").catch(() => {});
    } catch (e) {
      await fail(e);
    }
  }, [setStatus, setLastError, fail]);

  const restart = useCallback(async () => {
    if (useAppStore.getState().status === "connecting") return;
    setStatus("connecting");
    setLastError(null);
    try {
      await coreRestart();
      setStatus("connected");
      await traySetState("connected").catch(() => {});
    } catch (e) {
      await fail(e);
    }
  }, [setStatus, setLastError, fail]);

  const toggle = useCallback(async () => {
    if (status === "connected") await disconnect();
    else await connect();
  }, [status, connect, disconnect]);

  return {
    status,
    connected: status === "connected",
    busy: status === "connecting",
    connect,
    disconnect,
    restart,
    toggle,
  };
}
