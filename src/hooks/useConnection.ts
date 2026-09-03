import { useCallback } from "react";
import { useAppStore } from "../store/appStore";
import { coreStart, coreStop, coreRestart, traySetState } from "../api/backend";

/**
 * Shared connect/disconnect/restart controller used by both the sidebar and the
 * Profiles page, so connection state, the tray icon, and the status pill stay in
 * sync no matter where the user clicks.
 */
export function useConnection() {
  const status = useAppStore((s) => s.status);
  const setStatus = useAppStore((s) => s.setStatus);

  const connect = useCallback(async () => {
    setStatus("connecting");
    try {
      await coreStart();
      setStatus("connected");
      await traySetState("connected");
    } catch (e) {
      setStatus("error");
      await traySetState("error").catch(() => {});
      throw e;
    }
  }, [setStatus]);

  const disconnect = useCallback(async () => {
    setStatus("disconnected");
    try {
      await coreStop();
    } finally {
      await traySetState("idle").catch(() => {});
    }
  }, [setStatus]);

  const restart = useCallback(async () => {
    setStatus("connecting");
    try {
      await coreRestart();
      setStatus("connected");
      await traySetState("connected");
    } catch (e) {
      setStatus("error");
      await traySetState("error").catch(() => {});
      throw e;
    }
  }, [setStatus]);

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
