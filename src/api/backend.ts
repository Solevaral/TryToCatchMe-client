import { invoke } from "@tauri-apps/api/core";

/**
 * Typed wrappers over Tauri commands exposed by the Rust backend.
 * Command names must match #[tauri::command] fns in src-tauri/src/commands.rs.
 */

export interface CoreStatus {
  running: boolean;
  pid: number | null;
}

export async function coreStart(): Promise<void> {
  await invoke("core_start");
}

export async function coreStop(): Promise<void> {
  await invoke("core_stop");
}

export async function coreRestart(): Promise<void> {
  await invoke("core_restart");
}

export async function coreStatus(): Promise<CoreStatus> {
  return await invoke<CoreStatus>("core_status");
}

export async function getVersion(): Promise<string> {
  return await invoke<string>("app_version");
}

// ---- settings ----

export interface Settings {
  dns_doh: boolean;
  block_quic: boolean;
  auto_switch: boolean;
  capture_tun: boolean;
}

export async function isAdmin(): Promise<boolean> {
  return await invoke<boolean>("is_admin");
}

export async function relaunchAdmin(): Promise<void> {
  await invoke("relaunch_admin");
}

export async function settingsGet(): Promise<Settings> {
  return await invoke<Settings>("settings_get");
}

export async function settingsSet(settings: Settings): Promise<void> {
  await invoke("settings_set", { settings });
}

export type TrayState = "connected" | "error" | "idle";

export async function traySetState(state: TrayState): Promise<void> {
  await invoke("tray_set_state", { state });
}

// ---- profiles ----

export interface Profile {
  id: string;
  name: string;
  protocol: string;
  server: string;
  port: number;
}

export interface ImportResult {
  added: Profile[];
  errors: string[];
}

export async function profilesList(): Promise<Profile[]> {
  return await invoke<Profile[]>("profiles_list");
}

export async function profilesActive(): Promise<string | null> {
  return await invoke<string | null>("profiles_active");
}

export async function profilesImport(text: string): Promise<ImportResult> {
  return await invoke<ImportResult>("profiles_import", { text });
}

export async function profilesRemove(id: string): Promise<void> {
  await invoke("profiles_remove", { id });
}

export async function profilePing(id: string): Promise<number | null> {
  return await invoke<number | null>("profile_ping", { id });
}

export async function profilesSetActive(id: string | null): Promise<void> {
  await invoke("profiles_set_active", { id });
}

// ---- routing ----

export type RuleAction = "proxy" | "direct" | "block";

export interface RoutingRule {
  kind: string; // domain | domain_suffix | domain_keyword | ip_cidr
  value: string;
  action: RuleAction;
}

export interface ServiceSel {
  id: string;
  action: RuleAction;
}

export interface Service {
  id: string;
  name: string;
  icon: string;
  domains: string[];
  ip_cidrs: string[];
}

export interface RoutingConfig {
  mode: string; // global | direct | rule
  rules: RoutingRule[];
  services: ServiceSel[];
  region: string | null;
  geo_action: RuleAction;
  final_action: RuleAction;
}

export interface RoutingSnapshot {
  config: RoutingConfig;
  catalog: Service[];
}

export async function routingGet(): Promise<RoutingSnapshot> {
  return await invoke<RoutingSnapshot>("routing_get");
}

export async function routingSetConfig(config: RoutingConfig): Promise<void> {
  await invoke("routing_set_config", { config });
}

export async function serviceUpsert(service: Service): Promise<void> {
  await invoke("service_upsert", { service });
}

export async function serviceRemove(id: string): Promise<void> {
  await invoke("service_remove", { id });
}

export async function servicesReset(): Promise<void> {
  await invoke("services_reset");
}

export async function servicesLibrary(): Promise<Service[]> {
  return await invoke<Service[]>("services_library");
}

export async function geoRefresh(): Promise<void> {
  await invoke("geo_refresh");
}

// ---- diagnostics ----

export interface DiagStep {
  id: string;
  label: string;
  status: "ok" | "warn" | "fail" | "skip";
  detail: string;
  ms: number | null;
}

export interface DiagReport {
  steps: DiagStep[];
  verdict: string;
}

export async function diagRun(targets?: string[]): Promise<DiagReport> {
  return await invoke<DiagReport>("diag_run", { targets: targets ?? null });
}
