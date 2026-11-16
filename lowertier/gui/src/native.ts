import { invoke, isTauri } from "@tauri-apps/api/core";

export const nativeRuntime = isTauri();
export const appLayout = nativeRuntime || new URLSearchParams(location.search).get("layout") === "app";

export interface VpnStatus {
  state: "disconnected" | "connecting" | "connected" | "reconnecting" | "disconnecting";
  platform: "ios" | "preview";
  mtu: number;
  profile?: { id: string; name: string };
  connectedAt?: number;
  lastError: string;
}

export async function vpnCommand<T>(action: string, payload: Record<string, unknown> = {}): Promise<T> {
  if (!nativeRuntime) {
    if (action === "status") {
      return { state: "disconnected", platform: "preview", mtu: 1280, lastError: "" } as T;
    }
    throw new Error("VPN controls require the iOS app.");
  }
  return invoke<T>("plugin:lowertier-vpn|execute", { action, payload: JSON.stringify(payload) });
}

export async function nativeRequest(path: string, body?: Record<string, unknown>): Promise<Record<string, any>> {
  if (path === "nodes") return { nodes: [] };
  return vpnCommand("request", { path, body: body ?? {} });
}
