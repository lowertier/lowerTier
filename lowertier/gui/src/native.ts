import { invoke, isTauri } from "@tauri-apps/api/core";

export const nativeRuntime = isTauri();
export const appLayout = nativeRuntime || new URLSearchParams(location.search).get("layout") === "app";

export interface VpnStatus {
  state: "disconnected" | "connecting" | "connected" | "reconnecting" | "disconnecting";
  platform: "ios" | "preview";
  mtu: number;
  connectionGeneration: number;
  profile?: { id: string; name: string };
  connectedAt?: number;
  lastError: string;
}

export interface VpnPoll {
  status: VpnStatus;
  snapshot?: Record<string, any>;
}

export async function vpnCommand<T>(action: string, payload: Record<string, unknown> = {}): Promise<T> {
  if (!nativeRuntime) {
    const status: VpnStatus = { state: "disconnected", platform: "preview", mtu: 1280, connectionGeneration: 0, lastError: "" };
    if (action === "poll") {
      return { status } as T;
    }
    throw new Error("VPN controls require the iOS app.");
  }
  return invoke<T>("plugin:lowertier-vpn|execute", { action, payload });
}

export async function nativeRequest(path: string, body?: Record<string, unknown>): Promise<Record<string, any>> {
  return vpnCommand("request", { path, body: body ?? {} });
}
