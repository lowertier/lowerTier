import type { Doc } from "./api";

export const NONE = "–";

export function ipv4(inet?: Doc): string {
  const address = inet?.address?.addr;
  if (typeof address !== "number") return "";
  return [24, 16, 8, 0].map((shift) => (address >>> shift) & 255).join(".");
}

function scaled(value: number, units: string[], step: number): string {
  let index = 0;
  while (Math.abs(value) >= step && index < units.length - 1) {
    value /= step;
    index++;
  }
  const digits = value >= 100 || index === 0 ? 0 : value >= 10 ? 1 : 2;
  return `${value.toFixed(digits)} ${units[index]}`;
}

/** Bits per second. */
export function rate(bps?: number): string {
  if (bps == null || !Number.isFinite(bps)) return NONE;
  return scaled(bps, ["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"], 1000);
}

export function bytes(count?: number): string {
  if (count == null) return NONE;
  return scaled(count, ["B", "KiB", "MiB", "GiB", "TiB"], 1024);
}

export function latency(us?: number): string {
  if (us == null) return NONE;
  const ms = us / 1000;
  if (ms < 1) return `${ms.toFixed(2)} ms`;
  if (ms < 10) return `${ms.toFixed(1)} ms`;
  return `${Math.round(ms)} ms`;
}

/** Parts per million as a percentage. */
export function loss(ppm?: number): string {
  if (ppm == null) return NONE;
  const percent = ppm / 10_000;
  if (percent === 0) return "0%";
  if (percent < 0.1) return "<0.1%";
  return `${percent < 10 ? percent.toFixed(1) : Math.round(percent)}%`;
}

export function ago(ms: number): string {
  const seconds = Math.max(0, Math.round(ms / 1000));
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m`;
  return `${Math.round(seconds / 3600)}h`;
}

export function clock(unixMs: number): string {
  return new Date(unixMs).toLocaleTimeString([], { hour12: false });
}

/** A short form of a base64 key. */
export function shortKey(key?: string): string {
  return key ? `${key.slice(0, 8)}…` : "";
}

export function words(value: string): string {
  return value.replace(/[_.]/g, " ");
}
