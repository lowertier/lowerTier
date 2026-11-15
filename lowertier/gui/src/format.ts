import type { Doc } from "./api";

export const NONE = "–";

export type Numeric = number | string;

/** Convert protobuf integer strings only when a display needs a number. */
export function numeric(value?: Numeric | null): number | undefined {
  return value == null ? undefined : Number(value);
}

/**
 * Sum integer counters exactly. Convert counts to numbers only for the display ratio.
 * Zero totals produce zero shares.
 */
export function counterShares(counters: readonly Numeric[]): number[] {
  const counts = counters.map((value) => BigInt(value));
  const total = counts.reduce((sum, value) => sum + value, 0n);
  return counts.map((value) => (total === 0n ? 0 : Number(value) / Number(total)));
}

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
export function rate(bps?: Numeric): string {
  const value = numeric(bps);
  if (value == null || !Number.isFinite(value)) return NONE;
  return scaled(value, ["bit/s", "kbit/s", "Mbit/s", "Gbit/s", "Tbit/s"], 1000);
}

export function bytes(count?: Numeric): string {
  const value = numeric(count);
  if (value == null || !Number.isFinite(value)) return NONE;
  return scaled(value, ["B", "KiB", "MiB", "GiB", "TiB"], 1024);
}

export function latency(us?: Numeric): string {
  const value = numeric(us);
  if (value == null || !Number.isFinite(value)) return NONE;
  const ms = value / 1000;
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

export function clock(unixMs: Numeric): string {
  return new Date(Number(unixMs)).toLocaleTimeString([], { hour12: false });
}

/** A short form of a base64 key. */
export function shortKey(key?: string): string {
  return key ? `${key.slice(0, 8)}…` : "";
}

export function words(value: string): string {
  return value.replace(/[_.]/g, " ");
}
