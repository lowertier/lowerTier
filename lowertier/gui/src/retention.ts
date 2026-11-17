export const DEFAULT_RETENTION = 604_800;
export const RETENTION_PERIODS = [
  { label: "1 hour", seconds: 3600 },
  { label: "1 day", seconds: 86_400 },
  { label: "7 days", seconds: DEFAULT_RETENTION },
  { label: "30 days", seconds: 2_592_000 },
];

export type MachineType = "temporary" | "retained" | "permanent";

export function retentionSeconds(type: MachineType, period: number): number {
  return type === "temporary" ? 0 : type === "permanent" ? -1 : period;
}

export function machineType(seconds: number): MachineType {
  return seconds === 0 ? "temporary" : seconds === -1 ? "permanent" : "retained";
}

export function retentionLabel(seconds: number): string {
  if (seconds === 0) return "Temporary";
  if (seconds === -1) return "Keep until removed";
  const days = seconds / 86_400;
  const hours = seconds / 3600;
  const duration = Number.isInteger(days) ? `${days} ${days === 1 ? "day" : "days"}`
    : Number.isInteger(hours) ? `${hours} ${hours === 1 ? "hour" : "hours"}`
    : `${seconds} seconds`;
  return `Keep offline for ${duration}`;
}
