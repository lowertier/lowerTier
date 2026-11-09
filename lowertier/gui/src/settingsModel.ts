import type { Doc } from "./api";

export const REDACTED = "[REDACTED]";
export const ROUTING_PATHS = new Set([
  "path", "group", "relay.policy", "relay.use_relays", "relay.transit",
  "relay.probe_budget_bps", "routes.serve_exit",
]);
export const FLEET_GUI_CIDRS = ["10.126.126.0/24", "192.168.51.0/24", "192.168.40.0/24"];

export type Changes = Record<string, unknown>;
export type SecretSource = "value" | "file" | "automatic";

/** Quoted dotted keys preserve each update path, including children of opaque tables. */
export function optionPatch(changes: Changes): Doc {
  const paths = Object.keys(changes);
  for (const [index, path] of paths.entries()) {
    if (paths.slice(0, index).some((other) => path.startsWith(`${other}.`) || other.startsWith(`${path}.`))) {
      throw new Error(`Overlapping settings: ${path}. Apply one editor at a time.`);
    }
  }
  const set = Object.fromEntries(Object.entries(changes).filter(([, value]) => value !== null));
  const clear = paths.filter((path) => changes[path] === null);
  return { stage: true, ...(Object.keys(set).length ? { set } : {}), ...(clear.length ? { clear } : {}) };
}

export function secretSource(value: unknown, file: unknown): SecretSource {
  return file != null ? "file" : value != null ? "value" : "automatic";
}

export function secretChanges(path: string, source: SecretSource, value = ""): Changes {
  return {
    [path]: source === "value" ? value : null,
    [`${path}_file`]: source === "file" ? value : null,
    ...(path === "identity.private_key" ? { "identity.public_key": null } : {}),
  };
}

/** A replacement bundle supplies its own identity. The explicit root pin stays in place. */
export function credentialChanges(value: string): Changes {
  return {
    "network.credential": value,
    "network.secret": null,
    "network.secret_file": null,
    "identity.private_key": null,
    "identity.private_key_file": null,
    "identity.public_key": null,
  };
}

export interface GuiRule {
  cidr: string;
  requireKey: boolean;
  overlayDefault?: boolean;
}

export function overlaySubnet(address?: string): string | undefined {
  const match = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(address ?? "");
  if (!match) return undefined;
  const octets = match.slice(1, 5).map(Number);
  const prefix = Number(match[5]);
  if (octets.some((part) => part > 255) || prefix > 32) return undefined;
  const ip = octets.reduce((bits, part) => (bits << 8) | part, 0) >>> 0;
  const network = (ip & (prefix === 0 ? 0 : 0xffffffff << (32 - prefix))) >>> 0;
  return `${[24, 16, 8, 0].map((shift) => (network >>> shift) & 255).join(".")}/${prefix}`;
}

export function guiRules(allow?: string[], open: string[] = []): GuiRule[] {
  const rules: GuiRule[] = allow == null ? [{ cidr: "", requireKey: true, overlayDefault: true }] : [];
  for (const cidr of new Set([...(allow ?? []), ...open])) rules.push({ cidr, requireKey: !open.includes(cidr) });
  return rules;
}

export function guiChanges(rules: GuiRule[], subnet?: string, fleet = false): Changes {
  const normalized = new Map<string, boolean>();
  let defaultOverlay = false;
  for (const rule of rules) {
    if (rule.overlayDefault && rule.requireKey) {
      defaultOverlay = true;
      continue;
    }
    const cidr = rule.overlayDefault ? subnet : rule.cidr.trim();
    if (!cidr) throw new Error("Enter a source CIDR. Wait for the overlay address before changing its default rule.");
    if (normalized.has(cidr)) throw new Error(`Duplicate source CIDR: ${cidr}.`);
    normalized.set(cidr, rule.requireKey);
  }
  if (fleet) for (const cidr of FLEET_GUI_CIDRS) normalized.set(cidr, false);
  const keyed = [...normalized].some(([, requireKey]) => requireKey);
  if (defaultOverlay && (keyed || fleet)) {
    if (!subnet) throw new Error("Wait for the overlay address before adding source rules that require a key.");
    if (!normalized.has(subnet)) normalized.set(subnet, true);
  }
  return {
    "gui.allow": defaultOverlay && !keyed && !fleet ? null : [...normalized.keys()],
    "gui.open": [...normalized].filter(([, requireKey]) => !requireKey).map(([cidr]) => cidr),
  };
}
