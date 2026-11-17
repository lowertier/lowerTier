import type { Doc } from "./api";
import type { PeerRow } from "./store";

export function machineIdentity(key: string, instance?: string): string {
  return instance && instance !== "00000000-0000-0000-0000-000000000000"
    ? `instance:${instance}:key:${key}` : `key:${key}`;
}

export function offlineRows(
  records: Doc[],
  live: PeerRow[],
  at: number,
  idFor: (identity: string) => number,
  alias: (key: string) => string | undefined,
): PeerRow[] {
  const online = new Set(live.map((peer) => machineIdentity(peer.key, peer.raw.route?.inst_id)));
  return records.filter((record) =>
    !online.has(record.id)
    && (Number(record.offline_retention) === -1
      || at - Number(record.last_seen_unix_ms) < Number(record.offline_retention) * 1000),
  ).map((record) => {
    const route = record.route ?? {};
    const hostname = route.hostname || "Offline machine";
    return {
      id: idFor(record.id),
      key: record.peer_key ?? "",
      name: alias(record.peer_key) || hostname,
      hostname,
      address: typeof route.ipv4_addr === "string" ? route.ipv4_addr : "",
      online: false,
      machineId: record.id,
      lastSeen: Number(record.last_seen_unix_ms),
      retention: Number(record.offline_retention),
      direct: false,
      transport: "",
      hops: [],
      rx: 0,
      tx: 0,
      rxTotal: 0,
      txTotal: 0,
      nat: "",
      version: route.version ?? "",
      secure: false,
      subnets: route.proxy_cidrs ?? [],
      raw: { route },
    };
  });
}
