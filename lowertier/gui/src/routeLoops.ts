const NIL_INST = /^0{8}-0{4}-0{4}-0{4}-0{12}$/;

const validInst = (inst?: string): string | undefined => (inst && !NIL_INST.test(inst) ? inst : undefined);

/** Remove self hops and collapse any repeated-peer loop from a route path. */
export function sanitizeHops(rawHops: number[], selfId?: number, destination?: number): number[] {
  const out: number[] = [];
  for (const id of rawHops) {
    if (id == null || id === 0 || id === selfId) continue;
    const prev = out.indexOf(id);
    if (prev >= 0) {
      out.length = prev + 1;
    } else {
      out.push(id);
    }
  }
  if (!out.length && destination != null && destination !== selfId) return [destination];
  return out;
}

export interface PeerIdentityRef {
  key?: string;
  inst?: string;
}

/** Pick the first relay hop only when the peer is not direct and the hop cannot alias this node or the peer itself. */
export function selectViaPeerId(params: {
  peerId: number;
  peerKey?: string;
  peerInst?: string;
  direct: boolean;
  pathPeerIds: number[];
  routeNextHop?: number;
  selfId?: number;
  selfInst?: string;
  selfKey?: string;
  peersById: Map<number, PeerIdentityRef>;
}): number | undefined {
  if (params.direct) return undefined;
  const hops = sanitizeHops(params.pathPeerIds, params.selfId);
  const candidate = hops.length > 1 ? hops[0] : params.routeNextHop;
  if (!candidate || candidate === params.selfId || candidate === params.peerId) return undefined;
  const hopInfo = params.peersById.get(candidate);
  if (hopInfo) {
    const selfInst = validInst(params.selfInst);
    const peerInst = validInst(params.peerInst);
    const hopInst = validInst(hopInfo.inst);
    if ((selfInst && hopInst === selfInst) || (params.selfKey && hopInfo.key === params.selfKey)) return undefined;
    if ((peerInst && hopInst === peerInst) || (params.peerKey && hopInfo.key === params.peerKey)) return undefined;
  }
  return candidate;
}

/** Disambiguate unaliased peers whose hostname matches this node or another peer. */
export function disambiguatePeerNames(
  rows: { id: number; alias?: string; hostname: string; address: string }[],
  selfHostname?: string,
): Map<number, string> {
  const counts = new Map<string, number>();
  if (selfHostname) counts.set(selfHostname, 1);
  for (const row of rows) {
    const label = row.alias || row.hostname;
    counts.set(label, (counts.get(label) ?? 0) + 1);
  }
  const names = new Map<number, string>();
  for (const row of rows) {
    if (row.alias) {
      names.set(row.id, row.alias);
      continue;
    }
    const bareIp = row.address.split("/")[0];
    const collides = (counts.get(row.hostname) ?? 0) > 1 || (selfHostname != null && row.hostname === selfHostname);
    names.set(row.id, collides ? `${row.hostname} (${bareIp || `#${row.id}`})` : row.hostname);
  }
  return names;
}
