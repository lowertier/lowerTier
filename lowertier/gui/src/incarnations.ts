type Doc = Record<string, any>;

/** A restarted instance takes a new peer ID, and routes for its old ID can linger. Drop entries
 * that carry this node's own instance ID, and keep one entry per instance ID: the one with a live
 * connection, else the shortest path. */
export function currentIncarnations(peers: Doc[], selfInst?: string, selfId?: number): Doc[] {
  const live = (peer: Doc) => ((peer.conns ?? []) as Doc[]).some((conn) => !conn.is_closed);
  const hops = (peer: Doc) => ((peer.path_peer_ids ?? []) as number[]).length || Infinity;
  const kept = new Map<string, Doc>();
  const out: Doc[] = [];
  for (const peer of peers) {
    const inst = peer.route?.inst_id as string | undefined;
    if (!inst || /^0{8}-0{4}-0{4}-0{4}-0{12}$/.test(inst)) {
      out.push(peer);
      continue;
    }
    if (inst === selfInst && peer.peer_id !== selfId) continue;
    const other = kept.get(inst);
    if (!other || (live(peer) && !live(other)) || (live(peer) === live(other) && hops(peer) < hops(other))) kept.set(inst, peer);
  }
  return [...out, ...kept.values()];
}
