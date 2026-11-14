// Polls the selected daemon once a second and keeps short histories for charts.
import { createSignal } from "solid-js";
import { api, ApiError, setTarget, type Doc } from "./api";
import { configured } from "./config";
import { ipv4 } from "./format";
import { currentIncarnations } from "./incarnations";
import { aliasFor } from "./notes";
import { disambiguatePeerNames, sanitizeHops, selectViaPeerId } from "./routeLoops";

export const HISTORY = 120;
const INTERVAL = 1000;
const HIDDEN_INTERVAL = 5000;

export interface PeerRow {
  id: number;
  key: string;
  /** The local alias from [[note]], or the peer's own hostname. */
  name: string;
  hostname: string;
  address: string;
  direct: boolean;
  transport: string;
  /** First hop when traffic to the peer goes through another peer. */
  via?: number;
  hops: number[];
  rtt?: number;
  loss?: number;
  delivery?: number;
  rx: number;
  tx: number;
  rxTotal: number;
  txTotal: number;
  nat: string;
  version: string;
  secure: boolean;
  subnets: string[];
  raw: Doc;
}

export interface Series {
  rtt: number[];
  rx: number[];
  tx: number[];
}

const [snapshot, setSnapshot] = createSignal<Doc | null>(null);
const [peers, setPeers] = createSignal<PeerRow[]>([]);
const [localPeers, setLocalPeers] = createSignal<PeerRow[]>([]);
const [error, setError] = createSignal<ApiError | null>(null);
const [sampledAt, setSampledAt] = createSignal(0);
const [tick, setTick] = createSignal(0);
const [nodes, setNodes] = createSignal<Doc[]>([]);
const [selection, setSelection] = createSignal<{
  node?: string;
  instance?: string;
  remote?: string;
  remoteLabel?: string;
  viaInstance?: string;
}>({});
const [remoteSecret, setRemoteSecretSignal] = createSignal("");
const [now, setNow] = createSignal(Date.now());

export { snapshot, peers, localPeers, error, sampledAt, tick, nodes, selection, remoteSecret, now };

export const history = new Map<number, Series>();
export const totals: Series = { rtt: [], rx: [], tx: [] };

function push(ring: number[], value: number) {
  if (ring.length === HISTORY) ring.shift();
  ring.push(value);
}

let previous: { at: number; counters: Map<string, { rx: number; tx: number }> } | null = null;

function median(values: number[]): number | undefined {
  if (!values.length) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

function ingest(doc: Doc) {
  const at = doc.sampled_at_unix_ms ?? Date.now();
  const counters = new Map<string, { rx: number; tx: number }>();
  const elapsed = previous ? Math.max(0.2, (at - previous.at) / 1000) : 0;
  const rows: PeerRow[] = [];
  const selfNode = doc.node?.node ?? {};
  const selfPeerId = selfNode.peer_id as number | undefined;
  const selfInst = selfNode.inst_id as string | undefined;
  const selfHostname = selfNode.hostname as string | undefined;
  const selfKey = configured("identity.public_key") as string | undefined;
  const rawPeers = (doc.peers ?? []) as Doc[];
  const peersById = new Map<number, { key?: string; inst?: string }>(
    rawPeers.map((peer) => [
      peer.peer_id as number,
      { key: peer.peer_key as string | undefined, inst: peer.route?.inst_id as string | undefined },
    ]),
  );
  for (const peer of currentIncarnations(rawPeers, selfInst, selfPeerId)) {
    const route: Doc = peer.route ?? {};
    const conns = ((peer.conns ?? []) as Doc[]).filter((conn) => !conn.is_closed);
    let rx = 0;
    let tx = 0;
    let rxTotal = 0;
    let txTotal = 0;
    for (const conn of conns) {
      const stats = conn.stats ?? {};
      const id = `${peer.peer_id}/${conn.conn_id}`;
      const current = { rx: stats.rx_bytes ?? 0, tx: stats.tx_bytes ?? 0 };
      counters.set(id, current);
      rxTotal += current.rx;
      txTotal += current.tx;
      const before = previous?.counters.get(id);
      if (before && elapsed) {
        rx += (Math.max(0, current.rx - before.rx) * 8) / elapsed;
        tx += (Math.max(0, current.tx - before.tx) * 8) / elapsed;
      }
    }
    const lossFromConns = conns
      .map((conn) => conn.tx_loss_ppm ?? (conn.loss_rate != null ? conn.loss_rate * 1e6 : undefined))
      .filter((value): value is number => value != null);
    const direct = conns.length > 0;
    const hops = sanitizeHops((peer.path_peer_ids ?? []) as number[], selfPeerId, direct ? peer.peer_id : undefined);
    const via = selectViaPeerId({
      peerId: peer.peer_id,
      peerKey: peer.peer_key,
      peerInst: route.inst_id,
      direct,
      pathPeerIds: (peer.path_peer_ids ?? []) as number[],
      routeNextHop: route.next_hop_peer_id,
      selfId: selfPeerId,
      selfInst,
      selfKey,
      peersById,
    });
    const hostname = route.hostname || `peer ${peer.peer_id}`;
    const row: PeerRow = {
      id: peer.peer_id,
      key: peer.peer_key ?? "",
      name: aliasFor(peer.peer_key ?? "") || hostname,
      hostname,
      address: ipv4(route.ipv4_addr),
      direct,
      transport: conns[0]?.tunnel?.tunnel_type ?? "",
      via,
      hops,
      rtt: peer.rtt_us ?? (direct ? conns[0]?.stats?.latency_us : undefined),
      loss: peer.loss_ppm ?? (lossFromConns.length ? Math.max(...lossFromConns) : undefined),
      delivery: peer.delivery_bps,
      rx,
      tx,
      rxTotal,
      txTotal,
      nat: peer.udp_nat ?? "",
      version: route.version ?? "",
      secure: peer.end_to_end_session_ready === true,
      subnets: ((route.proxy_cidrs ?? []) as string[]).filter(Boolean),
      raw: peer,
    };
    rows.push(row);
    let series = history.get(row.id);
    if (!series) history.set(row.id, (series = { rtt: [], rx: [], tx: [] }));
    if (previous) {
      push(series.rtt, row.rtt ?? NaN);
      push(series.rx, rx);
      push(series.tx, tx);
    }
  }
  const names = disambiguatePeerNames(
    rows.map((row) => ({
      id: row.id,
      alias: aliasFor(row.key),
      hostname: row.hostname,
      address: row.address,
    })),
    selfHostname,
  );
  for (const row of rows) row.name = names.get(row.id) ?? row.name;
  rows.sort((a, b) => a.name.localeCompare(b.name));
  if (previous) {
    push(totals.rx, rows.reduce((sum, row) => sum + row.rx, 0));
    push(totals.tx, rows.reduce((sum, row) => sum + row.tx, 0));
    push(totals.rtt, median(rows.flatMap((row) => (row.rtt != null ? [row.rtt] : []))) ?? NaN);
  }
  previous = { at, counters };
  setSnapshot(doc);
  setPeers(rows);
  if (!selection().remote) setLocalPeers(rows);
  setSampledAt(at);
  setTick((value) => value + 1);
}

let timer: number | undefined;
let generation = 0;

async function poll() {
  const mine = generation;
  let delay = INTERVAL;
  try {
    const doc = await api("snapshot");
    if (mine !== generation) return;
    ingest(doc);
    setError(null);
  } catch (caught) {
    if (mine !== generation) return;
    setError(caught instanceof ApiError ? caught : new ApiError({ message: String(caught) }));
    delay = 2000;
  }
  if (document.hidden) delay = Math.max(delay, HIDDEN_INTERVAL);
  timer = window.setTimeout(poll, delay);
}

export function restart() {
  generation++;
  window.clearTimeout(timer);
  poll();
}

function resetView() {
  history.clear();
  for (const ring of Object.values(totals)) ring.length = 0;
  previous = null;
  setSnapshot(null);
  setPeers([]);
  setError(null);
  restart();
}

export function select(node?: string, instance?: string) {
  setSelection({ node, instance });
  setTarget(node, instance, undefined, undefined, undefined);
  resetView();
}

export function selectRemote(remote?: string, label?: string, secret?: string) {
  const current = selection();
  const nextSecret = secret !== undefined ? secret : remoteSecret();
  if (secret !== undefined) setRemoteSecretSignal(secret);
  const trimmed = remote?.trim();
  if (!trimmed) {
    const localInstance = current.viaInstance ?? current.instance;
    setSelection({ node: current.node, instance: localInstance });
    setTarget(current.node, localInstance, undefined, undefined, undefined);
    resetView();
    return;
  }
  const via = current.remote ? current.viaInstance : (current.instance ?? snapshot()?.instance);
  setSelection({
    node: current.node,
    instance: undefined,
    remote: trimmed,
    remoteLabel: label?.trim() || trimmed,
    viaInstance: via,
  });
  setTarget(current.node, undefined, trimmed, via, nextSecret);
  resetView();
}

export function updateRemoteSecret(secret: string) {
  setRemoteSecretSignal(secret);
  const current = selection();
  if (current.remote) {
    setTarget(current.node, current.instance, current.remote, current.viaInstance, secret);
    resetView();
  }
}

async function refreshNodes() {
  try {
    const doc = await api("nodes");
    setNodes(doc.nodes ?? []);
  } catch {}
}

export function start() {
  restart();
  refreshNodes();
  window.setInterval(refreshNodes, 5000);
  window.setInterval(() => setNow(Date.now()), 1000);
  document.addEventListener("visibilitychange", () => {
    if (!document.hidden) restart();
  });
}

/** The local node's peer ID. */
export const selfId = () => snapshot()?.node?.node?.peer_id as number | undefined;

export function peerName(id: number): string {
  if (id === selfId()) return snapshot()?.node?.node?.hostname || "this machine";
  return peers().find((peer) => peer.id === id)?.name ?? `peer ${id}`;
}

