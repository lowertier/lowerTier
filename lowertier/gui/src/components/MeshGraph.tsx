import { For, Show, createMemo, createSignal } from "solid-js";
import { exportsConfigured } from "../config";
import { latency as formatRtt } from "../format";
import { snapshot, type PeerRow } from "../store";

interface Props {
  peers: PeerRow[];
  onOpenPeer: (id: number) => void;
}

interface NodePos {
  x: number;
  y: number;
  row?: PeerRow;
  label: string;
  sublabel: string;
  subnets: string[];
  direct: boolean;
  isSelf: boolean;
  isRelayHub: boolean;
}

interface Edge {
  fromX: number;
  fromY: number;
  toX: number;
  toY: number;
  relayed: boolean;
  label: string;
  peerId: number;
}

export default function MeshGraph(props: Props) {
  const [hovered, setHovered] = createSignal<number | "self" | null>(null);

  const layout = createMemo(() => {
    const cx = 380;
    const cy = 180;
    const rows = props.peers;
    const relayHubs = new Set(rows.map((r) => r.via).filter((id): id is number => id != null));
    const inner = rows.filter((r) => r.direct || relayHubs.has(r.id) || r.via == null);
    const outer = rows.filter((r) => !r.direct && !relayHubs.has(r.id) && r.via != null);

    const nodes = new Map<number | "self", NodePos>();
    const selfNode = snapshot()?.node?.node ?? {};
    const selfSubnets = exportsConfigured().map((e) => e.mapped_cidr || e.cidr).filter(Boolean);
    nodes.set("self", {
      x: cx,
      y: cy,
      label: (selfNode.hostname as string | undefined) || "this machine",
      sublabel: (selfNode.ipv4_addr as string | undefined) || "local",
      subnets: selfSubnets,
      direct: true,
      isSelf: true,
      isRelayHub: false,
    });

    const placeRing = (list: PeerRow[], rx: number, ry: number, phase: number) => {
      const n = list.length;
      list.forEach((row, idx) => {
        const angle = phase + (2 * Math.PI * idx) / Math.max(n, 1) - Math.PI / 2;
        nodes.set(row.id, {
          x: cx + rx * Math.cos(angle),
          y: cy + ry * Math.sin(angle),
          row,
          label: row.name,
          sublabel: row.address || `peer ${row.id}`,
          subnets: row.subnets,
          direct: row.direct,
          isSelf: false,
          isRelayHub: relayHubs.has(row.id),
        });
      });
    };

    placeRing(inner, outer.length ? 165 : 220, outer.length ? 105 : 125, 0);
    placeRing(outer, 305, 145, Math.PI / Math.max(outer.length, 2));

    const selfPos = nodes.get("self")!;
    const edges: Edge[] = [];
    for (const row of rows) {
      const target = nodes.get(row.id);
      if (!target) continue;
      if (row.direct || row.via == null) {
        edges.push({
          fromX: selfPos.x,
          fromY: selfPos.y,
          toX: target.x,
          toY: target.y,
          relayed: !row.direct,
          label: [row.transport, row.rtt != null ? formatRtt(row.rtt) : ""].filter(Boolean).join(" "),
          peerId: row.id,
        });
      }
      if (row.via != null) {
        const hop = nodes.get(row.via) ?? selfPos;
        edges.push({
          fromX: hop.x,
          fromY: hop.y,
          toX: target.x,
          toY: target.y,
          relayed: true,
          label: row.rtt != null ? formatRtt(row.rtt) : "relayed",
          peerId: row.id,
        });
      }
    }

    return { nodes: [...nodes.entries()], edges };
  });

  const active = () => hovered();

  return (
    <div class="mesh-graph">
      <div class="mesh-legend">
        <span><i class="legend-dot self" /> This machine</span>
        <span><i class="legend-dot direct" /> Direct peer</span>
        <span><i class="legend-dot relayed" /> Relayed / multi-hop</span>
        <span><i class="legend-line" /> Solid = direct · Dashed = via relay</span>
      </div>
      <Show when={props.peers.length > 0} fallback={<p class="empty">No peers in the mesh yet.</p>}>
        <svg viewBox="0 0 760 360" class="mesh-svg" role="img" aria-label="Mesh topology graph">
          <g class="mesh-edges">
            <For each={layout().edges}>
              {(edge) => {
                const isActive = () => active() === edge.peerId;
                const mx = (edge.fromX + edge.toX) / 2;
                const my = (edge.fromY + edge.toY) / 2;
                return (
                  <g classList={{ "mesh-edge-active": isActive() }}>
                    <line
                      x1={edge.fromX}
                      y1={edge.fromY}
                      x2={edge.toX}
                      y2={edge.toY}
                      class={edge.relayed ? "edge-relayed" : "edge-direct"}
                    />
                    <Show when={edge.label && (isActive() || props.peers.length <= 8)}>
                      <text x={mx} y={my - 4} class="edge-label">{edge.label}</text>
                    </Show>
                  </g>
                );
              }}
            </For>
          </g>
          <g class="mesh-nodes">
            <For each={layout().nodes}>
              {([id, node]) => (
                <g
                  class="mesh-node"
                  classList={{
                    "node-self": node.isSelf,
                    "node-direct": !node.isSelf && node.direct,
                    "node-relayed": !node.isSelf && !node.direct,
                    "node-hub": node.isRelayHub,
                    "node-hover": active() === id,
                  }}
                  transform={`translate(${node.x}, ${node.y})`}
                  onMouseEnter={() => setHovered(id)}
                  onMouseLeave={() => setHovered(null)}
                  onClick={() => node.row && props.onOpenPeer(node.row.id)}
                >
                  <circle r={node.isSelf ? 18 : node.isRelayHub ? 15 : 12} />
                  <text y={node.isSelf ? -24 : -18} class="node-title">{node.label}</text>
                  <text y={node.isSelf ? 30 : 24} class="node-sub">{node.sublabel}</text>
                  <Show when={node.subnets.length > 0}>
                    <text y={node.isSelf ? 42 : 36} class="node-subnets">
                      {node.subnets.slice(0, 2).join(", ")}{node.subnets.length > 2 ? ` +${node.subnets.length - 2}` : ""}
                    </text>
                  </Show>
                </g>
              )}
            </For>
          </g>
        </svg>
      </Show>
    </div>
  );
}
