// Peers placed around this node at a distance set by round-trip time (log scale).
// Direct links come from the center; relayed peers hang off their first hop.
import { For, Show, createMemo } from "solid-js";
import { latency, loss as lossText, rate } from "../format";
import { peers, snapshot, type PeerRow } from "../store";

const SIZE = 640;
const C = SIZE / 2;
const INNER = 64;
const OUTER = 262;
const UNMEASURED = 292;
// log10 of milliseconds shown between INNER and OUTER.
const LOW = -1;
const HIGH = 3;
const RINGS = [1, 10, 100];

/** Position of a round trip on the log scale shared by the radar and the list: 0 at 0.1 ms,
 * 1 at 1000 ms. */
export function rttFraction(rttUs: number): number {
  const log = Math.log10(rttUs / 1000);
  return Math.min(1, Math.max(0, (log - LOW) / (HIGH - LOW)));
}

function radius(rttUs?: number): number {
  if (rttUs == null || !(rttUs > 0)) return UNMEASURED;
  return INNER + rttFraction(rttUs) * (OUTER - INNER);
}

function angle(key: string, id: number): number {
  let hash = 2166136261;
  for (const char of key || String(id)) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619);
  return ((hash >>> 0) / 4294967296) * Math.PI * 2;
}

type Box = { l: number; r: number; t: number; b: number };

// Label extents in viewBox units, from the 13px name and 11px detail lines.
function detail(row: PeerRow): string {
  const rate_ = row.rx + row.tx;
  return `${latency(row.rtt)}${(row.loss ?? 0) >= 10_000 ? ` · ${lossText(row.loss)} loss` : ""}${rate_ > 2000 ? ` · ${rate(rate_)}` : ""}`;
}

function box(row: PeerRow, x: number, y: number, right: boolean): Box {
  const width = Math.max(row.name.length * 7.4, detail(row).length * 6.1) + 12;
  return right
    ? { l: x - 8, r: x + 12 + width, t: y - 16, b: y + 18 }
    : { l: x - 12 - width, r: x + 8, t: y - 16, b: y + 18 };
}

const MARGIN = 6;
const SELF_BOX: Box = { l: C - 96, r: C + 96, t: C - 12, b: C + 52 };
const STEP = Math.PI / 72;
const RING_ANGLE = -0.9;

/** Where a ring's "N ms" caption sits, so peers keep clear of it. */
function ringLabel(ms: number): Box {
  const r = radius(ms * 1000);
  const x = C + r * Math.cos(RING_ANGLE) + 4;
  const y = C + r * Math.sin(RING_ANGLE) - 4;
  return { l: x - 2, r: x + String(ms).length * 7 + 30, t: y - 12, b: y + 4 };
}

function overlap(a: Box, b: Box): number {
  const w = Math.min(a.r, b.r) - Math.max(a.l, b.l);
  const h = Math.min(a.b, b.b) - Math.max(a.t, b.t);
  return w > 0 && h > 0 ? w * h : 0;
}

function overflow(b: Box): number {
  const out = (v: number) => Math.max(0, v);
  return (out(MARGIN - b.l) + out(b.r - (SIZE - MARGIN)) + out(MARGIN - b.t) + out(b.b - (SIZE - MARGIN))) * 40;
}

/** Angles that keep every dot and label clear of each other, this node and the map edge.
 * Radius carries the round-trip time, so only the angle moves, as little as possible from its
 * hashed preference. Peers are placed in a fixed order so a redraw keeps its arrangement. */
function spread(rows: PeerRow[]): Map<number, number> {
  const placed: Box[] = [SELF_BOX, ...RINGS.map(ringLabel)];
  const out = new Map<number, number>();
  const order = rows
    .map((row) => ({ row, preferred: angle(row.key, row.id), r: Math.round(radius(row.rtt) / 4) * 4 }))
    .sort((a, b) => a.preferred - b.preferred || a.row.id - b.row.id);
  for (const { row, preferred, r } of order) {
    let best = preferred;
    let bestBox = box(row, C + r * Math.cos(preferred), C + r * Math.sin(preferred), Math.cos(preferred) >= 0);
    let bestCost = Infinity;
    for (let k = 0; k <= 72 && bestCost > 0; k++) {
      for (const sign of k === 0 ? [1] : [1, -1]) {
        const a = preferred + sign * k * STEP;
        const x = C + r * Math.cos(a);
        const y = C + r * Math.sin(a);
        const candidate = box(row, x, y, Math.cos(a) >= 0);
        const cost = placed.reduce((sum, other) => sum + overlap(candidate, other), 0) + overflow(candidate) + k * 0.5;
        if (cost < bestCost) {
          best = a;
          bestBox = candidate;
          bestCost = cost;
        }
      }
    }
    placed.push(bestBox);
    out.set(row.id, best);
  }
  return out;
}

function lossy(row: PeerRow) {
  return (row.loss ?? 0) >= 10_000;
}

/** Flow marks move faster with more traffic. */
function flowDuration(bps: number): string {
  const seconds = 2.4 - Math.min(2, Math.log10(Math.max(1, bps)) / 4.5);
  return `${seconds.toFixed(2)}s`;
}

export default function PeerMap(props: { selected?: number; onSelect: (id?: number) => void }) {
  const placed = createMemo(() => {
    const rows = peers();
    const angles = spread(rows);
    return rows.map((row) => {
      const r = radius(row.rtt);
      const a = angles.get(row.id) ?? angle(row.key, row.id);
      return { row, x: C + r * Math.cos(a), y: C + r * Math.sin(a), a };
    });
  });
  const position = (id?: number) => {
    const found = placed().find((item) => item.row.id === id);
    return found ? { x: found.x, y: found.y } : { x: C, y: C };
  };
  const self = () => snapshot()?.node?.node;

  return (
    <svg
      class="peer-map"
      viewBox={`0 0 ${SIZE} ${SIZE}`}
      role="img"
      aria-label="Peers by round-trip time"
      onClick={() => props.onSelect(undefined)}
    >
      <For each={RINGS}>
        {(ms) => {
          const r = radius(ms * 1000);
          return (
            <g class="ring">
              <circle cx={C} cy={C} r={r} />
              <text x={C + r * Math.cos(RING_ANGLE) + 4} y={C + r * Math.sin(RING_ANGLE) - 4}>
                {ms} ms
              </text>
            </g>
          );
        }}
      </For>
      <circle class="ring unmeasured" cx={C} cy={C} r={UNMEASURED} />

      <For each={placed()}>
        {(item) => {
          const from = () => (item.row.via != null ? position(item.row.via) : { x: C, y: C });
          const d = () => `M${from().x},${from().y} L${item.x},${item.y}`;
          const active = () => props.selected === item.row.id;
          return (
            <g
              classList={{
                link: true,
                relayed: item.row.via != null,
                lossy: lossy(item.row),
                active: active(),
                dim: props.selected != null && !active(),
              }}
            >
              <path class="track" d={d()} stroke-width={1 + Math.min(3, Math.log10(1 + item.row.rx + item.row.tx) / 3)} />
              <Show when={item.row.rx + item.row.tx > 2000}>
                <path class="flow" d={d()} style={{ "animation-duration": flowDuration(item.row.rx + item.row.tx) }} />
              </Show>
            </g>
          );
        }}
      </For>

      <g class="self">
        <circle cx={C} cy={C} r={9} />
        <text x={C} y={C + 28} text-anchor="middle">
          {self()?.hostname ?? ""}
        </text>
        <text class="sub" x={C} y={C + 44} text-anchor="middle">
          {self()?.ipv4_addr ?? ""}
        </text>
      </g>

      <For each={placed()}>
        {(item) => {
          const right = () => Math.cos(item.a) >= 0;
          const active = () => props.selected === item.row.id;
          return (
            <g
              classList={{
                peer: true,
                relayed: item.row.via != null,
                lossy: lossy(item.row),
                active: active(),
                dim: props.selected != null && !active(),
              }}
              transform={`translate(${item.x},${item.y})`}
              tabindex="0"
              role="button"
              aria-label={`${item.row.name}, ${latency(item.row.rtt)}`}
              onClick={(event) => {
                event.stopPropagation();
                props.onSelect(active() ? undefined : item.row.id);
              }}
              onKeyDown={(event) => {
                if (event.key === "Enter" || event.key === " ") {
                  event.preventDefault();
                  props.onSelect(active() ? undefined : item.row.id);
                }
              }}
            >
              <circle class="hit" r={16} />
              <circle class="dot" r={item.row.via == null ? 5.5 : 5} />
              <text x={right() ? 12 : -12} y={-2} text-anchor={right() ? "start" : "end"}>
                {item.row.name}
              </text>
              <text class="sub" x={right() ? 12 : -12} y={13} text-anchor={right() ? "start" : "end"}>
                {detail(item.row)}
              </text>
            </g>
          );
        }}
      </For>
    </svg>
  );
}
