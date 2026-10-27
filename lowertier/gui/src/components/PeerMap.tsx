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

function radius(rttUs?: number): number {
  if (rttUs == null || !(rttUs > 0)) return UNMEASURED;
  const log = Math.log10(rttUs / 1000);
  const t = Math.min(1, Math.max(0, (log - LOW) / (HIGH - LOW)));
  return INNER + t * (OUTER - INNER);
}

function angle(key: string, id: number): number {
  let hash = 2166136261;
  for (const char of key || String(id)) hash = Math.imul(hash ^ char.charCodeAt(0), 16777619);
  return ((hash >>> 0) / 4294967296) * Math.PI * 2;
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
  const placed = createMemo(() =>
    peers().map((row) => {
      const r = radius(row.rtt);
      const a = angle(row.key, row.id);
      return { row, x: C + r * Math.cos(a), y: C + r * Math.sin(a), a };
    }),
  );
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
              <text x={C + r * Math.cos(-0.9) + 4} y={C + r * Math.sin(-0.9) - 4}>
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
                {latency(item.row.rtt)}
                {lossy(item.row) ? ` · ${lossText(item.row.loss)} loss` : ""}
                {item.row.rx + item.row.tx > 2000 ? ` · ${rate(item.row.rx + item.row.tx)}` : ""}
              </text>
            </g>
          );
        }}
      </For>
    </svg>
  );
}
