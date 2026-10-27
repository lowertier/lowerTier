// Throughput over the last two minutes: received as a filled area, sent as a line.
import { Show, createMemo, createSignal } from "solid-js";
import { rate } from "../format";
import { HISTORY, tick, totals } from "../store";

const W = 480;
const H = 150;
const TOP = 18;

function niceMax(value: number): number {
  if (value <= 0) return 1000;
  const power = 10 ** Math.floor(Math.log10(value));
  for (const step of [1, 2, 5, 10]) if (value <= step * power) return step * power;
  return 10 * power;
}

export default function Chart() {
  const [hover, setHover] = createSignal<number | null>(null);
  const data = createMemo(() => {
    tick();
    const rx = [...totals.rx];
    const tx = [...totals.tx];
    const max = niceMax(Math.max(0, ...rx, ...tx));
    const x = (index: number, length: number) => W - (length - 1 - index) * (W / (HISTORY - 1));
    const y = (value: number) => H - (value / max) * (H - TOP);
    const line = (values: number[]) =>
      values.map((value, index) => `${index ? "L" : "M"}${x(index, values.length).toFixed(1)},${y(value).toFixed(1)}`).join("");
    const area = rx.length > 1 ? `${line(rx)}L${W},${H}L${x(0, rx.length).toFixed(1)},${H}Z` : "";
    return { rx, tx, max, area, rxLine: line(rx), txLine: line(tx), x };
  });
  const shown = () => {
    const d = data();
    const index = hover() ?? d.rx.length - 1;
    return { rx: d.rx[index], tx: d.tx[index], back: d.rx.length - 1 - index };
  };
  const pick = (event: PointerEvent) => {
    const box = (event.currentTarget as SVGElement).getBoundingClientRect();
    const length = data().rx.length;
    if (!length) return;
    const fromRight = Math.round(((box.right - event.clientX) / box.width) * (HISTORY - 1));
    setHover(Math.max(0, Math.min(length - 1, length - 1 - fromRight)));
  };

  return (
    <figure class="chart">
      <div class="readout">
        <span class="down">
          <b>{rate(shown().rx)}</b> in
        </span>
        <span class="up">
          <b>{rate(shown().tx)}</b> out
        </span>
        <span class="when">{shown().back > 0 ? `${shown().back}s ago` : "now"}</span>
      </div>
      <svg
        viewBox={`0 0 ${W} ${H}`}
        preserveAspectRatio="none"
        onPointerMove={pick}
        onPointerLeave={() => setHover(null)}
        role="img"
        aria-label="Throughput, last two minutes"
      >
        <line class="grid" x1="0" x2={W} y1={TOP} y2={TOP} />
        <line class="grid" x1="0" x2={W} y1={(TOP + H) / 2} y2={(TOP + H) / 2} />
        <path class="area" d={data().area} />
        <path class="rx" d={data().rxLine} vector-effect="non-scaling-stroke" />
        <path class="tx" d={data().txLine} vector-effect="non-scaling-stroke" />
        <Show when={hover() != null}>
          <line class="cursor" x1={data().x(hover()!, data().rx.length)} x2={data().x(hover()!, data().rx.length)} y1={TOP} y2={H} vector-effect="non-scaling-stroke" />
        </Show>
      </svg>
      <figcaption>
        <span>{rate(data().max)}</span>
        <span>2 min</span>
      </figcaption>
    </figure>
  );
}
