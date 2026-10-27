import { For, createMemo } from "solid-js";

export function Segmented(props: {
  label: string;
  values: readonly string[];
  value?: string;
  onChange: (value: string) => void;
  disabled?: boolean;
}) {
  const index = createMemo(() => props.values.indexOf(props.value ?? ""));
  const move = (event: KeyboardEvent) => {
    const step = event.key === "ArrowRight" || event.key === "ArrowDown" ? 1 : event.key === "ArrowLeft" || event.key === "ArrowUp" ? -1 : 0;
    if (!step) return;
    event.preventDefault();
    const next = props.values[(Math.max(0, index()) + step + props.values.length) % props.values.length];
    props.onChange(next);
    const group = event.currentTarget as HTMLElement;
    queueMicrotask(() => (group.querySelector('[aria-checked="true"]') as HTMLElement | null)?.focus());
  };
  return (
    <div
      class="segmented"
      role="radiogroup"
      aria-label={props.label}
      style={{ "--count": props.values.length, "--index": Math.max(0, index()) }}
      classList={{ unset: index() < 0 }}
      onKeyDown={move}
    >
      <span class="thumb" aria-hidden="true" />
      <For each={props.values}>
        {(value, i) => (
          <button
            type="button"
            role="radio"
            aria-checked={i() === index()}
            tabindex={i() === Math.max(0, index()) ? 0 : -1}
            disabled={props.disabled}
            onClick={() => props.onChange(value)}
          >
            {value}
          </button>
        )}
      </For>
    </div>
  );
}

export function Switch(props: { label: string; checked: boolean; onChange: (value: boolean) => void; disabled?: boolean }) {
  return (
    <button
      type="button"
      class="switch"
      role="switch"
      aria-checked={props.checked}
      aria-label={props.label}
      disabled={props.disabled}
      onClick={() => props.onChange(!props.checked)}
    >
      <span />
    </button>
  );
}

export function Spark(props: { values: number[]; height?: number; class?: string }) {
  const W = 72;
  const H = () => props.height ?? 18;
  const path = createMemo(() => {
    const values = props.values;
    const finite = values.filter(Number.isFinite);
    if (finite.length < 2) return "";
    const max = Math.max(...finite);
    const min = Math.min(...finite);
    const span = max - min || 1;
    let d = "";
    let pen = false;
    values.forEach((value, index) => {
      if (!Number.isFinite(value)) {
        pen = false;
        return;
      }
      const x = (index / Math.max(1, values.length - 1)) * W;
      const y = H() - 2 - ((value - min) / span) * (H() - 4);
      d += `${pen ? "L" : "M"}${x.toFixed(1)},${y.toFixed(1)}`;
      pen = true;
    });
    return d;
  });
  return (
    <svg class={`spark ${props.class ?? ""}`} viewBox={`0 0 ${W} ${H()}`} width={W} height={H()} aria-hidden="true">
      <path d={path()} />
    </svg>
  );
}
