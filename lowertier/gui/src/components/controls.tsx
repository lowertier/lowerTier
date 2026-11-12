import { For, Show, createMemo, createSignal, onCleanup, onMount, type JSX } from "solid-js";
import { CheckGlyph, CloseGlyph, CopyGlyph } from "./icons";

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
      classList={{ unset: index() < 0, long: props.values.join("").length > 22 }}
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

export interface MenuItem {
  label: string;
  onSelect: () => void;
  danger?: boolean;
  disabled?: boolean;
}

/** A button that opens a list of actions. Arrow keys move, Escape closes. */
export function Menu(props: { label: string; items: MenuItem[]; children: JSX.Element }) {
  const [open, setOpen] = createSignal(false);
  const [place, setPlace] = createSignal<{ top?: number; bottom?: number; right: number }>({ right: 0 });
  let button: HTMLButtonElement | undefined;
  let list: HTMLUListElement | undefined;
  const close = (focus = true) => {
    setOpen(false);
    if (focus) button?.focus();
  };
  const items = () => (list ? [...list.querySelectorAll<HTMLButtonElement>("button:not(:disabled)")] : []);
  const show = () => {
    const box = button!.getBoundingClientRect();
    const right = Math.max(8, window.innerWidth - box.right);
    // Open upward when the list would run past the bottom of the viewport.
    const height = 8 + props.items.length * 31;
    setPlace(box.bottom + 4 + height > window.innerHeight - 8 ? { bottom: window.innerHeight - box.top + 4, right } : { top: box.bottom + 4, right });
    setOpen(true);
    queueMicrotask(() => items()[0]?.focus());
  };
  const outside = (event: PointerEvent) => {
    if (open() && !list?.contains(event.target as Node) && !button?.contains(event.target as Node)) close(false);
  };
  const dismiss = () => open() && close(list?.contains(document.activeElement) ?? false);
  document.addEventListener("pointerdown", outside);
  window.addEventListener("resize", dismiss);
  window.addEventListener("scroll", dismiss, true);
  onCleanup(() => {
    document.removeEventListener("pointerdown", outside);
    window.removeEventListener("resize", dismiss);
    window.removeEventListener("scroll", dismiss, true);
  });
  const keys = (event: KeyboardEvent) => {
    const all = items();
    const at = all.indexOf(document.activeElement as HTMLButtonElement);
    if (event.key === "Escape" || event.key === "Tab") {
      event.preventDefault();
      close();
    } else if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      const step = event.key === "ArrowDown" ? 1 : -1;
      all[(at + step + all.length) % all.length]?.focus();
    }
  };
  return (
    <>
      <button
        ref={button}
        type="button"
        class="icon-button"
        aria-label={props.label}
        aria-haspopup="menu"
        aria-expanded={open()}
        onClick={(event) => {
          event.stopPropagation();
          open() ? close() : show();
        }}
        onKeyDown={(event) => {
          if (event.key === "ArrowDown" && !open()) {
            event.preventDefault();
            show();
          }
        }}
      >
        {props.children}
      </button>
      <Show when={open()}>
        <ul ref={list} class="menu" role="menu" aria-label={props.label} style={{ top: place().top != null ? `${place().top}px` : undefined, bottom: place().bottom != null ? `${place().bottom}px` : undefined, right: `${place().right}px` }} onKeyDown={keys} onClick={(event) => event.stopPropagation()}>
          <For each={props.items}>
            {(item) => (
              <li role="none">
                <button
                  type="button"
                  role="menuitem"
                  classList={{ danger: item.danger }}
                  disabled={item.disabled}
                  onClick={() => {
                    close();
                    item.onSelect();
                  }}
                >
                  {item.label}
                </button>
              </li>
            )}
          </For>
        </ul>
      </Show>
    </>
  );
}

export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch {
    // Plain HTTP on a non-loopback address has no clipboard API: fall back to a selection.
    const area = document.createElement("textarea");
    area.value = text;
    area.setAttribute("readonly", "");
    area.style.position = "fixed";
    area.style.opacity = "0";
    document.body.append(area);
    area.select();
    const done = document.execCommand("copy");
    area.remove();
    return done;
  }
}

/** Copy a value and confirm in place. */
export function Copy(props: { text: string; label: string; children?: JSX.Element; class?: string }) {
  const [done, setDone] = createSignal(false);
  let timer: number | undefined;
  onCleanup(() => window.clearTimeout(timer));
  return (
    <button
      type="button"
      class={`copy ${props.class ?? ""}`}
      classList={{ done: done() }}
      aria-label={props.label}
      title={props.label}
      onClick={async (event) => {
        event.stopPropagation();
        if (await copyText(props.text)) {
          setDone(true);
          window.clearTimeout(timer);
          timer = window.setTimeout(() => setDone(false), 1400);
        }
      }}
    >
      {props.children}
      <span class="copy-mark">{done() ? <CheckGlyph /> : <CopyGlyph />}</span>
      <span class="sr-only" aria-live="polite">{done() ? "Copied" : ""}</span>
    </button>
  );
}

/** A modal dialog on the native element: focus stays inside, Escape and the backdrop close it. */
export function Dialog(props: { title: string; onClose: () => void; children: JSX.Element; wide?: boolean }) {
  let dialog: HTMLDialogElement | undefined;
  onMount(() => dialog?.showModal());
  return (
    <dialog
      ref={dialog}
      class="dialog"
      classList={{ wide: props.wide }}
      aria-label={props.title}
      onClose={() => props.onClose()}
      onClick={(event) => {
        if (event.target === dialog) dialog.close();
      }}
    >
      <div class="dialog-body">
        <header class="dialog-head">
          <h2>{props.title}</h2>
          <button type="button" class="icon-button" aria-label="Close" onClick={() => dialog?.close()}>
            <CloseGlyph />
          </button>
        </header>
        {props.children}
      </div>
    </dialog>
  );
}
