import { For, Match, Show, Switch as Pick, createMemo, createSignal, onMount } from "solid-js";
import { createStore, produce } from "solid-js/store";
import { fromToml, toToml } from "../api";
import { Segmented, Switch } from "../components/controls";
import { apply, busy, config, configured, loadSchema, lookup, restartPending, say, schema, type OptionSpec } from "../config";
import { words } from "../format";

const ORDER = ["node", "network", "identity", "address", "tun", "transport", "peer", "nat", "underlay", "discovery", "relay", "routes", "export", "proxy", "forward", "dns", "acl", "camouflage", "limits", "l2", "log", "control", "gui"];
const REDACTED = "[REDACTED]";

/** Text shown in an editor for a configured value. */
function text(option: OptionSpec, value: any): string {
  if (value == null) return "";
  switch (option.kind) {
    case "list":
    case "intlist":
      return (value as unknown[]).join("\n");
    case "tables":
    case "table": {
      const keys = option.path.split(".");
      const doc: any = {};
      let table = doc;
      for (const part of keys.slice(0, -1)) table = table[part] = {};
      table[keys[keys.length - 1]] = value;
      return toToml(doc);
    }
    default:
      return String(value);
  }
}

/** Parse editor text into the value sent for an option. `null` resets it. */
function parsed(option: OptionSpec, input: string): unknown {
  const trimmed = input.trim();
  if (!trimmed) return null;
  switch (option.kind) {
    case "int": {
      const number = Number(trimmed);
      if (!Number.isInteger(number)) throw new Error(`${option.path}: "${trimmed}" is not an integer.`);
      return number;
    }
    case "list":
      return trimmed.split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
    case "intlist":
      return trimmed
        .split(/[\n,]/)
        .map((item) => item.trim())
        .filter(Boolean)
        .map((item) => {
          const number = item.startsWith("0x") ? parseInt(item.slice(2), 16) : Number(item);
          if (!Number.isInteger(number)) throw new Error(`${option.path}: "${item}" is not an integer.`);
          return number;
        });
    case "tables":
    case "table": {
      const value = lookup(fromToml(trimmed), option.path);
      if (value == null) throw new Error(`${option.path}: write the entries as [[${option.path}]] tables.`);
      return value;
    }
    default:
      return trimmed;
  }
}

export default function Settings() {
  onMount(loadSchema);
  const [filter, setFilter] = createSignal("");
  const [raw, setRaw] = createSignal(false);
  // Edited text or values by option path; null resets the option.
  const [pending, setPending] = createStore<Record<string, any>>({});
  const changed = () => Object.keys(pending);

  const visible = createMemo(() => {
    const query = filter().trim().toLowerCase();
    return schema().filter((option) => !query || `${option.path} ${option.doc}`.toLowerCase().includes(query));
  });
  const modes = createMemo(() => visible().filter((option) => option.kind === "enum"));
  const sections = createMemo(() => {
    const groups = new Map<string, OptionSpec[]>();
    for (const option of visible()) {
      if (option.kind === "enum") continue;
      const section = option.path.split(".")[0];
      if (!groups.has(section)) groups.set(section, []);
      groups.get(section)!.push(option);
    }
    return [...groups.entries()].sort(([a], [b]) => {
      const rank = (name: string) => (ORDER.indexOf(name) + 1 || ORDER.length + 1);
      return rank(a) - rank(b);
    });
  });

  const edit = (path: string, value: unknown) => setPending(path, value);
  const discard = () => setPending(produce((draft) => Object.keys(draft).forEach((key) => delete draft[key])));
  const save = async () => {
    const changes: Record<string, unknown> = {};
    try {
      for (const path of changed()) {
        const option = schema().find((item) => item.path === path)!;
        const value = pending[path];
        changes[path] = typeof value === "string" ? parsed(option, value) : value;
      }
    } catch (caught) {
      say(caught instanceof Error ? caught.message : String(caught), true);
      return;
    }
    if (await apply(changes)) discard();
  };

  const Applies = (props: { option: OptionSpec }) => (
    <span class="applies" classList={{ pending: restartPending(props.option.path) }}>
      {restartPending(props.option.path) ? "restart pending" : props.option.apply}
    </span>
  );

  const Row = (props: { option: OptionSpec }) => {
    const path = props.option.path;
    const value = () => configured(path);
    const edited = () => path in pending;
    const current = () => (edited() ? pending[path] : value());
    const name = path.split(".").slice(1).join(".") || path;
    return (
      <div class="row" classList={{ edited: edited() }}>
        <div class="label">
          <b>{words(name)}</b>
          <code>{path}</code>
          <p>{props.option.doc}</p>
        </div>
        <div class="control" classList={{ column: ["list", "intlist", "tables", "table"].includes(props.option.kind) }}>
          <Pick
            fallback={
              <input
                type={props.option.secret ? "password" : "text"}
                autocomplete="off"
                spellcheck={false}
                aria-label={path}
                placeholder={props.option.secret ? (value() === REDACTED ? "set, unchanged" : "not set") : props.option.default || props.option.type}
                value={props.option.secret ? (edited() ? (current() ?? "") : "") : edited() ? (current() ?? "") : text(props.option, value())}
                onInput={(event) => edit(path, event.currentTarget.value)}
              />
            }
          >
            <Match when={props.option.kind === "bool"}>
              <Switch label={path} checked={(current() ?? props.option.default === "true") === true} onChange={(checked) => edit(path, checked)} />
            </Match>
            <Match when={["list", "intlist", "tables", "table"].includes(props.option.kind)}>
              <textarea
                rows={props.option.kind === "tables" ? 5 : 3}
                spellcheck={false}
                aria-label={path}
                placeholder={props.option.kind === "tables" ? `[[${path}]]\n${props.option.fields.map((field) => `${field} = ""`).join("\n")}` : "one per line"}
                value={edited() ? (current() ?? "") : text(props.option, value())}
                onInput={(event) => edit(path, event.currentTarget.value)}
              />
            </Match>
          </Pick>
          <span class="row-meta">
            <Applies option={props.option} />
            <Show when={value() != null && !edited()}>
              <button type="button" class="link" onClick={() => edit(path, null)}>
                Reset
              </button>
            </Show>
            <Show when={edited()}>
              <button type="button" class="link" onClick={() => setPending(produce((draft) => delete draft[path]))}>
                Undo
              </button>
            </Show>
          </span>
        </div>
      </div>
    );
  };

  return (
    <div class="stack settings" classList={{ dirty: changed().length > 0 }}>
      <div class="toolbar">
        <input type="search" placeholder="Find an option" aria-label="Find an option" value={filter()} onInput={(event) => setFilter(event.currentTarget.value)} />
        <button type="button" class="quiet" aria-pressed={raw()} onClick={() => setRaw(!raw())}>
          {raw() ? "Show form" : "Show TOML"}
        </button>
      </div>

      <Show
        when={!raw()}
        fallback={
          <section class="panel">
            <pre class="toml">{config() ? toToml(config()!.desired ?? config()!.active ?? {}) : "Loading…"}</pre>
          </section>
        }
      >
        <Show when={modes().length}>
          <section class="panel settings-group">
            <h2>Modes</h2>
            <For each={modes()}>
              {(option) => (
                <div class="row" classList={{ edited: option.path in pending }}>
                  <div class="label">
                    <b>{words(option.path)}</b>
                    <code>{option.path}</code>
                    <p>{option.doc}</p>
                  </div>
                  <div class="control">
                    <Segmented
                      label={option.path}
                      values={option.values}
                      value={option.path in pending ? pending[option.path] : (configured(option.path) ?? option.default)}
                      onChange={(value) => edit(option.path, value)}
                    />
                    <Applies option={option} />
                  </div>
                </div>
              )}
            </For>
          </section>
        </Show>

        <For each={sections()}>
          {([section, options]) => (
            <details class="panel settings-group" open={filter().trim() !== "" || section === "node" || section === "tun"}>
              <summary>
                <h2>{words(section)}</h2>
                <span class="count">{options.length}</span>
              </summary>
              <For each={options}>{(option) => <Row option={option} />}</For>
            </details>
          )}
        </For>
        <Show when={schema().length && !visible().length}>
          <p class="empty">No option matches.</p>
        </Show>
      </Show>

      <Show when={changed().length}>
        <div class="savebar" role="region" aria-label="Unsaved changes">
          <span>
            {changed().length} unsaved {changed().length === 1 ? "change" : "changes"}
          </span>
          <button type="button" class="link" onClick={discard} disabled={busy()}>
            Discard
          </button>
          <button type="button" class="primary" onClick={save} disabled={busy()}>
            {busy() ? "Applying…" : "Apply"}
          </button>
        </div>
      </Show>
    </div>
  );
}
