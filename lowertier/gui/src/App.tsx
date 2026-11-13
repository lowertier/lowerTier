import { For, Match, Show, Switch, createEffect, createSignal, on } from "solid-js";
import { hasKey, saveKey } from "./api";
import { Dialog, Segmented } from "./components/controls";
import { Mark } from "./components/icons";
import { THEMES, setTheme, theme, type Theme } from "./theme";
import { busy, config, configured, loadConfig, loadSchema, notice, restartInstance } from "./config";
import { ago } from "./format";
import { error, localPeers, nodes, now, remoteSecret, sampledAt, select, selectRemote, selection, snapshot, updateRemoteSecret } from "./store";
import AddMachine from "./views/AddMachine";
import EditMachine from "./views/EditMachine";
import Logs from "./views/Logs";
import Machines from "./views/Machines";
import PeerDetail from "./views/PeerDetail";
import Routing from "./views/Routing";
import Settings, { PAGES, type Page } from "./views/Settings";

const VIEWS = ["machines", "routes", "logs", "settings"] as const;
type View = (typeof VIEWS)[number];
const TITLES: Record<View, string> = { machines: "Machines", routes: "Routes", logs: "Logs", settings: "Settings" };

interface Place {
  view: View;
  page: Page;
}

function fromPath(): Place {
  const [first, second] = location.pathname.replace(/^\/+/, "").split("/");
  const view = (VIEWS as readonly string[]).includes(first) ? (first as View) : "machines";
  const page = (PAGES as readonly string[]).includes(second) ? (second as Page) : "general";
  return { view, page };
}

const href = (place: Place) => (place.view === "machines" ? "/" : place.view === "settings" ? `/settings/${place.page}` : `/${place.view}`);

function Lock() {
  return (
    <main class="locked">
      <form
        onSubmit={(event) => {
          event.preventDefault();
          const value = new FormData(event.currentTarget).get("key");
          if (typeof value === "string" && value.trim()) saveKey(value);
        }}
      >
        <div class="brand">
          <Mark size={28} />
          <span>lowertier</span>
        </div>
        <label for="access-key">Access key</label>
        <div class="key-row">
          <input id="access-key" name="key" type="password" autocomplete="off" autofocus spellcheck={false} />
          <button type="submit" class="primary">
            Open
          </button>
        </div>
        <p class="hint">
          The key is the content of <code>gui.key</code>, or the address printed by <code>lowertier gui</code>.
        </p>
      </form>
    </main>
  );
}

function RemoteDialog(props: {
  keys: Record<string, string>;
  defaultTarget: string;
  onClose: () => void;
}) {
  const [target, setTarget] = createSignal(selection().remote ?? "");
  const [secret, setSecret] = createSignal(remoteSecret());
  let close: () => void = props.onClose;
  const aliases = () => Object.entries(props.keys).sort(([a], [b]) => a.localeCompare(b));
  const choose = (nextTarget?: string, label?: string) => {
    selectRemote(nextTarget, label, secret());
    close();
  };
  return (
    <Dialog title="Manage another node" onClose={props.onClose}>
      <form
        class="edit-form"
        ref={(form) => {
          close = () => (form.closest("dialog") as HTMLDialogElement | null)?.close();
        }}
        onSubmit={(event) => {
          event.preventDefault();
          choose(target().trim(), target().trim());
        }}
      >
        <p class="hint">
          Control another node over an end-to-end Noise session. The remote node must allow this node&apos;s identity key in <code>control.allow</code> or <code>control.grant</code>, or share a <code>control.secret</code> phrase.
        </p>
        <Show when={selection().remote}>
          <div class="row-actions">
            <button type="button" onClick={() => choose(undefined)}>
              Return to this machine
            </button>
          </div>
        </Show>
        <Show when={localPeers().length}>
          <label class="field">
            <span>Connected peers</span>
            <select
              value={localPeers().some((p) => p.key === target()) ? target() : ""}
              onChange={(event) => {
                const value = event.currentTarget.value;
                if (value) {
                  const peer = localPeers().find((p) => p.key === value);
                  choose(value, peer?.name);
                }
              }}
            >
              <option value="">Pick a peer…</option>
              <For each={localPeers().filter((p) => p.key)}>
                {(peer) => (
                  <option value={peer.key}>
                    {peer.name} ({peer.address || peer.key.slice(0, 12)})
                  </option>
                )}
              </For>
            </select>
          </label>
        </Show>
        <Show when={props.defaultTarget || aliases().length}>
          <label class="field">
            <span>Pinned remote keys (control.keys)</span>
            <select
              value={aliases().some(([alias]) => alias === target()) || target() === "default" ? target() : ""}
              onChange={(event) => {
                const value = event.currentTarget.value;
                if (value) choose(value, value === "default" ? `default (${props.defaultTarget})` : value);
              }}
            >
              <option value="">Pick a configured alias…</option>
              <Show when={props.defaultTarget}>
                <option value="default">default ({props.defaultTarget})</option>
              </Show>
              <For each={aliases()}>{([alias]) => <option value={alias}>{alias}</option>}</For>
            </select>
          </label>
        </Show>
        <label class="field">
          <span>Target alias, key, or &quot;default&quot;</span>
          <input
            type="text"
            value={target()}
            placeholder="node-a, default, or pubkey:..."
            spellcheck={false}
            onInput={(event) => setTarget(event.currentTarget.value)}
          />
        </label>
        <label class="field">
          <span>Control phrase (optional, if remote uses control.secret)</span>
          <input
            type="password"
            value={secret()}
            placeholder="Leave empty when using pinned keys"
            autocomplete="off"
            onInput={(event) => setSecret(event.currentTarget.value)}
          />
        </label>
        <div class="row-actions">
          <button type="submit" class="primary" disabled={!target().trim()}>
            Connect
          </button>
          <Show when={selection().remote && secret() !== remoteSecret()}>
            <button
              type="button"
              onClick={() => {
                updateRemoteSecret(secret());
                close();
              }}
            >
              Update phrase only
            </button>
          </Show>
          <button type="button" class="link" onClick={() => close()}>
            Cancel
          </button>
        </div>
      </form>
    </Dialog>
  );
}

export default function App() {
  const [place, setPlace] = createSignal<Place>(fromPath());
  const [selected, setSelected] = createSignal<number>();
  const [adding, setAdding] = createSignal(false);
  const [editing, setEditing] = createSignal<{ id: number; focus: "name" | "text" } | null>(null);
  const [pickingRemote, setPickingRemote] = createSignal(false);
  const [confirming, setConfirming] = createSignal(false);
  const [localControlKeys, setLocalControlKeys] = createSignal<Record<string, string>>({});
  const [localControlDefault, setLocalControlDefault] = createSignal("");
  const go = (next: Partial<Place>) => {
    const target = { ...place(), ...next };
    setPlace(target);
    history.pushState(null, "", href(target));
    window.scrollTo({ top: 0 });
  };
  window.addEventListener("popstate", () => setPlace(fromPath()));

  // Configuration belongs to the selected daemon: reload it when the daemon or instance changes.
  createEffect(
    on(
      () => [selection(), snapshot()?.instance, snapshot() != null],
      () => {
        if (snapshot()) loadConfig();
      },
      { defer: false },
    ),
  );
  createEffect(on(selection, () => setSelected(undefined), { defer: true }));
  createEffect(() => {
    if (!selection().remote && config()) {
      const keys = configured("control.keys");
      setLocalControlKeys(keys && typeof keys === "object" ? { ...(keys as Record<string, string>) } : {});
      setLocalControlDefault((configured("control.default") as string | undefined) ?? "");
    }
  });
  if (hasKey) loadSchema();

  const node = () => snapshot()?.node?.node;
  const current = () => nodes().find((item) => (selection().node ? item.portal === selection().node : item.default));
  const network = () => (configured("network.name") as string | undefined) ?? "";
  const restartFields = () => (config()?.restart_fields ?? []) as string[];

  return (
    <Show when={hasKey} fallback={<Lock />}>
      <div class="shell" classList={{ "sheet-open": place().view === "machines" && selected() != null }}>
        <header class="top">
          <div class="top-row">
            <a
              class="brand"
              href="/"
              onClick={(event) => {
                event.preventDefault();
                go({ view: "machines" });
              }}
            >
              <Mark />
              <span>lowertier</span>
            </a>
            <Show when={network()}>
              <span class="network" title="Network name">
                {network()}
              </span>
            </Show>
            <span class="spacer" />
            <div class="theme">
              <Segmented label="Theme" values={[...THEMES]} value={theme()} onChange={(value) => setTheme(value as Theme)} />
            </div>
            <div class="target">
              <Show when={!selection().remote && nodes().length > 1}>
                <select aria-label="Daemon" value={current()?.portal ?? ""} onChange={(event) => select(event.currentTarget.value, undefined)}>
                  <For each={nodes()}>{(item) => <option value={item.portal}>{item.name}</option>}</For>
                </select>
              </Show>
              <Show when={!selection().remote && (current()?.instances ?? []).length > 1}>
                <select aria-label="Instance" value={selection().instance ?? snapshot()?.instance ?? ""} onChange={(event) => select(selection().node, event.currentTarget.value)}>
                  <For each={current()!.instances as string[]}>{(name) => <option value={name}>{name}</option>}</For>
                </select>
              </Show>
              <button type="button" onClick={() => setPickingRemote(true)}>
                {selection().remote ? "Switch node…" : "Remote…"}
              </button>
              <span class="where">
                <b>{node()?.hostname || selection().remoteLabel || current()?.name || "No node"}</b>
                <span class="live" classList={{ down: error() != null }}>
                  <Show when={!error()} fallback={"disconnected"}>
                    {sampledAt() ? `${selection().remote ? "remote · " : ""}updated ${ago(now() - sampledAt())} ago` : "connecting"}
                  </Show>
                </span>
              </span>
            </div>
          </div>
          <nav class="tabs" aria-label="Sections" style={{ "--index": VIEWS.indexOf(place().view), "--count": VIEWS.length }}>
            <For each={VIEWS}>
              {(name) => (
                <a
                  href={href({ view: name, page: place().page })}
                  aria-current={place().view === name ? "page" : undefined}
                  onClick={(event) => {
                    event.preventDefault();
                    go({ view: name });
                  }}
                >
                  {TITLES[name]}
                </a>
              )}
            </For>
            <span class="indicator" aria-hidden="true" />
          </nav>
        </header>

        <main class="content">
          <Show when={selection().remote}>
            <div class="banner staged">
              <span>
                <b>Managing remote node:</b> {node()?.hostname || selection().remoteLabel}
              </span>
              <button type="button" class="link" onClick={() => setPickingRemote(true)}>
                Change target
              </button>
              <button type="button" class="primary" onClick={() => selectRemote(undefined)}>
                Return to this machine
              </button>
            </div>
          </Show>
          <Show when={error()}>
            {(failure) => (
              <div class="banner" role="alert">
                <span>
                  <b>
                    {failure().code === "offline"
                      ? "lowertier gui is not running."
                      : selection().remote
                        ? "The remote node is not answering."
                        : "The node is not answering."}
                  </b>{" "}
                  {failure().message} Retrying.
                </span>
                <Show when={selection().remote}>
                  <button type="button" class="link" onClick={() => setPickingRemote(true)}>
                    Set phrase / target
                  </button>
                  <button type="button" onClick={() => selectRemote(undefined)}>
                    Return to this machine
                  </button>
                </Show>
              </div>
            )}
          </Show>
          <Show when={restartFields().length}>
            <div class="banner staged">
              <span>
                <b>Waiting for a restart:</b> {restartFields().join(", ")}.
              </span>
              <button
                type="button"
                class="primary"
                disabled={busy()}
                onClick={() => {
                  if (confirming()) {
                    setConfirming(false);
                    restartInstance();
                  } else setConfirming(true);
                }}
              >
                {confirming() ? "Confirm: peers reconnect" : "Restart instance"}
              </button>
              <Show when={confirming()}>
                <button type="button" class="link" onClick={() => setConfirming(false)}>
                  Cancel
                </button>
              </Show>
            </div>
          </Show>
          <Switch>
            <Match when={place().view === "machines"}>
              <Machines selected={selected()} onSelect={setSelected} onEdit={(id, focus) => setEditing({ id, focus })} onAdd={() => setAdding(true)} />
            </Match>
            <Match when={place().view === "routes"}>
              <Routing
                onOpenPeer={(id) => {
                  setSelected(id);
                  go({ view: "machines" });
                }}
              />
            </Match>
            <Match when={place().view === "settings"}>
              <Settings page={place().page} onPage={(page) => go({ page })} onRouting={() => go({ view: "routes" })} onAddMachine={() => setAdding(true)} />
            </Match>
            <Match when={place().view === "logs"}>
              <Logs />
            </Match>
          </Switch>
        </main>

        <Show when={place().view === "machines" && selected() != null}>
          <PeerDetail id={selected()!} onClose={() => setSelected(undefined)} onEdit={(id, focus) => setEditing({ id, focus })} />
        </Show>
        <Show when={adding()}>
          <AddMachine onClose={() => setAdding(false)} />
        </Show>
        <Show when={editing()}>{(edit) => <EditMachine id={edit().id} focus={edit().focus} onClose={() => setEditing(null)} />}</Show>
        <Show when={pickingRemote()}>
          <RemoteDialog
            keys={localControlKeys()}
            defaultTarget={localControlDefault()}
            onClose={() => setPickingRemote(false)}
          />
        </Show>
        <Show when={notice()}>
          {(message) => (
            <div class="notice" classList={{ bad: message().error }} role="status">
              {message().text}
            </div>
          )}
        </Show>
      </div>
    </Show>
  );
}
