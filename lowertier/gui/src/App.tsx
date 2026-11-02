import { For, Match, Show, Switch, createEffect, createSignal, on } from "solid-js";
import { hasKey, saveKey } from "./api";
import { busy, config, loadConfig, loadSchema, notice, restartInstance } from "./config";
import { ago } from "./format";
import { error, nodes, now, sampledAt, select, selection, snapshot } from "./store";
import Logs from "./views/Logs";
import Overview from "./views/Overview";
import Peers from "./views/Peers";
import Routing from "./views/Routing";
import Settings from "./views/Settings";

const VIEWS = ["overview", "peers", "routing", "settings", "logs"] as const;
type View = (typeof VIEWS)[number];
const TITLES: Record<View, string> = {
  overview: "Overview",
  peers: "Peers",
  routing: "Routing",
  settings: "Settings",
  logs: "Logs",
};

function fromPath(): View {
  const name = location.pathname.replace(/^\/+/, "") as View;
  return VIEWS.includes(name) ? name : "overview";
}

function Mark() {
  // Two nodes on different tiers joined by a stepped path.
  return (
    <svg class="mark" viewBox="0 0 24 16" width="24" height="16" aria-hidden="true">
      <path d="M4 4h7v8h9" />
      <circle cx="4" cy="4" r="2.6" />
      <circle cx="20" cy="12" r="2.6" />
    </svg>
  );
}

export default function App() {
  const [view, setView] = createSignal<View>(fromPath());
  const [peer, setPeer] = createSignal<number>();
  const [confirming, setConfirming] = createSignal(false);
  const go = (next: View) => {
    setView(next);
    history.pushState(null, "", next === "overview" ? "/" : `/${next}`);
  };
  window.addEventListener("popstate", () => setView(fromPath()));
  const openPeer = (id: number) => {
    setPeer(id);
    go("peers");
  };

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
  if (hasKey) loadSchema();

  const node = () => snapshot()?.node?.node;
  const current = () => nodes().find((item) => (selection().node ? item.portal === selection().node : item.default));

  return (
    <Show
      when={hasKey}
      fallback={
        <main class="locked">
          <Mark />
          <form
            onSubmit={(event) => {
              event.preventDefault();
              const value = new FormData(event.currentTarget).get("key");
              if (typeof value === "string" && value.trim()) saveKey(value);
            }}
          >
            <label for="access-key">Access key</label>
            <div class="key-row">
              <input id="access-key" name="key" type="password" autocomplete="off" autofocus spellcheck={false} />
              <button type="submit" class="primary">
                Open
              </button>
            </div>
            <p>
              The key is the content of <code>gui.key</code>, or the address printed by <code>lowertier gui</code>.
            </p>
          </form>
        </main>
      }
    >
      <div class="shell">
        <nav class="rail" aria-label="Sections">
          <div class="brand">
            <Mark />
            <span>lowertier</span>
          </div>

          <div class="target">
            <b>{node()?.hostname || current()?.name || "No node"}</b>
            <span class="mono">{node()?.ipv4_addr || current()?.portal || ""}</span>
            <Show when={nodes().length > 1}>
              <select aria-label="Daemon" value={current()?.portal ?? ""} onChange={(event) => select(event.currentTarget.value, undefined)}>
                <For each={nodes()}>{(item) => <option value={item.portal}>{item.name}</option>}</For>
              </select>
            </Show>
            <Show when={(current()?.instances ?? []).length > 1}>
              <select aria-label="Instance" value={selection().instance ?? snapshot()?.instance ?? ""} onChange={(event) => select(selection().node, event.currentTarget.value)}>
                <For each={current()!.instances as string[]}>{(name) => <option value={name}>{name}</option>}</For>
              </select>
            </Show>
          </div>

          <ul class="nav" style={{ "--index": VIEWS.indexOf(view()) }}>
            <span class="indicator" aria-hidden="true" />
            <For each={VIEWS}>
              {(name) => (
                <li>
                  <a
                    href={name === "overview" ? "/" : `/${name}`}
                    aria-current={view() === name ? "page" : undefined}
                    onClick={(event) => {
                      event.preventDefault();
                      go(name);
                    }}
                  >
                    {TITLES[name]}
                  </a>
                </li>
              )}
            </For>
          </ul>

          <p class="live" classList={{ down: error() != null }}>
            <Show when={!error()} fallback={"Disconnected"}>
              {sampledAt() ? `Updated ${ago(now() - sampledAt())} ago` : "Connecting"}
            </Show>
          </p>
        </nav>

        <main class="content">
          <Show when={error()}>
            {(failure) => (
              <div class="banner" role="alert">
                <b>{failure().code === "offline" ? "lowertier gui is not running." : "The daemon is not answering."}</b> {failure().message} Retrying.
              </div>
            )}
          </Show>
          <Show when={((config()?.restart_fields ?? []) as string[]).length}>
            <div class="banner staged">
              <span>
                <b>Waiting for an instance restart:</b> {(config()!.restart_fields as string[]).join(", ")}.
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
          <h1>{TITLES[view()]}</h1>
          <Switch>
            <Match when={view() === "overview"}>
              <Overview onOpenPeer={openPeer} />
            </Match>
            <Match when={view() === "peers"}>
              <Peers selected={peer()} onSelect={setPeer} />
            </Match>
            <Match when={view() === "routing"}>
              <Routing onOpenPeer={openPeer} />
            </Match>
            <Match when={view() === "settings"}>
              <Settings />
            </Match>
            <Match when={view() === "logs"}>
              <Logs />
            </Match>
          </Switch>
        </main>

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
