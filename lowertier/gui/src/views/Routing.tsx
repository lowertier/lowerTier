import { For, Index, Show, createMemo, createSignal } from "solid-js";
import { Segmented, Switch } from "../components/controls";
import { apply, busy, configured, preferences, restartPending, say, spec } from "../config";
import { latency, rate } from "../format";
import { peers, snapshot, type PeerRow } from "../store";
import { OverrideStatus, PathChain, ViaSelect, routeFor } from "./PeerDetail";
import type { Doc } from "../api";

const POLICY: Record<string, string> = {
  hop: "Fewest hops.",
  latency: "Lowest measured round trip.",
  goodput: "Highest measured delivery rate. Needs a probe budget.",
};

const TRANSIT: Record<string, string> = {
  allow: "Peers may route their traffic through this node.",
  avoid: "Peers route through this node only when every other path has more avoided nodes.",
  deny: "This node never carries traffic for other peers. It stays reachable.",
};

function Applies(props: { path: string }) {
  return (
    <span class="applies" classList={{ pending: restartPending(props.path) }}>
      {restartPending(props.path) ? "restart pending" : spec(props.path)?.apply ?? ""}
    </span>
  );
}

export default function Routing(props: { onOpenPeer: (id: number) => void }) {
  const policy = () => configured("relay.policy") ?? "hop";
  const transit = () => configured("relay.transit") ?? "allow";
  const budget = () => configured("relay.probe_budget_bps");
  const [budgetText, setBudgetText] = createSignal("");

  const routed = createMemo(() =>
    peers().map((row) => ({ row, route: routeFor(row) })),
  );
  const extraRoutes = createMemo(() =>
    ((snapshot()?.routes ?? []) as Doc[]).filter((route) => route.destination && route.destination.includes("/")),
  );

  const exits = () => (configured("routes.exit_nodes") ?? []) as string[];
  const exitCandidates = createMemo(() => peers().filter((row) => row.address && !exits().includes(row.address)));
  const nameOf = (address: string) => peers().find((row) => row.address === address)?.name;
  const moveExit = (index: number, step: number) => {
    const next = [...exits()];
    const [item] = next.splice(index, 1);
    next.splice(index + step, 0, item);
    apply({ "routes.exit_nodes": next });
  };

  return (
    <div class="stack">
      <section class="panel settings-group">
        <h2>Path selection</h2>
        <div class="row">
          <div class="label">
            <b>Route by</b>
            <p>{POLICY[policy()] ?? ""}</p>
          </div>
          <div class="control">
            <Segmented
              label="Route policy"
              values={["hop", "latency", "goodput"]}
              value={policy()}
              disabled={busy()}
              onChange={(value) => {
                if (value === "goodput" && !budget()) {
                  apply({ "relay.policy": value, "relay.probe_budget_bps": "2Mbit" });
                } else apply({ "relay.policy": value });
              }}
            />
            <Applies path="relay.policy" />
          </div>
        </div>
        <Show when={policy() === "goodput"}>
          <form
            class="row"
            onSubmit={(event) => {
              event.preventDefault();
              if (budgetText().trim()) apply({ "relay.probe_budget_bps": budgetText().trim() }).then((ok) => ok && setBudgetText(""));
            }}
          >
            <div class="label">
              <b>Probe budget</b>
              <p>Bandwidth spent measuring paths. Current {rate(budget())}.</p>
            </div>
            <div class="control">
              <input type="text" placeholder="2Mbit" aria-label="Probe budget" value={budgetText()} onInput={(event) => setBudgetText(event.currentTarget.value)} />
              <button type="submit" disabled={busy() || !budgetText().trim()}>
                Save
              </button>
            </div>
          </form>
        </Show>
        <div class="row">
          <div class="label">
            <b>Use relays</b>
            <p>Send this node's traffic through other peers when there is no direct path.</p>
          </div>
          <div class="control">
            <Switch
              label="Use relays"
              checked={configured("relay.use_relays") ?? true}
              disabled={busy()}
              onChange={(value) => {
                const relayed = preferences().filter((entry) => entry.via !== entry.peer);
                if (!value && relayed.length) {
                  say(`First set ${relayed.length === 1 ? "the route that goes" : `the ${relayed.length} routes that go`} through another peer back to Automatic or Direct.`, true);
                  return;
                }
                apply({ "relay.use_relays": value });
              }}
            />
            <Applies path="relay.use_relays" />
          </div>
        </div>
        <div class="row">
          <div class="label">
            <b>Carry traffic for others</b>
            <p>{TRANSIT[transit()] ?? ""}</p>
          </div>
          <div class="control">
            <Segmented label="Transit" values={["allow", "avoid", "deny"]} value={transit()} disabled={busy()} onChange={(value) => apply({ "relay.transit": value })} />
            <Applies path="relay.transit" />
          </div>
        </div>
      </section>

      <section class="panel">
        <header class="panel-head">
          <h2>Routes to peers</h2>
          <p class="hint">Choose a first hop for any peer. Unavailable choices fall back to automatic routing.</p>
        </header>
        <div class="table-wrap">
          <table class="routes">
            <thead>
              <tr>
                <th scope="col">Destination</th>
                <th scope="col">Current path</th>
                <th scope="col" class="num">Cost</th>
                <th scope="col">Override</th>
                <th scope="col">Reach through</th>
              </tr>
            </thead>
            <tbody>
              <Index each={routed()}>
                {(item) => (
                  <tr>
                    <td>
                      <button type="button" class="link" onClick={() => props.onOpenPeer(item().row.id)}>
                        {item().row.name}
                      </button>
                      <span class="mono sub">{item().row.address}</span>
                    </td>
                    <td>
                      <PathChain ids={item().route?.path_peer_ids ?? item().row.hops} destination={item().row.id} />
                      <Show when={item().route?.path_error}>
                        <span class="sub bad">{item().route!.path_error}</span>
                      </Show>
                    </td>
                    <td class="num">
                      {item().route?.measured_rtt_us != null
                        ? latency(item().route!.measured_rtt_us)
                        : item().route?.cost_ms != null
                          ? `${item().route!.cost_ms} ms`
                          : latency(item().row.rtt)}
                    </td>
                    <td>
                      <OverrideStatus route={item().route} />
                    </td>
                    <td>
                      <ViaSelect row={item().row} />
                    </td>
                  </tr>
                )}
              </Index>
            </tbody>
          </table>
          <Show when={!peers().length}>
            <p class="empty">No peers to route to yet.</p>
          </Show>
        </div>
        <Show when={extraRoutes().length}>
          <h3>Subnet routes</h3>
          <ul class="plain">
            <For each={extraRoutes()}>
              {(route) => (
                <li>
                  <span class="mono">{route.destination}</span> <PathChain ids={route.path_peer_ids ?? []} destination={route.final_gateway_peer_id} />
                </li>
              )}
            </For>
          </ul>
        </Show>
      </section>

      <section class="panel settings-group">
        <h2>Internet exit</h2>
        <div class="row">
          <div class="label">
            <b>Exit nodes</b>
            <p>Send internet traffic through these peers, first available wins.</p>
          </div>
          <div class="control column">
            <Show when={!exits().length}>
              <p class="hint">None. Internet traffic leaves from this machine.</p>
            </Show>
            <ol class="exits">
              <For each={exits()}>
                {(address, index) => (
                  <li>
                    <span>
                      {nameOf(address) ?? "unknown peer"} <span class="mono sub">{address}</span>
                    </span>
                    <span class="actions">
                      <button type="button" disabled={busy() || index() === 0} onClick={() => moveExit(index(), -1)} aria-label={`Move ${address} up`}>
                        Up
                      </button>
                      <button type="button" disabled={busy()} onClick={() => apply({ "routes.exit_nodes": exits().length > 1 ? exits().filter((item) => item !== address) : null })} aria-label={`Remove ${address}`}>
                        Remove
                      </button>
                    </span>
                  </li>
                )}
              </For>
            </ol>
            <select
              aria-label="Add an exit node"
              disabled={busy() || !exitCandidates().length}
              value=""
              onChange={(event) => {
                const address = event.currentTarget.value;
                event.currentTarget.value = "";
                if (address) apply({ "routes.exit_nodes": [...exits(), address] });
              }}
            >
              <option value="">{exitCandidates().length ? "Add an exit node" : "No other peer to add"}</option>
              <For each={exitCandidates()}>{(row: PeerRow) => <option value={row.address}>{row.name} ({row.address})</option>}</For>
            </select>
            <Applies path="routes.exit_nodes" />
          </div>
        </div>
        <div class="row">
          <div class="label">
            <b>Serve as exit</b>
            <p>Let peers send internet traffic out through this node.</p>
          </div>
          <div class="control">
            <Switch label="Serve as exit" checked={configured("routes.serve_exit") ?? false} disabled={busy()} onChange={(value) => apply({ "routes.serve_exit": value })} />
            <Applies path="routes.serve_exit" />
          </div>
        </div>
      </section>
    </div>
  );
}
