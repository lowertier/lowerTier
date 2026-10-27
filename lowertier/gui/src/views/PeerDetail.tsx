import { For, Show, createMemo, createSignal } from "solid-js";
import { busy, linkCosts, preferRoute, preferences, setLinkCost } from "../config";
import { bytes, latency, loss, rate, shortKey, NONE } from "../format";
import { history, peerName, peers, selfId, snapshot, tick, type PeerRow } from "../store";
import { Spark } from "../components/controls";
import type { Doc } from "../api";

/** The route row for a peer, matched by key or by final gateway. */
export function routeFor(row: PeerRow): Doc | undefined {
  const routes = (snapshot()?.routes ?? []) as Doc[];
  return routes.find((route) => (route.peer_key && route.peer_key === row.key) || route.final_gateway_peer_id === row.id);
}

export function PathChain(props: { ids: number[]; destination: number }) {
  const hops = () => {
    const ids = props.ids.filter((id) => id !== selfId());
    return ids.length ? ids : [props.destination];
  };
  return (
    <span class="chain">
      <span class="hop self">this node</span>
      <For each={hops()}>
        {(id) => (
          <>
            <span class="arrow" aria-hidden="true">
              <svg viewBox="0 0 12 8" width="12" height="8">
                <path d="M0 4h10M7 1l3 3-3 3" />
              </svg>
            </span>
            <span class="hop">{peerName(id)}</span>
          </>
        )}
      </For>
    </span>
  );
}

export function ViaSelect(props: { row: PeerRow }) {
  const current = () => preferences().find((entry) => entry.peer === props.row.key)?.via ?? "";
  const options = createMemo(() => peers().filter((peer) => peer.key && peer.key !== props.row.key && peer.direct));
  return (
    <select
      aria-label={`Reach ${props.row.name} through`}
      value={current()}
      disabled={busy() || !props.row.key}
      onChange={(event) => preferRoute(props.row.key, event.currentTarget.value || undefined)}
    >
      <option value="">Automatic</option>
      <option value={props.row.key}>Direct</option>
      <For each={options()}>{(peer) => <option value={peer.key}>Through {peer.name}</option>}</For>
    </select>
  );
}

export function OverrideStatus(props: { route?: Doc }) {
  const status = () => props.route?.override_status || "automatic";
  return (
    <span classList={{ status: true, [status()]: true }} title={props.route?.override_inactive_reason || undefined}>
      {status() === "active" ? "Preferred path in use" : status() === "inactive" ? "Preferred path unavailable" : "Automatic"}
    </span>
  );
}

export default function PeerDetail(props: { id: number; onClose: () => void }) {
  const row = () => peers().find((peer) => peer.id === props.id);
  const series = () => {
    tick();
    return history.get(props.id);
  };
  const [bias, setBias] = createSignal<string | null>(null);
  const savedBias = () => (row() ? linkCosts().find((entry) => entry.peer === row()!.key)?.bias_ms : undefined);
  const copy = (text: string) => navigator.clipboard?.writeText(text).catch(() => {});

  return (
    <aside class="detail" aria-label="Peer details">
      <Show when={row()} fallback={<p class="empty">This peer is no longer in the network.</p>}>
        {(peer) => (
          <>
            <header>
              <div>
                <h2>{peer().name}</h2>
                <p class="mono">
                  {peer().address || "no address"} ·{" "}
                  <button type="button" class="link" title="Copy public key" onClick={() => copy(peer().key)}>
                    {shortKey(peer().key)}
                  </button>
                </p>
              </div>
              <button type="button" class="close" aria-label="Close details" onClick={props.onClose}>
                <svg viewBox="0 0 12 12" width="12" height="12">
                  <path d="M2 2l8 8M10 2l-8 8" />
                </svg>
              </button>
            </header>

            <dl class="figures">
              <div>
                <dt>Round trip</dt>
                <dd>{latency(peer().rtt)}</dd>
                <Spark values={series()?.rtt ?? []} />
              </div>
              <div>
                <dt>Loss</dt>
                <dd classList={{ bad: (peer().loss ?? 0) >= 10_000 }}>{loss(peer().loss)}</dd>
              </div>
              <div>
                <dt>In</dt>
                <dd>{rate(peer().rx)}</dd>
                <Spark values={series()?.rx ?? []} class="rx" />
              </div>
              <div>
                <dt>Out</dt>
                <dd>{rate(peer().tx)}</dd>
                <Spark values={series()?.tx ?? []} class="tx" />
              </div>
              <div>
                <dt>Delivery estimate</dt>
                <dd>{rate(peer().delivery)}</dd>
              </div>
              <div>
                <dt>Transferred</dt>
                <dd>
                  {bytes(peer().rxTotal)} in · {bytes(peer().txTotal)} out
                </dd>
              </div>
            </dl>

            <section>
              <h3>Route</h3>
              <p class="path">
                <PathChain ids={peer().hops} destination={peer().id} />
              </p>
              <label class="field">
                <span>Reach through</span>
                <ViaSelect row={peer()} />
              </label>
              <p class="hint">
                <OverrideStatus route={routeFor(peer())} />. Saved as <code>relay.prefer</code>, applies live.
              </p>
              <Show when={peer().direct}>
                <form
                  class="field inline"
                  onSubmit={(event) => {
                    event.preventDefault();
                    const value = Number(bias() ?? savedBias() ?? 0);
                    setLinkCost(peer().key, Number.isFinite(value) && value > 0 ? Math.round(value) : undefined).then(() => setBias(null));
                  }}
                >
                  <label for="bias">Link cost bias</label>
                  <input
                    id="bias"
                    type="number"
                    min="0"
                    step="1"
                    inputmode="numeric"
                    value={bias() ?? String(savedBias() ?? 0)}
                    onInput={(event) => setBias(event.currentTarget.value)}
                  />
                  <span class="unit">ms</span>
                  <button type="submit" disabled={busy() || bias() == null}>
                    Save
                  </button>
                </form>
                <p class="hint">Added to this link's cost when choosing routes. 0 removes the bias.</p>
              </Show>
            </section>

            <section>
              <h3>Connections</h3>
              <Show when={((peer().raw.conns ?? []) as Doc[]).length} fallback={<p class="hint">No direct connection. Traffic is relayed.</p>}>
                <ul class="conns">
                  <For each={(peer().raw.conns ?? []) as Doc[]}>
                    {(conn) => (
                      <li classList={{ closed: conn.is_closed }}>
                        <b>{conn.tunnel?.tunnel_type ?? "?"}</b>
                        <span class="mono">{conn.tunnel?.remote_addr?.url ?? NONE}</span>
                        <span>
                          {latency(conn.stats?.latency_us)} · {conn.is_client ? "outbound" : "inbound"} · {String(conn.secure_auth_level ?? "").replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase()}
                        </span>
                      </li>
                    )}
                  </For>
                </ul>
              </Show>
              <p class="hint">
                NAT {peer().nat || "unknown"} · version {peer().version || "unknown"}
                {peer().secure ? " · end-to-end session ready" : ""}
              </p>
            </section>
          </>
        )}
      </Show>
    </aside>
  );
}
