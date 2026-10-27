import { For, Show, createSignal } from "solid-js";
import { busy, linkCosts, pathsConfigured, savePaths, setLinkCost, type PathConfig } from "../config";
import { PathStatusView, ViaEditor } from "../components/paths";
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

/** Index of the configured [[path]] whose destination is this peer, or -1. */
export function pathIndexFor(row: PeerRow): number {
  const address = row.address.split("/")[0];
  return pathsConfigured().findIndex((path) => path.to === row.key || (address !== "" && path.to === address));
}

export function pathStatusFor(index: number): Doc | undefined {
  return ((snapshot()?.paths ?? []) as Doc[]).find((status) => status.index === index);
}

/** Edit the waypoints that traffic from this node to `row` passes through. */
export function PeerPath(props: { row: PeerRow }) {
  const index = () => pathIndexFor(props.row);
  const configuredPath = () => (index() >= 0 ? pathsConfigured()[index()] : undefined);
  const [draft, setDraft] = createSignal<string[] | null>(null);
  const [strict, setStrict] = createSignal<boolean | null>(null);
  const via = () => draft() ?? configuredPath()?.via ?? [];
  const isStrict = () => strict() ?? configuredPath()?.strict ?? false;
  const dirty = () => draft() !== null || strict() !== null;
  const save = async () => {
    const paths = pathsConfigured();
    const entry: PathConfig = { to: configuredPath()?.to ?? props.row.key, via: via(), strict: isStrict() };
    if (index() >= 0) {
      if (via().length) paths[index()] = entry;
      else paths.splice(index(), 1);
    } else if (via().length) {
      paths.push(entry);
    }
    if (await savePaths(paths)) {
      setDraft(null);
      setStrict(null);
    }
  };
  return (
    <div class="peer-path">
      <ViaEditor value={via()} exclude={[props.row.key]} onChange={setDraft} disabled={busy() || !props.row.key} />
      <Show when={via().length}>
        <label class="check">
          <input type="checkbox" checked={isStrict()} onChange={(event) => setStrict(event.currentTarget.checked)} /> Strict: drop traffic instead of falling back
        </label>
      </Show>
      <Show when={dirty()}>
        <div class="row-actions">
          <button type="button" class="primary" disabled={busy()} onClick={save}>
            Save path
          </button>
          <button
            type="button"
            class="link"
            onClick={() => {
              setDraft(null);
              setStrict(null);
            }}
          >
            Discard
          </button>
        </div>
      </Show>
      <p class="hint">
        {via().length
          ? "Waypoints are visited in order. A group sends each flow to one member."
          : "Automatic routing. Add waypoints to steer this node's traffic through chosen peers or groups."}{" "}
        Saved as <code>[[path]]</code>, applies live.
      </p>
      <PathStatusView status={index() >= 0 && !dirty() ? pathStatusFor(index()) : undefined} />
    </div>
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
              <h3>Automatic route</h3>
              <p class="path">
                <PathChain ids={peer().hops} destination={peer().id} />
              </p>
              <h3>Path from this node</h3>
              <PeerPath row={peer()} />
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
