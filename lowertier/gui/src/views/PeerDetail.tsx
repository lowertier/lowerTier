import { For, Show, createSignal } from "solid-js";
import { busy, configured, linkCosts, pathsConfigured, savePaths, setLinkCost, type PathConfig } from "../config";
import { PathStatusView, ViaEditor } from "../components/paths";
import Chart from "../components/Chart";
import { bytes, latency, loss, rate, NONE } from "../format";
import { noteFor } from "../notes";
import { history, peerName, peers, selfId, snapshot, tick, type PeerRow } from "../store";
import { Copy, Spark } from "../components/controls";
import { Arrow, CloseGlyph } from "../components/icons";
import { SELF, bareAddress } from "./Machines";
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
      <span class="hop self">this machine</span>
      <For each={hops()}>
        {(id) => (
          <>
            <Arrow />
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

/** Edit the waypoints that traffic from this machine to `row` passes through. */
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
          : "Automatic routing. Add waypoints to steer this machine's traffic through chosen peers or groups."}{" "}
        Saved as <code>[[path]]</code>, applies live.
      </p>
      <PathStatusView status={index() >= 0 && !dirty() ? pathStatusFor(index()) : undefined} />
    </div>
  );
}

function SelfDetail() {
  const node = () => snapshot()?.node?.node ?? {};
  const key = () => (configured("identity.public_key") as string | undefined) ?? "";
  return (
    <>
      <section>
        <h3>Throughput</h3>
        <Chart />
      </section>
      <section>
        <h3>This machine</h3>
        <dl class="facts">
          <dt>Address</dt>
          <dd class="mono">{node().ipv4_addr || NONE}</dd>
          <dt>Public key</dt>
          <dd>
            <Show when={key()} fallback={NONE}>
              <Copy text={key()} label="Copy public key" class="key">
                <span class="mono">{key()}</span>
              </Copy>
            </Show>
          </dd>
          <dt>Public IP</dt>
          <dd class="mono">{(node().stun_info?.public_ip ?? []).join(", ") || NONE}</dd>
          <dt>NAT</dt>
          <dd>
            UDP {node().stun_info?.udp_nat_type ?? "unknown"} · TCP {node().stun_info?.tcp_nat_type ?? "unknown"}
          </dd>
          <dt>Listening</dt>
          <dd class="mono pre">{(node().listeners ?? []).join("\n") || NONE}</dd>
          <dt>Route policy</dt>
          <dd>{snapshot()?.active_policy ?? NONE}</dd>
          <dt>Relayed for others</dt>
          <dd>{bytes(snapshot()?.relay?.total_bytes)}</dd>
          <dt>Version</dt>
          <dd>{node().version || NONE}</dd>
        </dl>
      </section>
    </>
  );
}

export default function PeerDetail(props: { id: number; onClose: () => void; onEdit: (id: number, field: "name" | "text") => void }) {
  const row = () => peers().find((peer) => peer.id === props.id);
  const series = () => {
    tick();
    return history.get(props.id);
  };
  const [bias, setBias] = createSignal<string | null>(null);
  const savedBias = () => (row() ? linkCosts().find((entry) => entry.peer === row()!.key)?.bias_ms : undefined);
  const node = () => snapshot()?.node?.node ?? {};
  const title = () => (props.id === SELF ? node().hostname || "This machine" : row()?.name ?? "Machine");
  const address = () => bareAddress(props.id === SELF ? node().ipv4_addr ?? "" : row()?.address ?? "");

  return (
    <aside class="sheet" aria-label={`${title()} details`}>
      <header class="sheet-head">
        <div>
          <h2>{title()}</h2>
          <p class="sub">
            <Show when={props.id !== SELF && row() && row()!.name !== row()!.hostname}>{row()!.hostname} · </Show>
            <Show when={address()} fallback={"no address"}>
              <span class="mono">{address()}</span>
            </Show>
          </p>
        </div>
        <button type="button" class="icon-button" aria-label="Close details" onClick={props.onClose}>
          <CloseGlyph />
        </button>
      </header>
      <Show when={props.id !== SELF} fallback={<SelfDetail />}>
        <Show when={row()} fallback={<p class="empty">This machine left the network.</p>}>
          {(peer) => (
            <>
              <section class="note-block">
                <Show
                  when={noteFor(peer().key)?.text}
                  fallback={
                    <button type="button" class="link" onClick={() => props.onEdit(peer().id, "text")}>
                      Add a note
                    </button>
                  }
                >
                  <p class="note-text">{noteFor(peer().key)!.text}</p>
                  <button type="button" class="link" onClick={() => props.onEdit(peer().id, "text")}>
                    Edit note
                  </button>
                </Show>
                <button type="button" class="link" onClick={() => props.onEdit(peer().id, "name")}>
                  Rename
                </button>
              </section>

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
                <h3>Path from this machine</h3>
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
                    <input id="bias" type="number" min="0" step="1" inputmode="numeric" value={bias() ?? String(savedBias() ?? 0)} onInput={(event) => setBias(event.currentTarget.value)} />
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
                          <span class="sub">
                            {latency(conn.stats?.latency_us)} · {conn.is_client ? "outbound" : "inbound"} ·{" "}
                            {String(conn.secure_auth_level ?? "").replace(/([a-z])([A-Z])/g, "$1 $2").toLowerCase()}
                          </span>
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
                <dl class="facts">
                  <dt>Public key</dt>
                  <dd>
                    <Copy text={peer().key} label="Copy public key" class="key">
                      <span class="mono">{peer().key}</span>
                    </Copy>
                  </dd>
                  <dt>NAT</dt>
                  <dd>{peer().nat || "unknown"}</dd>
                  <dt>Version</dt>
                  <dd>{peer().version || "unknown"}</dd>
                  <dt>Session</dt>
                  <dd>{peer().secure ? "end-to-end session ready" : "no end-to-end session"}</dd>
                </dl>
              </section>
            </>
          )}
        </Show>
      </Show>
    </aside>
  );
}
