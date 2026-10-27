import { Show, createMemo, createSignal } from "solid-js";
import Chart from "../components/Chart";
import PeerMap from "../components/PeerMap";
import { bytes, latency, loss, rate, NONE } from "../format";
import { peerById, peers, snapshot } from "../store";

export default function Overview(props: { onOpenPeer: (id: number) => void }) {
  const [selected, setSelected] = createSignal<number>();
  const node = () => snapshot()?.node?.node ?? {};
  const counts = createMemo(() => {
    const rows = peers();
    const direct = rows.filter((row) => row.via == null).length;
    const rtts = rows.flatMap((row) => (row.rtt != null ? [row.rtt] : [])).sort((a, b) => a - b);
    const worst = rows.reduce<(typeof rows)[number] | undefined>((found, row) => ((row.loss ?? -1) > (found?.loss ?? -1) ? row : found), undefined);
    return { direct, relayed: rows.length - direct, median: rtts[Math.floor(rtts.length / 2)], worst };
  });
  const picked = () => peerById(selected());

  return (
    <div class="overview">
      <section class="panel map-panel">
        <header class="panel-head">
          <h2>Peers by round trip</h2>
          <ul class="legend" aria-label="Legend">
            <li class="direct">direct</li>
            <li class="relayed">relayed</li>
            <li class="lossy">over 1% loss</li>
          </ul>
        </header>
        <PeerMap selected={selected()} onSelect={setSelected} />
        <Show when={snapshot() && !peers().length}>
          <p class="map-empty">No peers yet. Add one under Settings, peer, or wait for discovery.</p>
        </Show>
        <Show when={picked()}>
          {(row) => (
            <div class="map-card">
              <b>{row().name}</b>
              <span class="mono">{row().address}</span>
              <span>
                {latency(row().rtt)} · {loss(row().loss)} loss · {rate(row().rx)} in · {rate(row().tx)} out
              </span>
              <button type="button" onClick={() => props.onOpenPeer(row().id)}>
                Details and routing
              </button>
            </div>
          )}
        </Show>
      </section>

      <div class="side">
        <section class="panel">
          <Chart />
        </section>

        <section class="panel">
          <dl class="figures">
            <div>
              <dt>Peers</dt>
              <dd>
                {counts().direct} direct · {counts().relayed} relayed
              </dd>
            </div>
            <div>
              <dt>Median round trip</dt>
              <dd>{latency(counts().median)}</dd>
            </div>
            <div>
              <dt>Highest loss</dt>
              <dd classList={{ bad: (counts().worst?.loss ?? 0) >= 10_000 }}>
                {counts().worst?.loss != null ? `${loss(counts().worst!.loss)}${counts().worst!.loss! > 0 ? ` ${counts().worst!.name}` : ""}` : NONE}
              </dd>
            </div>
            <div>
              <dt>Relayed for others</dt>
              <dd>{bytes(snapshot()?.relay?.total_bytes)}</dd>
            </div>
          </dl>
        </section>

        <section class="panel">
          <dl class="facts">
            <dt>Virtual IP</dt>
            <dd class="mono">{node().ipv4_addr || NONE}</dd>
            <dt>NAT</dt>
            <dd>
              UDP {node().stun_info?.udp_nat_type ?? "unknown"} · TCP {node().stun_info?.tcp_nat_type ?? "unknown"}
            </dd>
            <dt>Public IP</dt>
            <dd class="mono">{(node().stun_info?.public_ip ?? []).join(", ") || NONE}</dd>
            <dt>Listening</dt>
            <dd class="mono">{(node().listeners ?? []).join("\n") || NONE}</dd>
            <dt>Route policy</dt>
            <dd>{snapshot()?.active_policy ?? NONE}</dd>
            <dt>Version</dt>
            <dd>{node().version || NONE}</dd>
          </dl>
        </section>
      </div>
    </div>
  );
}
