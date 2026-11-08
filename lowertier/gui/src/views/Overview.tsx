import { Index, Show, createMemo } from "solid-js";
import Chart from "../components/Chart";
import { bytes, latency, loss, rate, NONE } from "../format";
import { issuesOf } from "../peerIssues";
import { peerName, peers, snapshot, type PeerRow } from "../store";

const LOSSY = 10_000; // parts per million: 1%
const SHOWN = 8;
const NAMES = 14;
const BUSY_BPS = 2000;

function median(values: number[]): number | undefined {
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

export default function Overview(props: { onOpenPeer: (id: number) => void; onAllPeers: () => void }) {
  const node = () => snapshot()?.node?.node ?? {};
  const mid = createMemo(() => median(peers().flatMap((row) => (row.rtt != null ? [row.rtt] : []))));
  const issues = createMemo(() => issuesOf(peers(), node().version ?? ""));
  const busiest = createMemo(() =>
    peers()
      .filter((row) => row.rx + row.tx > BUSY_BPS)
      .sort((a, b) => b.rx + b.tx - (a.rx + a.tx))
      .slice(0, 5),
  );
  const worst = createMemo(() => peers().reduce<PeerRow | undefined>((found, row) => ((row.loss ?? -1) > (found?.loss ?? -1) ? row : found), undefined));
  // Peers grouped by the first hop their traffic takes: direct first, then each relay.
  const paths = createMemo(() => {
    const groups = new Map<number, PeerRow[]>();
    for (const row of peers()) groups.set(row.via ?? -1, [...(groups.get(row.via ?? -1) ?? []), row]);
    return [...groups.entries()]
      .map(([via, rows]) => ({ via, rows: rows.sort((a, b) => a.name.localeCompare(b.name)) }))
      .sort((a, b) => (a.via === -1 ? -1 : b.via === -1 ? 1 : b.rows.length - a.rows.length));
  });
  const direct = () => peers().filter((row) => row.direct).length;

  return (
    <div class="overview">
      <div class="main">
        <section class="panel">
          <header class="panel-head">
            <h2>
              <Show when={issues().length} fallback={peers().length || !snapshot() ? "Nothing needs attention" : "No peers yet"}>
                {issues().length} of {peers().length} peers need attention
              </Show>
            </h2>
            <Show when={peers().length}>
              <button type="button" class="link" onClick={props.onAllPeers}>
                All {peers().length} peers
              </button>
            </Show>
          </header>
          <Show
            when={issues().length}
            fallback={
              <p class="hint">
                <Show when={peers().length} fallback={snapshot() ? "Add a peer under Settings, peer, or wait for discovery." : ""}>
                  All peers have direct connections. No older LowTier versions detected.
                </Show>
              </p>
            }
          >
            <ul class="issues">
              <Index each={issues().slice(0, SHOWN)}>
                {(issue) => (
                  <li>
                    <button type="button" class="link" onClick={() => props.onOpenPeer(issue().row.id)}>
                      {issue().row.name}
                    </button>
                    <span class="reason" classList={{ bad: !issue().row.direct }}>
                      {issue().reason}
                    </span>
                  </li>
                )}
              </Index>
            </ul>
            <Show when={issues().length > SHOWN}>
              <p class="hint">
                {issues().length - SHOWN} more on the{" "}
                <button type="button" class="link" onClick={props.onAllPeers}>
                  Peers page
                </button>
                .
              </p>
            </Show>
          </Show>
        </section>

        <section class="panel">
          <Chart />
          <Show when={busiest().length}>
            <h3>Busiest peers</h3>
            <ul class="busiest">
              <Index each={busiest()}>
                {(row) => (
                  <li>
                    <button type="button" class="link" onClick={() => props.onOpenPeer(row().id)}>
                      {row().name}
                    </button>
                    <span>
                      {rate(row().rx)} in · {rate(row().tx)} out
                    </span>
                  </li>
                )}
              </Index>
            </ul>
          </Show>
        </section>
      </div>

      <div class="side">
        <section class="panel">
          <dl class="figures">
            <div>
              <dt>Peers</dt>
              <dd>
                {direct()} of {peers().length} direct
              </dd>
            </div>
            <div>
              <dt>Median round trip</dt>
              <dd>{latency(mid())}</dd>
            </div>
            <div>
              <dt>Highest loss</dt>
              <dd classList={{ bad: (worst()?.loss ?? 0) >= LOSSY }}>
                {worst()?.loss != null ? `${loss(worst()!.loss)}${worst()!.loss! > 0 ? ` ${worst()!.name}` : ""}` : NONE}
              </dd>
            </div>
            <div>
              <dt>Relayed for others</dt>
              <dd>{bytes(snapshot()?.relay?.total_bytes)}</dd>
            </div>
          </dl>
        </section>

        <Show when={peers().length}>
          <section class="panel">
            <h3 class="first">Paths</h3>
            <dl class="paths">
              <Index each={paths()}>
                {(group) => (
                  <>
                    <dt>{group().via === -1 ? "Direct" : `Through ${peerName(group().via)}`}</dt>
                    <dd>
                      <Index each={group().rows.slice(0, NAMES)}>
                        {(row, index) => (
                          <>
                            <button type="button" class="link" onClick={() => props.onOpenPeer(row().id)}>
                              {row().name}
                            </button>
                            {index < Math.min(group().rows.length, NAMES) - 1 ? ", " : ""}
                          </>
                        )}
                      </Index>
                      <Show when={group().rows.length > NAMES}> and {group().rows.length - NAMES} more</Show>
                    </dd>
                  </>
                )}
              </Index>
            </dl>
          </section>
        </Show>

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
