// Every peer as one row, nearest first. The bar uses the radar's log scale for round trip.
import { For, Show } from "solid-js";
import { latency, loss, rate } from "../format";
import { peerName, peers, type PeerRow } from "../store";
import { rttFraction } from "./PeerMap";

const TICKS = [1, 10, 100];

function sorted(rows: PeerRow[]): PeerRow[] {
  const rtt = (row: PeerRow) => (row.rtt != null && row.rtt > 0 ? row.rtt : Infinity);
  return [...rows].sort((a, b) => rtt(a) - rtt(b) || a.name.localeCompare(b.name));
}

export default function PeerList(props: { onOpen: (id: number) => void }) {
  return (
    <ul class="peer-list" aria-label="Peers by round trip">
      <For each={sorted(peers())}>
        {(row) => (
          <li>
            <button
              type="button"
              classList={{ relayed: row.via != null, lossy: (row.loss ?? 0) >= 10_000 }}
              onClick={() => props.onOpen(row.id)}
              aria-label={`${row.name}, ${latency(row.rtt)}`}
            >
              <span class="who">
                <b title={row.name}>{row.name}</b>
                <span class="sub">
                  <Show when={row.via == null} fallback={`through ${peerName(row.via!)}`}>
                    direct {row.transport}
                  </Show>
                  {(row.loss ?? 0) >= 10_000 ? ` · ${loss(row.loss)} loss` : ""}
                  {row.rx + row.tx > 2000 ? ` · ${rate(row.rx + row.tx)}` : ""}
                </span>
              </span>
              <span class="track" aria-hidden="true">
                <For each={TICKS}>{(ms) => <i style={{ left: `${rttFraction(ms * 1000) * 100}%` }} />}</For>
                <Show when={row.rtt != null && row.rtt > 0}>
                  <span class="fill" style={{ width: `${Math.max(1.5, rttFraction(row.rtt!) * 100)}%` }} />
                </Show>
              </span>
              <span class="value">{latency(row.rtt)}</span>
            </button>
          </li>
        )}
      </For>
    </ul>
  );
}
