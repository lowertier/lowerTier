// Every peer as one row, nearest first, with a bar on a log scale of round trip.
import { For, Show } from "solid-js";
import { latency, loss, rate } from "../format";
import { peerName, peers, type PeerRow } from "../store";

// Round trip on a log scale: 0 at 0.1 ms, 1 at 1000 ms.
const LOW = -1;
const HIGH = 3;
const TICKS = [1, 10, 100];

function rttFraction(rttUs: number): number {
  const log = Math.log10(rttUs / 1000);
  return Math.min(1, Math.max(0, (log - LOW) / (HIGH - LOW)));
}

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
