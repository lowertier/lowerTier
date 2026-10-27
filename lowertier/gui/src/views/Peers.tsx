import { Index, Show, createMemo, createSignal } from "solid-js";
import { Spark } from "../components/controls";
import { latency, loss, rate } from "../format";
import { history, peerName, peers, tick } from "../store";
import PeerDetail from "./PeerDetail";

type Sort = "name" | "rtt" | "loss" | "rx" | "tx";

export default function Peers(props: { selected?: number; onSelect: (id?: number) => void }) {
  const [filter, setFilter] = createSignal("");
  const [sort, setSort] = createSignal<Sort>("name");
  const rows = createMemo(() => {
    const text = filter().trim().toLowerCase();
    const found = peers().filter((row) => !text || `${row.name} ${row.address} ${row.transport}`.toLowerCase().includes(text));
    const key = sort();
    if (key === "name") return found;
    const value = (row: (typeof found)[number]) => (key === "rtt" ? row.rtt : key === "loss" ? row.loss : row[key]) ?? -1;
    return [...found].sort((a, b) => (key === "rtt" ? value(a) - value(b) : value(b) - value(a)));
  });
  const header = (key: Sort, label: string, numeric = true) => (
    <th scope="col" classList={{ num: numeric }} aria-sort={sort() === key ? (key === "name" || key === "rtt" ? "ascending" : "descending") : "none"}>
      <button type="button" onClick={() => setSort(key)}>
        {label}
      </button>
    </th>
  );

  return (
    <div class="with-detail" classList={{ open: props.selected != null }}>
      <section class="panel">
        <header class="panel-head">
          <h2>{peers().length} peers</h2>
          <input type="search" placeholder="Filter by name, address, transport" aria-label="Filter peers" value={filter()} onInput={(event) => setFilter(event.currentTarget.value)} />
        </header>
        <div class="table-wrap">
          <table class="peers">
            <thead>
              <tr>
                {header("name", "Peer", false)}
                <th scope="col">Path</th>
                {header("rtt", "Round trip")}
                {header("loss", "Loss")}
                {header("rx", "In")}
                {header("tx", "Out")}
              </tr>
            </thead>
            <tbody>
              <Index each={rows()}>
                {(row) => (
                  <tr
                    classList={{ selected: props.selected === row().id }}
                    tabindex="0"
                    onClick={() => props.onSelect(props.selected === row().id ? undefined : row().id)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") props.onSelect(row().id);
                    }}
                  >
                    <td>
                      <b>{row().name}</b>
                      <span class="mono sub">{row().address}</span>
                    </td>
                    <td>
                      <Show when={row().via == null} fallback={<span class="relayed">through {peerName(row().via!)}</span>}>
                        direct <span class="sub">{row().transport}</span>
                      </Show>
                    </td>
                    <td class="num">
                      {latency(row().rtt)}
                      <Spark values={(tick(), history.get(row().id)?.rtt ?? [])} />
                    </td>
                    <td class="num" classList={{ bad: (row().loss ?? 0) >= 10_000 }}>
                      {loss(row().loss)}
                    </td>
                    <td class="num">{rate(row().rx)}</td>
                    <td class="num">{rate(row().tx)}</td>
                  </tr>
                )}
              </Index>
            </tbody>
          </table>
          <Show when={!rows().length}>
            <p class="empty">{peers().length ? "No peer matches the filter." : "No peers yet."}</p>
          </Show>
        </div>
      </section>
      <Show when={props.selected != null}>
        <PeerDetail id={props.selected!} onClose={() => props.onSelect(undefined)} />
      </Show>
    </div>
  );
}
