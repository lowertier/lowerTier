import { Index, Show, createMemo, createSignal } from "solid-js";
import { Copy, Menu, Segmented, Spark, copyText } from "../components/controls";
import { LinkGlyph, MoreGlyph } from "../components/icons";
import { configured, say } from "../config";
import { ago, latency, loss, rate, NONE } from "../format";
import { noteFor } from "../notes";
import { olderVersion } from "../peerIssues";
import { history, machines, now, peerName, peers, restart, selectRemote, snapshot, tick, type PeerRow } from "../store";
import { rpc } from "../api";
import { retentionLabel } from "../retention";
import MachineRetention from "./MachineRetention";

export const SELF = -1;
const LOSSY = 10_000;
const FILTERS = ["all", "direct", "relayed", "offline", "attention"] as const;
type Filter = (typeof FILTERS)[number];
const FILTER_LABEL: Record<Filter, string> = { all: "All", direct: "Direct", relayed: "Relayed", offline: "Offline", attention: "Attention" };

type Sort = "name" | "rtt" | "traffic";

function median(values: number[]): number | undefined {
  if (!values.length) return undefined;
  const sorted = [...values].sort((a, b) => a - b);
  return sorted[Math.floor(sorted.length / 2)];
}

export const bareAddress = (address: string) => address.split("/")[0];

export default function Machines(props: {
  selected?: number;
  onSelect: (id?: number) => void;
  onEdit: (id: number, field: "name" | "text") => void;
  onAdd: () => void;
}) {
  const [query, setQuery] = createSignal("");
  const [filter, setFilter] = createSignal<Filter>("all");
  const [sort, setSort] = createSignal<Sort>("name");
  const [retention, setRetention] = createSignal<PeerRow>();
  const node = () => snapshot()?.node?.node ?? {};
  const localVersion = () => node().version ?? "";
  const attention = (row: PeerRow) => !row.direct || olderVersion(row.version, localVersion()) || (row.loss ?? 0) >= LOSSY;

  const rows = createMemo(() => {
    const text = query().trim().toLowerCase();
    const found = machines().filter((row) => {
      if (filter() === "direct" && !row.direct) return false;
      if (filter() === "relayed" && (!row.online || row.direct)) return false;
      if (filter() === "offline" && row.online) return false;
      if (filter() === "attention" && !attention(row)) return false;
      const note = noteFor(row.key)?.text ?? "";
      return !text || `${row.name} ${row.hostname} ${row.address} ${row.transport} ${row.version} ${note}`.toLowerCase().includes(text);
    });
    if (sort() === "rtt") return [...found].sort((a, b) => (a.rtt ?? Infinity) - (b.rtt ?? Infinity));
    if (sort() === "traffic") return [...found].sort((a, b) => b.rx + b.tx - (a.rx + a.tx));
    return [...found].sort((a, b) => a.name.localeCompare(b.name));
  });
  const showSelf = () => {
    const text = query().trim().toLowerCase();
    return filter() === "all" && (!text || `${node().hostname ?? ""} ${node().ipv4_addr ?? ""}`.toLowerCase().includes(text));
  };
  const direct = () => peers().filter((row) => row.direct).length;
  const needing = () => machines().filter(attention).length;
  const totalIn = () => peers().reduce((sum, row) => sum + row.rx, 0);
  const totalOut = () => peers().reduce((sum, row) => sum + row.tx, 0);
  const mid = () => median(peers().flatMap((row) => (row.rtt != null ? [row.rtt] : [])));

  const sortHeader = (key: Sort, label: string, numeric = false) => (
    <th scope="col" classList={{ num: numeric }} aria-sort={sort() === key ? (key === "traffic" ? "descending" : "ascending") : "none"}>
      <button type="button" class="sort" onClick={() => setSort(key)}>
        {label}
      </button>
    </th>
  );

  const open = (id: number) => props.onSelect(props.selected === id ? undefined : id);
  const rowKeys = (id: number) => (event: KeyboardEvent) => {
    if (event.target !== event.currentTarget) return;
    if (event.key === "Enter" || event.key === " ") {
      event.preventDefault();
      open(id);
    }
  };
  const copy = (text: string, what: string) => copyText(text).then((done) => say(done ? `Copied ${what}.` : `Could not copy ${what}.`, !done));
  const selfKey = () => (configured("identity.public_key") as string | undefined) ?? "";
  const forget = async (row: PeerRow) => {
    try {
      await rpc("ForgetMachine", { id: row.machineId });
      if (props.selected === row.id) props.onSelect(undefined);
      say(`Removed the offline record for ${row.name}.`);
      restart();
    } catch (error) {
      say(error instanceof Error ? error.message : String(error), true);
    }
  };

  return (
    <div class="machines">
      <dl class="summary" aria-label="Network summary">
        <div>
          <dt>Machines</dt>
          <dd>{snapshot() ? machines().length + 1 : NONE}<span class="of"> · {machines().filter((row) => !row.online).length} offline</span></dd>
        </div>
        <div>
          <dt>Direct</dt>
          <dd>
            {direct()}
            <span class="of"> of {peers().length}</span>
          </dd>
        </div>
        <div>
          <dt>Median round trip</dt>
          <dd>{latency(mid())}</dd>
        </div>
        <div>
          <dt>Traffic</dt>
          <dd>
            {rate(totalIn())} <span class="of">in</span> · {rate(totalOut())} <span class="of">out</span>
          </dd>
        </div>
        <div classList={{ warn: needing() > 0 }}>
          <dt>Needs attention</dt>
          <dd>
            <Show when={needing()} fallback={"None"}>
              <button type="button" class="link" onClick={() => setFilter("attention")}>
                {needing()} {needing() === 1 ? "machine" : "machines"}
              </button>
            </Show>
          </dd>
        </div>
      </dl>

      <div class="toolbar">
        <input type="search" class="search" placeholder="Search by name, address, note, version" aria-label="Search machines" value={query()} onInput={(event) => setQuery(event.currentTarget.value)} />
        <Segmented label="Show" values={FILTERS.map((value) => FILTER_LABEL[value])} value={FILTER_LABEL[filter()]} onChange={(label) => setFilter(FILTERS.find((value) => FILTER_LABEL[value] === label) ?? "all")} />
        <span class="spacer" />
        <button type="button" class="primary" onClick={props.onAdd}>
          Add machine
        </button>
      </div>

      <div class="table-wrap">
        <table class="machine-table">
          <thead>
            <tr>
              {sortHeader("name", "Machine")}
              <th scope="col">Address</th>
              <th scope="col">Connection</th>
              {sortHeader("rtt", "Round trip", true)}
              {sortHeader("traffic", "Traffic", true)}
              <th scope="col">Version</th>
              <th scope="col">Last online</th>
              <th scope="col">
                <span class="sr-only">Actions</span>
              </th>
            </tr>
          </thead>
          <tbody>
            <Show when={showSelf() && snapshot()}>
              <tr class="self" classList={{ selected: props.selected === SELF }} tabindex="0" onClick={() => open(SELF)} onKeyDown={rowKeys(SELF)}>
                <td>
                  <div class="who">
                    <b>{node().hostname || "This machine"}</b>
                    <span class="sub">This machine</span>
                  </div>
                </td>
                <td>
                  <Show when={node().ipv4_addr} fallback={<span class="sub">no address</span>}>
                    <Copy text={bareAddress(node().ipv4_addr)} label="Copy this machine's address" class="address">
                      <span class="mono">{bareAddress(node().ipv4_addr)}</span>
                    </Copy>
                  </Show>
                </td>
                <td>
                  <span class="link-cell">
                    <LinkGlyph kind="self" />
                    <span>{(node().listeners ?? []).length} listeners</span>
                  </span>
                </td>
                <td class="num sub">{NONE}</td>
                <td class="num">
                  <span class="traffic">
                    {rate(totalIn())}
                    <span class="sub">{rate(totalOut())}</span>
                  </span>
                </td>
                <td class="mono-ish">{node().version || NONE}</td>
                <td>Online</td>
                <td class="actions">
                  <Menu
                    label="Actions for this machine"
                    items={[
                      { label: "Rename machine…", onSelect: () => props.onEdit(SELF, "name") },
                      { label: "Copy address", onSelect: () => copy(bareAddress(node().ipv4_addr ?? ""), "the address"), disabled: !node().ipv4_addr },
                      { label: "Copy public key", onSelect: () => copy(selfKey(), "the public key"), disabled: !selfKey() },
                      { label: "Add another machine…", onSelect: props.onAdd },
                    ]}
                  >
                    <MoreGlyph />
                  </Menu>
                </td>
              </tr>
            </Show>
            <Index each={rows()}>
              {(row) => {
                const note = () => noteFor(row().key);
                const older = () => olderVersion(row().version, localVersion());
                return (
                  <tr classList={{ selected: props.selected === row().id, offline: !row().online }} tabindex="0" onClick={() => open(row().id)} onKeyDown={rowKeys(row().id)}>
                    <td>
                      <div class="who">
                        <b>{row().name}</b>
                        <span class="sub">{retentionLabel(row().retention)}</span>
                        <Show when={row().name !== row().hostname}>
                          <span class="sub">{row().hostname}</span>
                        </Show>
                        <Show when={note()?.text}>
                          <span class="note" title={note()!.text}>
                            {note()!.text!.split("\n")[0]}
                          </span>
                        </Show>
                      </div>
                    </td>
                    <td>
                      <Show when={row().address} fallback={<span class="sub">no address</span>}>
                        <Copy text={bareAddress(row().address)} label={`Copy the address of ${row().name}`} class="address">
                          <span class="mono">{bareAddress(row().address)}</span>
                        </Copy>
                      </Show>
                    </td>
                    <td>
                      <span class="link-cell" classList={{ relayed: !row().direct }}>
                        <LinkGlyph kind={row().direct ? "direct" : row().via != null ? "relayed" : "down"} />
                        <Show when={row().direct} fallback={<span>{!row().online ? "Offline" : row().via != null ? `via ${peerName(row().via!)}` : "no route"}</span>}>
                          <span>
                            direct <span class="sub">{row().transport}</span>
                          </span>
                        </Show>
                      </span>
                    </td>
                    <td class="num">
                      <span class="rtt">
                        <Spark values={(tick(), history.get(row().id)?.rtt ?? [])} />
                        <span>{latency(row().rtt)}</span>
                      </span>
                      <Show when={(row().loss ?? 0) > 0}>
                        <span class="sub" classList={{ bad: (row().loss ?? 0) >= LOSSY }}>
                          {loss(row().loss)} loss
                        </span>
                      </Show>
                    </td>
                    <td class="num">
                      <span class="traffic">
                        {row().online ? rate(row().rx) : NONE}
                        <span class="sub">{row().online ? rate(row().tx) : NONE}</span>
                      </span>
                    </td>
                    <td classList={{ warn: older() }} title={older() ? "Older than this machine" : undefined}>
                      {row().version || NONE}
                    </td>
                    <td>
                      <Show when={!row().online} fallback="Online">
                        <time dateTime={new Date(row().lastSeen ?? 0).toISOString()} title={new Date(row().lastSeen ?? 0).toLocaleString()}>
                          {ago(Math.max(0, now() - (row().lastSeen ?? now())))} ago
                        </time>
                      </Show>
                    </td>
                    <td class="actions">
                      <Menu
                        label={`Actions for ${row().name}`}
                        items={[
                          { label: "Manage node", onSelect: () => selectRemote(row().key, row().name), disabled: !row().key || !row().online },
                          { label: "Offline retention…", onSelect: () => setRetention(row()), disabled: !row().key },
                          ...(!row().online && row().machineId ? [{ label: "Forget offline record", onSelect: () => forget(row()), danger: true }] : []),
                          { label: "Rename…", onSelect: () => props.onEdit(row().id, "name") },
                          { label: note()?.text ? "Edit note…" : "Add note…", onSelect: () => props.onEdit(row().id, "text") },
                          { label: "Copy address", onSelect: () => copy(bareAddress(row().address), "the address"), disabled: !row().address },
                          { label: "Copy public key", onSelect: () => copy(row().key, "the public key"), disabled: !row().key },
                          { label: "Path and details", onSelect: () => props.onSelect(row().id) },
                        ]}
                      >
                        <MoreGlyph />
                      </Menu>
                    </td>
                  </tr>
                );
              }}
            </Index>
          </tbody>
        </table>
        <Show when={snapshot() && !rows().length && !showSelf()}>
          <p class="empty">No machine matches.</p>
        </Show>
        <Show when={snapshot() && !machines().length && filter() === "all" && !query()}>
          <div class="empty first-run">
            <p>No other machines yet.</p>
            <button type="button" class="link" onClick={props.onAdd}>
              Create a join code
            </button>
          </div>
        </Show>
        <Show when={!snapshot()}>
          <p class="empty">Connecting to the node…</p>
        </Show>
      </div>
      <p class="table-foot">
        Traffic shows received over sent. Offline records show the last time this node observed a route.
      </p>
      <Show when={retention()}>{(row) => <MachineRetention row={row()} onClose={() => setRetention(undefined)} />}</Show>
    </div>
  );
}
