import { For, Index, Show, createMemo, createSignal } from "solid-js";
import { Segmented, Switch } from "../components/controls";
import MeshGraph from "../components/MeshGraph";
import { LayersEditor, PathStatusView, RefSelect, isGroup, refLabel } from "../components/paths";
import {
  apply,
  busy,
  configured,
  exportsConfigured,
  groupsConfigured,
  pathUsesGroup,
  pathsConfigured,
  renameGroupInPath,
  restartPending,
  saveExports,
  saveRouting,
  say,
  spec,
  stageNodes,
  type ExportConfig,
  type GroupConfig,
  type PathConfig,
  type PathStageConfig,
} from "../config";
import { latency, rate } from "../format";
import { peers, snapshot } from "../store";
import { PathChain, pathIndexFor, routeFor, wildcardPathIndex } from "./PeerDetail";
import type { Doc } from "../api";

const POLICY: Record<string, string> = {
  hop: "Fewest hops.",
  latency: "Lowest measured round trip.",
  goodput: "Highest measured delivery rate. Needs speed tests (below).",
};

const TRANSIT: Record<string, string> = {
  allow: "Peers may route their traffic through this machine.",
  avoid: "Peers route through this machine only when every other path has more avoided nodes.",
  deny: "This machine never carries traffic for other peers. It stays reachable.",
};

function Applies(props: { path: string }) {
  return (
    <span class="applies" classList={{ pending: restartPending(props.path) }}>
      {restartPending(props.path) ? "restart pending" : spec(props.path)?.apply ?? ""}
    </span>
  );
}

// Peer keys are base64 and may contain '/': a subnet looks like an address with a prefix length.
const isSubnet = (to: string) => /^[0-9a-fA-F:.]+\/\d{1,3}$/.test(to);

function targetLabel(to: string): string {
  if (to === "*") return "All peers (*)";
  if (to === "internet") return "Internet";
  if (isSubnet(to)) return to;
  return refLabel(to);
}

function stageLabel(stage: PathStageConfig): string {
  return stageNodes(stage).map(refLabel).join(" + ");
}

const pathStatus = (index: number) => ((snapshot()?.paths ?? []) as Doc[]).find((status) => status.index === index);

function Arrow() {
  return (
    <span class="arrow" aria-hidden="true">
      <svg viewBox="0 0 12 8" width="12" height="8">
        <path d="M0 4h10M7 1l3 3-3 3" />
      </svg>
    </span>
  );
}

type TargetKind = "peer" | "any" | "internet" | "subnet";

function PathEditor(props: { initial?: PathConfig; onSave: (path: PathConfig) => void; onCancel: () => void }) {
  const initialKind = (): TargetKind => {
    const to = props.initial?.to;
    if (!to) return "peer";
    if (to === "*") return "any";
    return to === "internet" ? "internet" : isSubnet(to) ? "subnet" : "peer";
  };
  const [kind, setKind] = createSignal<TargetKind>(initialKind());
  const [to, setTo] = createSignal(
    props.initial?.to && initialKind() !== "internet" && initialKind() !== "any" ? props.initial.to : "",
  );
  const [mode, setMode] = createSignal(props.initial?.mode || "parallel");
  const [layers, setLayers] = createSignal<PathStageConfig[]>(props.initial?.layers ?? []);
  const initialGateway = props.initial?.gateway;
  const [gatewayRef, setGatewayRef] = createSignal(stageNodes(initialGateway)[0] ?? "");
  const [strict, setStrict] = createSignal(props.initial?.strict ?? false);
  const target = () => (kind() === "internet" ? "internet" : kind() === "any" ? "*" : to().trim());
  const gatewayValue = (): PathStageConfig | undefined => {
    if (kind() === "peer" || kind() === "any") return undefined;
    const chosen = gatewayRef().trim();
    if (!chosen) return undefined;
    if (initialGateway && stageNodes(initialGateway)[0] === chosen && stageNodes(initialGateway).length > 1) {
      return initialGateway;
    }
    return chosen;
  };
  const problem = () => {
    if (kind() === "internet" && !gatewayValue()) return "Choose the exit gateway.";
    if (!target()) return kind() === "subnet" ? "Enter a CIDR such as 10.8.0.0/16." : "Choose a destination peer.";
    if (kind() === "subnet" && !isSubnet(target())) return "Enter a CIDR such as 10.8.0.0/16.";
    if (kind() !== "internet" && !layers().length && !gatewayValue()) return "Add at least one relay layer.";
    return "";
  };
  return (
    <form
      class="path-editor"
      onSubmit={(event) => {
        event.preventDefault();
        if (problem()) return;
        props.onSave({
          to: target(),
          mode: mode(),
          layers: layers(),
          gateway: gatewayValue(),
          strict: strict(),
        });
      }}
    >
      <div class="editor-row">
        <span class="editor-label">Traffic to</span>
        <div class="editor-control">
          <Segmented label="Destination kind" values={["peer", "any", "internet", "subnet"]} value={kind()} onChange={(value) => setKind(value as TargetKind)} />
          <Show when={kind() === "peer"}>
            <RefSelect label="Destination peer" value={to()} placeholder="Choose a peer" groups={false} onChange={setTo} />
          </Show>
          <Show when={kind() === "any"}>
            <p class="hint">Applies to every peer without its own explicit path rule.</p>
          </Show>
          <Show when={kind() === "subnet"}>
            <input
              type="text"
              list="discovered-subnets"
              placeholder="10.8.0.0/16 or 192.168.1.0/24"
              aria-label="Destination subnet"
              value={to()}
              onInput={(event) => setTo(event.currentTarget.value)}
            />
            <datalist id="discovered-subnets">
              <For each={[...new Set(peers().flatMap((row) => row.subnets))]}>
                {(cidr) => <option value={cidr} />}
              </For>
            </datalist>
          </Show>
        </div>
      </div>
      <div class="editor-row">
        <span class="editor-label">Mode</span>
        <div class="editor-control">
          <Segmented label="Relay mode" values={["parallel", "flow", "failover"]} value={mode()} onChange={setMode} />
          <p class="hint">
            {mode() === "parallel"
              ? "Stripes bursts across relays using live RTT and queue estimates, then reorders at the destination."
              : mode() === "flow"
                ? "Pins each connection to one relay by weighted hash."
                : "Uses the first usable relay chain in order."}
          </p>
        </div>
      </div>
      <div class="editor-row">
        <span class="editor-label">Layers</span>
        <div class="editor-control">
          <LayersEditor value={layers()} exclude={kind() === "peer" && to() ? [to()] : []} onChange={setLayers} />
        </div>
      </div>
      <Show when={kind() === "internet" || kind() === "subnet"}>
        <div class="editor-row">
          <span class="editor-label">{kind() === "internet" ? "Exit at" : "Leave at"}</span>
          <div class="editor-control">
            <RefSelect
              label="Gateway"
              value={gatewayRef()}
              placeholder={kind() === "internet" ? "Choose an exit or exit group" : "Automatic subnet gateway"}
              onChange={setGatewayRef}
            />
            <p class="hint">
              {kind() === "internet"
                ? "Members need routes.serve_exit. Gateways keep per-flow affinity to preserve NAT."
                : "Members must export the subnet or serve as exits."}
            </p>
          </div>
        </div>
      </Show>
      <label class="check">
        <input type="checkbox" checked={strict()} onChange={(event) => setStrict(event.currentTarget.checked)} /> Strict: drop traffic when the path is unusable instead of
        routing automatically
      </label>
      <div class="row-actions">
        <button type="submit" class="primary" disabled={busy() || problem() !== ""}>
          Save path
        </button>
        <button type="button" class="link" onClick={props.onCancel}>
          Cancel
        </button>
        <Show when={problem()}>
          <span class="hint">{problem()}</span>
        </Show>
      </div>
    </form>
  );
}

function GroupEditor(props: { initial?: GroupConfig; onSave: (group: GroupConfig) => void; onCancel: () => void; onDelete?: () => void }) {
  const [name, setName] = createSignal(props.initial?.name ?? "");
  const [nodes, setNodes] = createSignal<string[]>(props.initial?.nodes ?? []);
  const [weights, setWeights] = createSignal<number[]>(props.initial?.weights ?? (props.initial?.nodes ?? []).map(() => 1));
  const [mode, setMode] = createSignal(props.initial?.mode || "parallel");
  const problem = () => {
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(name())) return "Name: 1 to 32 letters, digits, - or _.";
    if (name() === "internet" || name() === "*") return "This name is reserved.";
    if (!nodes().length) return "Add at least one node.";
    return "";
  };
  return (
    <form
      class="path-editor"
      onSubmit={(event) => {
        event.preventDefault();
        if (problem()) return;
        props.onSave({ name: name(), nodes: nodes(), mode: mode(), weights: mode() !== "failover" ? weights() : undefined });
      }}
    >
      <div class="editor-row">
        <span class="editor-label">Name</span>
        <div class="editor-control">
          <input type="text" aria-label="Group name" placeholder="eu-relays" value={name()} onInput={(event) => setName(event.currentTarget.value)} />
        </div>
      </div>
      <div class="editor-row">
        <span class="editor-label">Mode</span>
        <div class="editor-control">
          <Segmented label="Mode" values={["parallel", "flow", "failover"]} value={mode()} onChange={setMode} />
          <p class="hint">
            {mode() === "parallel"
              ? "Aggregates bandwidth across all usable nodes by weight."
              : mode() === "flow"
                ? "Each flow goes to one node, spread by weight. A lost node moves only its own flows."
                : "Everything goes to the first usable node, in this order."}
          </p>
        </div>
      </div>
      <div class="editor-row">
        <span class="editor-label">Nodes</span>
        <div class="editor-control">
          <ol class="via-list">
            <For each={nodes()}>
              {(member, index) => (
                <li>
                  <span>{refLabel(member)}</span>
                  <span class="actions">
                    <Show when={mode() !== "failover"}>
                      <label class="weight">
                        weight
                        <input
                          type="number"
                          min="1"
                          max="1000"
                          aria-label={`Weight of ${refLabel(member)}`}
                          value={weights()[index()] ?? 1}
                          onInput={(event) => {
                            const next = [...weights()];
                            next[index()] = Math.max(1, Math.min(1000, Number(event.currentTarget.value) || 1));
                            setWeights(next);
                          }}
                        />
                      </label>
                    </Show>
                    <button
                      type="button"
                      class="quiet small"
                      aria-label={`Remove ${refLabel(member)}`}
                      onClick={() => {
                        setNodes(nodes().filter((_, at) => at !== index()));
                        setWeights(weights().filter((_, at) => at !== index()));
                      }}
                    >
                      Remove
                    </button>
                  </span>
                </li>
              )}
            </For>
          </ol>
          <RefSelect
            label="Add a node"
            placeholder="Add a peer"
            groups={false}
            exclude={nodes()}
            onChange={(reference) => {
              setNodes([...nodes(), reference]);
              setWeights([...weights(), 1]);
            }}
          />
        </div>
      </div>
      <div class="row-actions">
        <button type="submit" class="primary" disabled={busy() || problem() !== ""}>
          Save group
        </button>
        <button type="button" class="link" onClick={props.onCancel}>
          Cancel
        </button>
        <Show when={props.onDelete}>
          <button type="button" class="link danger" onClick={props.onDelete}>
            Delete group
          </button>
        </Show>
        <Show when={problem()}>
          <span class="hint">{problem()}</span>
        </Show>
      </div>
    </form>
  );
}

function ExportEditor(props: { initial?: ExportConfig; onSave: (entry: ExportConfig) => void; onCancel: () => void }) {
  const [cidr, setCidr] = createSignal(props.initial?.cidr ?? "");
  const [mapped, setMapped] = createSignal(props.initial?.mapped_cidr ?? "");
  const [allow, setAllow] = createSignal((props.initial?.allow ?? []).join(", "));
  const validCidr = (value: string) => /^(\d+\.){3}\d+\/\d+$/.test(value.trim());
  const problem = () => {
    if (!validCidr(cidr())) return "Enter a local subnet CIDR, e.g. 192.168.1.0/24.";
    if (mapped().trim() && !validCidr(mapped())) return "Mapped CIDR must be a valid IPv4 CIDR.";
    return "";
  };
  return (
    <form
      class="path-editor"
      onSubmit={(event) => {
        event.preventDefault();
        if (problem()) return;
        const allowList = allow().split(/[\s,]+/).map((s) => s.trim()).filter(Boolean);
        props.onSave({
          cidr: cidr().trim(),
          mapped_cidr: mapped().trim() || undefined,
          allow: allowList.length ? allowList : undefined,
        });
      }}
    >
      <div class="editor-row">
        <span class="editor-label">Local subnet</span>
        <div class="editor-control">
          <input type="text" placeholder="192.168.1.0/24" aria-label="Local subnet CIDR" value={cidr()} onInput={(e) => setCidr(e.currentTarget.value)} />
        </div>
      </div>
      <div class="editor-row">
        <span class="editor-label">Mapped CIDR</span>
        <div class="editor-control">
          <input type="text" placeholder="Optional (e.g. 10.201.0.0/24 if overlapping)" aria-label="Mapped subnet CIDR" value={mapped()} onInput={(e) => setMapped(e.currentTarget.value)} />
          <p class="hint">Remap overlapping LAN subnets (for example two sites both using 192.168.1.0/24).</p>
        </div>
      </div>
      <div class="editor-row">
        <span class="editor-label">Allow from</span>
        <div class="editor-control">
          <input type="text" placeholder="Optional comma-separated source CIDRs" aria-label="Allowed source CIDRs" value={allow()} onInput={(e) => setAllow(e.currentTarget.value)} />
        </div>
      </div>
      <div class="row-actions">
        <button type="submit" class="primary" disabled={busy() || problem() !== ""}>Save subnet</button>
        <button type="button" class="link" onClick={props.onCancel}>Cancel</button>
        <Show when={problem()}><span class="hint">{problem()}</span></Show>
      </div>
    </form>
  );
}

export default function Routing(props: { onOpenPeer: (id: number) => void }) {
  const policy = () => configured("relay.policy") ?? "hop";
  const transit = () => configured("relay.transit") ?? "allow";
  const p2pMode = () => String(configured("nat.p2p") ?? "on");
  const maxDirect = () => configured("limits.max_direct_peers");
  const [maxDirectText, setMaxDirectText] = createSignal("");
  const budget = () => configured("relay.probe_budget_bps");
  const probeEvery = () => configured("relay.probe_interval_seconds") ?? 30;
  const [budgetText, setBudgetText] = createSignal("");
  // The open path, group, or export editor: an index, "new", or none.
  const [editingPath, setEditingPath] = createSignal<number | "new" | null>(null);
  const [newPathDraft, setNewPathDraft] = createSignal<PathConfig | undefined>(undefined);
  const [editingGroup, setEditingGroup] = createSignal<number | "new" | null>(null);
  const [editingExport, setEditingExport] = createSignal<number | "new" | null>(null);

  const discoveredSubnets = createMemo(() => {
    const out: { cidr: string; peer: string; peerId: number; via?: number; direct: boolean }[] = [];
    for (const row of peers()) {
      for (const cidr of row.subnets) {
        out.push({ cidr, peer: row.name, peerId: row.id, via: row.via, direct: row.direct });
      }
    }
    return out;
  });

  const saveExport = async (index: number | "new", entry: ExportConfig) => {
    const list = exportsConfigured();
    if (index === "new") list.push(entry);
    else list[index] = entry;
    if (await saveExports(list)) setEditingExport(null);
  };
  const deleteExport = (index: number) => {
    const list = exportsConfigured();
    list.splice(index, 1);
    saveExports(list);
  };
  const steerSubnet = (cidr: string) => {
    setNewPathDraft({ to: cidr });
    setEditingPath("new");
  };

  const routed = createMemo(() => peers().map((row) => ({ row, route: routeFor(row) })));
  const extraRoutes = createMemo(() =>
    ((snapshot()?.routes ?? []) as Doc[]).filter((route) => route.destination && route.destination.includes("/")),
  );

  const savePath = async (index: number | "new", path: PathConfig) => {
    const paths = pathsConfigured();
    if (index === "new") paths.push(path);
    else paths[index] = path;
    if (await saveRouting(groupsConfigured(), paths)) setEditingPath(null);
  };
  const deletePath = (index: number) => {
    const paths = pathsConfigured();
    paths.splice(index, 1);
    saveRouting(groupsConfigured(), paths);
  };
  const saveGroup = async (index: number | "new", group: GroupConfig) => {
    const groups = groupsConfigured();
    let paths = pathsConfigured();
    if (groups.some((other, at) => other.name === group.name && at !== index)) {
      say(`A group named ${group.name} already exists.`, true);
      return;
    }
    if (index === "new") groups.push(group);
    else {
      const previous = groups[index].name;
      groups[index] = group;
      if (previous !== group.name) {
        paths = paths.map((path) => renameGroupInPath(path, previous, group.name));
      }
    }
    if (await saveRouting(groups, paths)) setEditingGroup(null);
  };
  const deleteGroup = (index: number) => {
    const groups = groupsConfigured();
    const name = groups[index].name;
    const users = pathsConfigured().filter((path) => pathUsesGroup(path, name));
    if (users.length) {
      say(`${name} is used by ${users.length === 1 ? "a path" : `${users.length} paths`}. Change those paths first.`, true);
      return;
    }
    groups.splice(index, 1);
    saveRouting(groups, pathsConfigured()).then((ok) => ok && setEditingGroup(null));
  };

  return (
    <div class="stack">
      <section class="panel">
        <header class="panel-head">
          <h2>Mesh topology</h2>
          <span class="sub">{peers().filter((p) => p.direct).length} direct · {peers().filter((p) => !p.direct).length} relayed</span>
        </header>
        <MeshGraph peers={peers()} onOpenPeer={props.onOpenPeer} />
      </section>

      <section class="panel settings-group">
        <h2>Path selection & mesh scaling</h2>
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
        <form
          class="row"
          onSubmit={(event) => {
            event.preventDefault();
            if (budgetText().trim()) apply({ "relay.probe_budget_bps": budgetText().trim() }).then((ok) => ok && setBudgetText(""));
          }}
        >
          <div class="label">
            <b>Speed tests</b>
            <p>
              Every {probeEvery()} s, measure how fast each direct connection delivers. The results fill the Rate column,
              start new traffic on each peer's fastest connection (unless you route by latency), and are required by goodput.
              The value caps the bandwidth the tests use for the whole machine; 0 turns them off.
            </p>
            <p>{budget() ? `On, up to ${rate(budget())}.` : "Off. Enter a limit such as 2Mbit to turn them on."}</p>
          </div>
          <div class="control">
            <input type="text" placeholder="2Mbit" aria-label="Speed test bandwidth limit" value={budgetText()} onInput={(event) => setBudgetText(event.currentTarget.value)} />
            <button type="submit" disabled={busy() || !budgetText().trim()}>
              Save
            </button>
          </div>
        </form>
        <div class="row">
          <div class="label">
            <b>Use relays</b>
            <p>Automatic routing may send this machine's traffic through other peers when there is no direct link.</p>
          </div>
          <div class="control">
            <Switch label="Use relays" checked={configured("relay.use_relays") ?? true} disabled={busy()} onChange={(value) => apply({ "relay.use_relays": value })} />
            <Applies path="relay.use_relays" />
          </div>
        </div>
        <div class="row">
          <div class="label">
            <b>Carry traffic for others</b>
            <p>{TRANSIT[transit()] ?? ""} Acting as a waypoint needs allow or avoid.</p>
          </div>
          <div class="control">
            <Segmented label="Transit" values={["allow", "avoid", "deny"]} value={transit()} disabled={busy()} onChange={(value) => apply({ "relay.transit": value })} />
            <Applies path="relay.transit" />
          </div>
        </div>
        <div class="row">
          <div class="label">
            <b>Serve as exit</b>
            <p>Let peers send internet traffic out through this machine.</p>
          </div>
          <div class="control">
            <Switch label="Serve as exit" checked={configured("routes.serve_exit") ?? false} disabled={busy()} onChange={(value) => apply({ "routes.serve_exit": value })} />
            <Applies path="routes.serve_exit" />
          </div>
        </div>
        <div class="row">
          <div class="label">
            <b>Direct peer mode</b>
            <p>Lazy only dials direct P2P on traffic demand; on maintains direct mesh up to the connection budget.</p>
          </div>
          <div class="control">
            <Segmented label="Direct peer mode" values={["lazy", "on", "required", "off"]} value={p2pMode()} disabled={busy()} onChange={(value) => apply({ "nat.p2p": value })} />
            <Applies path="nat.p2p" />
          </div>
        </div>
        <form
          class="row"
          onSubmit={(event) => {
            event.preventDefault();
            const parsed = Number.parseInt(maxDirectText().trim(), 10);
            if (!Number.isNaN(parsed) && parsed >= 0) {
              apply({ "limits.max_direct_peers": parsed }).then((ok) => ok && setMaxDirectText(""));
            }
          }}
        >
          <div class="label">
            <b>Max direct peers</b>
            <p>Cap steady-state direct connections (0 = unlimited, default 32). Active relays and recent traffic stay connected.</p>
          </div>
          <div class="control inline">
            <input
              type="number"
              min="0"
              placeholder={String(maxDirect() ?? 32)}
              aria-label="Max direct peers"
              value={maxDirectText()}
              onInput={(event) => setMaxDirectText(event.currentTarget.value)}
            />
            <button type="submit" class="quiet" disabled={busy() || maxDirectText().trim() === ""}>Set</button>
            <Applies path="limits.max_direct_peers" />
          </div>
        </form>
      </section>

      <section class="panel settings-group">
        <header class="panel-head">
          <h2>Subnets & router forwarding</h2>
          <Show when={editingExport() === null}>
            <button type="button" class="quiet" onClick={() => setEditingExport("new")}>Export subnet</button>
          </Show>
        </header>
        <p class="hint lead">
          Export local LAN subnets (for example 192.168.1.0/24 on a router) to the mesh, or steer discovered remote subnets via relays or direct mesh.
        </p>
        <div class="row">
          <div class="label">
            <b>System router forwarding</b>
            <p>Use kernel IP forwarding instead of userspace NAT proxy so LAN devices behind a router reach remote subnets two-way.</p>
          </div>
          <div class="control">
            <Switch label="System router forwarding" checked={configured("proxy.system_forward") ?? false} disabled={busy()} onChange={(value) => apply({ "proxy.system_forward": value })} />
            <Applies path="proxy.system_forward" />
          </div>
        </div>
        <Show when={editingExport() === "new"}>
          <ExportEditor onSave={(entry) => saveExport("new", entry)} onCancel={() => setEditingExport(null)} />
        </Show>
        <Show when={exportsConfigured().length > 0}>
          <ol class="path-list">
            <For each={exportsConfigured()}>
              {(entry, index) => (
                <li>
                  <Show
                    when={editingExport() === index()}
                    fallback={
                      <div class="path-row">
                        <div class="path-summary">
                          <span class="mono">{entry.cidr}</span>
                          <Show when={entry.mapped_cidr}><span class="sub">→ mapped as {entry.mapped_cidr}</span></Show>
                          <Show when={entry.allow?.length}><span class="sub">allow: {entry.allow!.join(", ")}</span></Show>
                        </div>
                        <div class="row-actions">
                          <button type="button" class="quiet" onClick={() => setEditingExport(index())}>Edit</button>
                          <button type="button" class="link danger" disabled={busy()} onClick={() => deleteExport(index())}>Remove</button>
                        </div>
                      </div>
                    }
                  >
                    <ExportEditor initial={entry} onSave={(next) => saveExport(index(), next)} onCancel={() => setEditingExport(null)} />
                  </Show>
                </li>
              )}
            </For>
          </ol>
        </Show>
        <Show when={discoveredSubnets().length > 0}>
          <div class="discovered-subnets">
            <h3>Discovered mesh subnets</h3>
            <ul class="path-list">
              <For each={discoveredSubnets()}>
                {(item) => (
                  <li>
                    <div class="path-row">
                      <div class="path-summary">
                        <span class="mono">{item.cidr}</span>
                        <span class="sub">via {item.peer} ({item.direct ? "direct" : "relayed"})</span>
                      </div>
                      <div class="row-actions">
                        <button type="button" class="quiet" onClick={() => steerSubnet(item.cidr)}>Steer / Relay</button>
                      </div>
                    </div>
                  </li>
                )}
              </For>
            </ul>
          </div>
        </Show>
      </section>

      <section class="panel">
        <header class="panel-head">
          <h2>Paths</h2>
          <Show when={editingPath() === null}>
            <button type="button" class="quiet" onClick={() => { setNewPathDraft(undefined); setEditingPath("new"); }}>
              New path
            </button>
          </Show>
        </header>
        <p class="hint lead">
          Steer this machine's traffic through chosen relay layers or groups, in order. Parallel layers stripe across usable nodes; relay hops forward sealed packets without
          opening them.
        </p>
        <Show when={editingPath() === "new"}>
          <PathEditor initial={newPathDraft()} onSave={(path) => { setNewPathDraft(undefined); savePath("new", path); }} onCancel={() => { setNewPathDraft(undefined); setEditingPath(null); }} />
        </Show>
        <Show when={!pathsConfigured().length && editingPath() !== "new"}>
          <p class="empty">No paths. All traffic routes automatically.</p>
        </Show>
        <ol class="path-list">
          <For each={pathsConfigured()}>
            {(path, index) => (
              <li>
                <Show
                  when={editingPath() === index()}
                  fallback={
                    <div class="path-row">
                      <div class="path-summary">
                        <b>{targetLabel(path.to)}</b>
                        <span class="chain">
                          <span class="hop self">this machine</span>
                          <For each={[...(path.layers ?? []), ...(path.gateway ? [path.gateway] : [])]}>
                            {(stage) => {
                              const nodes = stageNodes(stage);
                              const singleGroup = nodes.length === 1 && isGroup(nodes[0]);
                              return (
                                <>
                                  <Arrow />
                                  <span class="hop" classList={{ group: singleGroup || nodes.length > 1 }}>
                                    {stageLabel(stage)}
                                  </span>
                                </>
                              );
                            }}
                          </For>
                          <Show when={path.to !== "internet"}>
                            <Arrow />
                            <span class="hop">{targetLabel(path.to)}</span>
                          </Show>
                        </span>
                        <span class="sub">
                          {path.mode || "parallel"}
                          {path.strict ? " · strict" : ""}
                          {pathStatus(index()) && path.layers?.length
                            ? ` · ${pathStatus(index())!.relayed_packets ?? 0} relayed · ${pathStatus(index())!.reordered_packets ?? 0} reordered · ${pathStatus(index())!.fallback_packets ?? 0} fallback · ${pathStatus(index())!.dropped_packets ?? 0} dropped`
                            : ""}
                        </span>
                      </div>
                      <div class="row-actions">
                        <button type="button" class="quiet" onClick={() => setEditingPath(index())}>
                          Edit
                        </button>
                        <button type="button" class="link danger" disabled={busy()} onClick={() => deletePath(index())}>
                          Delete
                        </button>
                      </div>
                      <PathStatusView status={pathStatus(index())} />
                    </div>
                  }
                >
                  <PathEditor initial={path} onSave={(next) => savePath(index(), next)} onCancel={() => setEditingPath(null)} />
                </Show>
              </li>
            )}
          </For>
        </ol>
      </section>

      <section class="panel">
        <header class="panel-head">
          <h2>Groups</h2>
          <Show when={editingGroup() === null}>
            <button type="button" class="quiet" onClick={() => setEditingGroup("new")}>
              New group
            </button>
          </Show>
        </header>
        <p class="hint lead">A group is a named set of peers for a relay layer or exit gateway pool.</p>
        <Show when={editingGroup() === "new"}>
          <GroupEditor onSave={(group) => saveGroup("new", group)} onCancel={() => setEditingGroup(null)} />
        </Show>
        <Show when={!groupsConfigured().length && editingGroup() !== "new"}>
          <p class="empty">No groups.</p>
        </Show>
        <ul class="path-list">
          <For each={groupsConfigured()}>
            {(group, index) => (
              <li>
                <Show
                  when={editingGroup() === index()}
                  fallback={
                    <div class="path-row">
                      <div class="path-summary">
                        <b>{group.name}</b>
                        <span>
                          {group.nodes
                            .map((member, at) => `${refLabel(member)}${group.weights?.[at] && group.weights[at] !== 1 ? ` ×${group.weights[at]}` : ""}`)
                            .join(", ")}
                        </span>
                        <span class="sub">
                          {group.mode === "failover"
                            ? "failover, in order"
                            : group.mode === "flow"
                              ? "balanced per flow"
                              : "parallel across nodes"}
                        </span>
                      </div>
                      <div class="row-actions">
                        <button type="button" class="quiet" onClick={() => setEditingGroup(index())}>
                          Edit
                        </button>
                      </div>
                    </div>
                  }
                >
                  <GroupEditor initial={group} onSave={(next) => saveGroup(index(), next)} onCancel={() => setEditingGroup(null)} onDelete={() => deleteGroup(index())} />
                </Show>
              </li>
            )}
          </For>
        </ul>
      </section>

      <section class="panel">
        <header class="panel-head">
          <h2>Routes to peers</h2>
        </header>
        <div class="table-wrap">
          <table class="routes">
            <thead>
              <tr>
                <th scope="col">Destination</th>
                <th scope="col">Automatic route</th>
                <th scope="col" class="num">
                  Cost
                </th>
                <th scope="col">Path</th>
              </tr>
            </thead>
            <tbody>
              <Index each={routed()}>
                {(item) => {
                  const explicit = () => pathIndexFor(item().row);
                  const index = () => (explicit() >= 0 ? explicit() : wildcardPathIndex());
                  return (
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
                        <Show
                          when={index() >= 0}
                          fallback={
                            <button type="button" class="link" onClick={() => props.onOpenPeer(item().row.id)}>
                              Automatic
                            </button>
                          }
                        >
                          <span classList={{ status: true, [pathStatus(index())?.state ?? ""]: true }}>
                            through {(pathsConfigured()[index()]?.layers ?? []).map(stageLabel).join(" → ")}
                          </span>
                        </Show>
                      </td>
                    </tr>
                  );
                }}
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
    </div>
  );
}
