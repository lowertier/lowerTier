import { For, Index, Show, createMemo, createSignal } from "solid-js";
import { Segmented, Switch } from "../components/controls";
import { PathStatusView, RefSelect, ViaEditor, isGroup, refLabel } from "../components/paths";
import {
  apply,
  busy,
  configured,
  groupsConfigured,
  pathsConfigured,
  restartPending,
  saveRouting,
  say,
  spec,
  type GroupConfig,
  type PathConfig,
} from "../config";
import { latency, rate } from "../format";
import { peers, snapshot } from "../store";
import { PathChain, pathIndexFor, routeFor } from "./PeerDetail";
import type { Doc } from "../api";

const POLICY: Record<string, string> = {
  hop: "Fewest hops.",
  latency: "Lowest measured round trip.",
  goodput: "Highest measured delivery rate. Needs a probe budget.",
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
  if (to === "internet") return "Internet";
  if (isSubnet(to)) return to;
  return refLabel(to);
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

type TargetKind = "peer" | "internet" | "subnet";

function PathEditor(props: { initial?: PathConfig; onSave: (path: PathConfig) => void; onCancel: () => void }) {
  const initialKind = (): TargetKind => {
    const to = props.initial?.to;
    if (!to) return "peer";
    return to === "internet" ? "internet" : isSubnet(to) ? "subnet" : "peer";
  };
  const [kind, setKind] = createSignal<TargetKind>(initialKind());
  const [to, setTo] = createSignal(props.initial?.to && initialKind() !== "internet" ? props.initial.to : "");
  const [via, setVia] = createSignal<string[]>(props.initial?.via ?? []);
  const [gateway, setGateway] = createSignal(props.initial?.gateway ?? "");
  const [strict, setStrict] = createSignal(props.initial?.strict ?? false);
  const target = () => (kind() === "internet" ? "internet" : to().trim());
  const problem = () => {
    if (kind() === "internet" && !gateway()) return "Choose the exit gateway.";
    if (!target()) return kind() === "subnet" ? "Enter a CIDR such as 10.8.0.0/16." : "Choose a destination peer.";
    if (kind() === "subnet" && !isSubnet(target())) return "Enter a CIDR such as 10.8.0.0/16.";
    if (kind() !== "internet" && !via().length && !gateway()) return "Add at least one waypoint.";
    return "";
  };
  return (
    <form
      class="path-editor"
      onSubmit={(event) => {
        event.preventDefault();
        if (problem()) return;
        props.onSave({ to: target(), via: via(), gateway: kind() === "peer" ? undefined : gateway() || undefined, strict: strict() });
      }}
    >
      <div class="editor-row">
        <span class="editor-label">Traffic to</span>
        <div class="editor-control">
          <Segmented label="Destination kind" values={["peer", "internet", "subnet"]} value={kind()} onChange={(value) => setKind(value as TargetKind)} />
          <Show when={kind() === "peer"}>
            <RefSelect label="Destination peer" value={to()} placeholder="Choose a peer" groups={false} onChange={setTo} />
          </Show>
          <Show when={kind() === "subnet"}>
            <input type="text" placeholder="10.8.0.0/16" aria-label="Destination subnet" value={to()} onInput={(event) => setTo(event.currentTarget.value)} />
          </Show>
        </div>
      </div>
      <div class="editor-row">
        <span class="editor-label">Through</span>
        <div class="editor-control">
          <ViaEditor value={via()} exclude={kind() === "peer" && to() ? [to()] : []} onChange={setVia} />
        </div>
      </div>
      <Show when={kind() !== "peer"}>
        <div class="editor-row">
          <span class="editor-label">{kind() === "internet" ? "Exit at" : "Leave at"}</span>
          <div class="editor-control">
            <RefSelect
              label="Gateway"
              value={gateway()}
              placeholder={kind() === "internet" ? "Choose an exit or exit group" : "Automatic subnet gateway"}
              onChange={setGateway}
            />
            <p class="hint">{kind() === "internet" ? "Members need routes.serve_exit." : "Members must export the subnet or serve as exits."}</p>
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
  const [members, setMembers] = createSignal<string[]>(props.initial?.members ?? []);
  const [weights, setWeights] = createSignal<number[]>(props.initial?.weights ?? (props.initial?.members ?? []).map(() => 1));
  const [balance, setBalance] = createSignal(props.initial?.balance || "flow");
  const problem = () => {
    if (!/^[A-Za-z0-9_-]{1,32}$/.test(name())) return "Name: 1 to 32 letters, digits, - or _.";
    if (name() === "internet") return "The name internet is reserved.";
    if (!members().length) return "Add at least one member.";
    return "";
  };
  return (
    <form
      class="path-editor"
      onSubmit={(event) => {
        event.preventDefault();
        if (problem()) return;
        props.onSave({ name: name(), members: members(), balance: balance(), weights: balance() === "flow" ? weights() : undefined });
      }}
    >
      <div class="editor-row">
        <span class="editor-label">Name</span>
        <div class="editor-control">
          <input type="text" aria-label="Group name" placeholder="eu-relays" value={name()} onInput={(event) => setName(event.currentTarget.value)} />
        </div>
      </div>
      <div class="editor-row">
        <span class="editor-label">Balance</span>
        <div class="editor-control">
          <Segmented label="Balance" values={["flow", "failover"]} value={balance()} onChange={setBalance} />
          <p class="hint">
            {balance() === "flow"
              ? "Each flow goes to one member, spread by weight. A lost member moves only its own flows."
              : "Everything goes to the first usable member, in this order."}
          </p>
        </div>
      </div>
      <div class="editor-row">
        <span class="editor-label">Members</span>
        <div class="editor-control">
          <ol class="via-list">
            <For each={members()}>
              {(member, index) => (
                <li>
                  <span>{refLabel(member)}</span>
                  <span class="actions">
                    <Show when={balance() === "flow"}>
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
                        setMembers(members().filter((_, at) => at !== index()));
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
            label="Add a member"
            placeholder="Add a peer"
            groups={false}
            exclude={members()}
            onChange={(reference) => {
              setMembers([...members(), reference]);
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

export default function Routing(props: { onOpenPeer: (id: number) => void }) {
  const policy = () => configured("relay.policy") ?? "hop";
  const transit = () => configured("relay.transit") ?? "allow";
  const budget = () => configured("relay.probe_budget_bps");
  const [budgetText, setBudgetText] = createSignal("");
  // The open path or group editor: an index, "new", or none.
  const [editingPath, setEditingPath] = createSignal<number | "new" | null>(null);
  const [editingGroup, setEditingGroup] = createSignal<number | "new" | null>(null);

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
        const rename = (reference: string) => (reference === previous ? group.name : reference);
        paths = paths.map((path) => ({ ...path, via: path.via?.map(rename), gateway: path.gateway && rename(path.gateway) }));
      }
    }
    if (await saveRouting(groups, paths)) setEditingGroup(null);
  };
  const deleteGroup = (index: number) => {
    const groups = groupsConfigured();
    const name = groups[index].name;
    const users = pathsConfigured().filter((path) => path.gateway === name || path.via?.includes(name));
    if (users.length) {
      say(`${name} is used by ${users.length === 1 ? "a path" : `${users.length} paths`}. Change those paths first.`, true);
      return;
    }
    groups.splice(index, 1);
    saveRouting(groups, pathsConfigured()).then((ok) => ok && setEditingGroup(null));
  };

  return (
    <div class="stack">
      <section class="panel settings-group">
        <h2>Path selection</h2>
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
            <b>Probe budget</b>
            <p>Bandwidth spent measuring paths. Current {rate(budget())}. Set 0 to stop probes under hop or latency.</p>
          </div>
          <div class="control">
            <input type="text" placeholder="2Mbit" aria-label="Probe budget" value={budgetText()} onInput={(event) => setBudgetText(event.currentTarget.value)} />
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
      </section>

      <section class="panel">
        <header class="panel-head">
          <h2>Paths</h2>
          <Show when={editingPath() === null}>
            <button type="button" class="quiet" onClick={() => setEditingPath("new")}>
              New path
            </button>
          </Show>
        </header>
        <p class="hint lead">
          Steer this machine's traffic through chosen peers or groups, in order. Groups balance flows across their members. Waypoints pass sealed packets on without opening
          them.
        </p>
        <Show when={editingPath() === "new"}>
          <PathEditor onSave={(path) => savePath("new", path)} onCancel={() => setEditingPath(null)} />
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
                          <For each={[...(path.via ?? []), ...(path.gateway ? [path.gateway] : [])]}>
                            {(reference) => (
                              <>
                                <Arrow />
                                <span class="hop" classList={{ group: isGroup(reference) }}>
                                  {refLabel(reference)}
                                </span>
                              </>
                            )}
                          </For>
                          <Show when={path.to !== "internet"}>
                            <Arrow />
                            <span class="hop">{targetLabel(path.to)}</span>
                          </Show>
                        </span>
                        <span class="sub">
                          {path.strict ? "strict · " : ""}
                          {pathStatus(index()) && path.via?.length
                            ? `${pathStatus(index())!.waypoint_packets ?? 0} packets through waypoints · ${pathStatus(index())!.fallback_packets ?? 0} fallback · ${pathStatus(index())!.dropped_packets ?? 0} dropped`
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
        <p class="hint lead">A group is a set of peers sharing one role in a path: a load-balanced relay tier, or a pool of exits.</p>
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
                          {group.members
                            .map((member, at) => `${refLabel(member)}${group.weights?.[at] && group.weights[at] !== 1 ? ` ×${group.weights[at]}` : ""}`)
                            .join(", ")}
                        </span>
                        <span class="sub">{group.balance === "failover" ? "failover, in order" : "balanced per flow"}</span>
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
                  const index = () => pathIndexFor(item().row);
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
                            through {(pathsConfigured()[index()]?.via ?? []).map(refLabel).join(", ")}
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
