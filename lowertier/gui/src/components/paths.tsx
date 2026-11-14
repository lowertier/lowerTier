// Shared pieces for [[path]] and [[group]] editing and status.
import { For, Show, createMemo } from "solid-js";
import type { Doc } from "../api";
import {
  configured,
  groupsConfigured,
  stageFromNodes,
  stageMode,
  stageNodes,
  type PathStageConfig,
} from "../config";
import { latency } from "../format";
import { peerName, peers, snapshot } from "../store";

export const MAX_RELAY_LAYERS = 8;

/** A readable name for a peer key, a virtual IP, or a group name. */
export function refLabel(reference: string): string {
  if (groupsConfigured().some((group) => group.name === reference)) return reference;
  const peer = peers().find((row) => row.key === reference || row.address.split("/")[0] === reference);
  return peer ? peer.name : reference.length > 20 ? `${reference.slice(0, 8)}…` : reference;
}

export function isGroup(reference: string): boolean {
  return groupsConfigured().some((group) => group.name === reference);
}

/** Choose a group or a peer. Peers are stored by public key. */
export function RefSelect(props: {
  label: string;
  value?: string;
  placeholder: string;
  exclude?: string[];
  groups?: boolean;
  disabled?: boolean;
  onChange: (reference: string) => void;
}) {
  const excluded = () => {
    const selfKey = String(configured("identity.public_key") ?? "");
    const selfIp = (snapshot()?.node?.node?.ipv4_addr as string | undefined)?.split("/")[0] ?? "";
    return new Set([...(props.exclude ?? []), selfKey, selfIp].filter(Boolean));
  };
  return (
    <select
      aria-label={props.label}
      value={props.value ?? ""}
      disabled={props.disabled}
      onChange={(event) => {
        const value = event.currentTarget.value;
        if (props.value === undefined) event.currentTarget.value = "";
        if (value) props.onChange(value);
      }}
    >
      <option value="">{props.placeholder}</option>
      <Show when={props.groups !== false && groupsConfigured().length}>
        <optgroup label="Groups">
          <For each={groupsConfigured().filter((group) => !excluded().has(group.name))}>
            {(group) => (
              <option value={group.name}>
                {group.name} ({group.nodes.length})
              </option>
            )}
          </For>
        </optgroup>
      </Show>
      <optgroup label="Peers">
        <For
          each={peers().filter(
            (peer) =>
              peer.key &&
              !excluded().has(peer.key) &&
              !(peer.address && excluded().has(peer.address.split("/")[0])),
          )}
        >
          {(peer) => <option value={peer.key}>{peer.name}</option>}
        </For>
      </optgroup>
    </select>
  );
}

/** An ordered sequence of up to 8 relay stages; each stage holds 1 or more parallel peers/groups. */
export function LayersEditor(props: {
  value: PathStageConfig[];
  exclude?: string[];
  onChange: (layers: PathStageConfig[]) => void;
  disabled?: boolean;
}) {
  const usedSinglePeers = () => props.value.flatMap(stageNodes).filter((ref) => !isGroup(ref));
  const move = (index: number, step: number) => {
    const next = [...props.value];
    const [item] = next.splice(index, 1);
    next.splice(index + step, 0, item);
    props.onChange(next);
  };
  const updateStage = (index: number, nextNodes: string[]) => {
    const updated = stageFromNodes(nextNodes, props.value[index]);
    const next = [...props.value];
    if (updated === undefined) next.splice(index, 1);
    else next[index] = updated;
    props.onChange(next);
  };
  return (
    <div class="via-editor">
      <ol class="via-list">
        <For each={props.value}>
          {(stage, index) => {
            const nodes = () => stageNodes(stage);
            const customMode = () => stageMode(stage);
            return (
              <li class="layer-row">
                <div class="layer-head">
                  <span>
                    <b>Layer {index() + 1}</b>
                    <Show when={nodes().length > 1}>
                      <span class="sub inline">{customMode() ?? "parallel"}</span>
                    </Show>
                  </span>
                  <span class="actions">
                    <button
                      type="button"
                      class="quiet small"
                      disabled={props.disabled || index() === 0}
                      onClick={() => move(index(), -1)}
                      aria-label={`Move Layer ${index() + 1} earlier`}
                    >
                      Earlier
                    </button>
                    <button
                      type="button"
                      class="quiet small"
                      disabled={props.disabled}
                      onClick={() => props.onChange(props.value.filter((_, at) => at !== index()))}
                      aria-label={`Remove Layer ${index() + 1}`}
                    >
                      Remove layer
                    </button>
                  </span>
                </div>
                <div class="layer-chips">
                  <For each={nodes()}>
                    {(reference, nodeIndex) => (
                      <span class="layer-chip">
                        <span>
                          {refLabel(reference)}
                          <Show when={isGroup(reference)}>
                            <span class="sub inline">group</span>
                          </Show>
                        </span>
                        <button
                          type="button"
                          class="quiet small"
                          disabled={props.disabled}
                          onClick={() => updateStage(index(), nodes().filter((_, at) => at !== nodeIndex()))}
                          aria-label={`Remove ${refLabel(reference)} from Layer ${index() + 1}`}
                        >
                          ×
                        </button>
                      </span>
                    )}
                  </For>
                  <Show when={nodes().length < 32}>
                    <RefSelect
                      label={`Add parallel relay to Layer ${index() + 1}`}
                      placeholder="+ Parallel relay…"
                      exclude={[...(props.exclude ?? []), ...usedSinglePeers(), ...nodes()]}
                      disabled={props.disabled}
                      onChange={(reference) => updateStage(index(), [...nodes(), reference])}
                    />
                  </Show>
                </div>
              </li>
            );
          }}
        </For>
      </ol>
      <Show when={props.value.length < MAX_RELAY_LAYERS}>
        <RefSelect
          label="Add a relay layer"
          placeholder={props.value.length ? "Add next layer…" : "Through…"}
          exclude={[...(props.exclude ?? []), ...usedSinglePeers()]}
          disabled={props.disabled}
          onChange={(reference) => props.onChange([...props.value, reference])}
        />
      </Show>
    </div>
  );
}

const STATE_TEXT: Record<string, string> = {
  ready: "In use",
  fallback: "Automatic routing (fallback)",
  down: "Blocked (strict)",
};

function hopLabel(peerId: number): string {
  return peerName(peerId);
}

/** Live state of one path: each layer's members, active multipath chains, and traffic share. */
export function PathStatusView(props: { status?: Doc }) {
  const segments = createMemo(() => {
    const status = props.status;
    if (!status) return [];
    const layers = ((status.layers ?? []) as Doc[]).map((segment, index) => ({ role: `Layer ${index + 1}`, segment }));
    return status.gateway ? [...layers, { role: "Gateway", segment: status.gateway as Doc }] : layers;
  });
  const chains = () => ((props.status?.chains ?? []) as Doc[]);
  return (
    <Show when={props.status}>
      {(status) => (
        <div class="path-status">
          <p classList={{ state: true, [status().state]: true }}>
            {STATE_TEXT[status().state] ?? status().state}
            <Show when={status().reason}> · {status().reason}</Show>
          </p>
          <For each={segments()}>
            {({ role, segment }) => {
              const members = () => (segment.members ?? []) as Doc[];
              const total = () => members().reduce((sum, member) => sum + (member.picks ?? 0), 0);
              return (
                <div class="segment">
                  <span class="segment-name">
                    {role}: {isGroup(segment.name) ? segment.name : refLabel(segment.name)}
                    <Show when={members().length > 1 || segment.mode}>
                      <span class="sub inline">{segment.mode || "parallel"}</span>
                    </Show>
                  </span>
                  <For each={members()}>
                    {(member) => {
                      const share = () => (total() ? (member.picks ?? 0) / total() : 0);
                      return (
                        <div class="member" classList={{ unusable: !member.usable }} title={member.reason || undefined}>
                          <span class="member-name">{member.hostname || refLabel(member.ref)}</span>
                          <span class="bar" aria-hidden="true">
                            <span style={{ width: `${(share() * 100).toFixed(1)}%` }} />
                          </span>
                          <span class="member-figure">{member.usable ? `${Math.round(share() * 100)}%` : member.reason}</span>
                        </div>
                      );
                    }}
                  </For>
                </div>
              );
            }}
          </For>
          <Show when={chains().length}>
            <div class="segment">
              <span class="segment-name">Active chains</span>
              <ul class="chain-list">
                <For each={chains()}>
                  {(chain) => (
                    <li class="chain-item" classList={{ unusable: chain.healthy === false }}>
                      <span>
                        {((chain.hops ?? []) as number[]).map(hopLabel).join(" → ")}
                      </span>
                      <span class="sub">
                        {chain.rtt_us ? `${latency(chain.rtt_us)} · ` : ""}
                        {chain.packets ?? 0} pkts
                        {chain.healthy === false ? " · down" : ""}
                      </span>
                    </li>
                  )}
                </For>
              </ul>
            </div>
          </Show>
        </div>
      )}
    </Show>
  );
}
