// Shared pieces for [[path]] and [[group]] editing and status.
import { For, Show, createMemo } from "solid-js";
import type { Doc } from "../api";
import { groupsConfigured } from "../config";
import { peers } from "../store";

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
  const excluded = () => new Set(props.exclude ?? []);
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
                {group.name} ({group.members.length})
              </option>
            )}
          </For>
        </optgroup>
      </Show>
      <optgroup label="Peers">
        <For each={peers().filter((peer) => peer.key && !excluded().has(peer.key))}>
          {(peer) => <option value={peer.key}>{peer.name}</option>}
        </For>
      </optgroup>
    </select>
  );
}

/** An ordered list of waypoints. */
export function ViaEditor(props: { value: string[]; exclude?: string[]; onChange: (via: string[]) => void; disabled?: boolean }) {
  const move = (index: number, step: number) => {
    const next = [...props.value];
    const [item] = next.splice(index, 1);
    next.splice(index + step, 0, item);
    props.onChange(next);
  };
  return (
    <div class="via-editor">
      <ol class="via-list">
        <For each={props.value}>
          {(reference, index) => (
            <li>
              <span>
                {refLabel(reference)}
                <Show when={isGroup(reference)}>
                  <span class="sub inline">group</span>
                </Show>
              </span>
              <span class="actions">
                <button type="button" class="quiet small" disabled={props.disabled || index() === 0} onClick={() => move(index(), -1)} aria-label={`Move ${refLabel(reference)} earlier`}>
                  Earlier
                </button>
                <button type="button" class="quiet small" disabled={props.disabled} onClick={() => props.onChange(props.value.filter((_, at) => at !== index()))} aria-label={`Remove ${refLabel(reference)}`}>
                  Remove
                </button>
              </span>
            </li>
          )}
        </For>
      </ol>
      <Show when={props.value.length < 4}>
        <RefSelect
          label="Add a waypoint"
          placeholder={props.value.length ? "Then through…" : "Through…"}
          exclude={[...(props.exclude ?? []), ...props.value]}
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

/** Live state of one path: each segment's members and their share of the traffic. */
export function PathStatusView(props: { status?: Doc }) {
  const segments = createMemo(() => {
    const status = props.status;
    if (!status) return [];
    const via = ((status.via ?? []) as Doc[]).map((segment, index) => ({ role: `Waypoint ${index + 1}`, segment }));
    return status.gateway ? [...via, { role: "Gateway", segment: status.gateway as Doc }] : via;
  });
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
                    <Show when={members().length > 1}>
                      <span class="sub inline">{segment.balance}</span>
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
        </div>
      )}
    </Show>
  );
}
