import { For, Index, Match, Show, Switch as Pick, createEffect, createMemo, createSignal, on, onMount } from "solid-js";
import { createStore, produce } from "solid-js/store";
import { fromToml, toToml } from "../api";
import { Segmented, Switch } from "../components/controls";
import { apply, busy, config, configured, loadSchema, lookup, restartPending, say, schema, type OptionSpec } from "../config";
import { words } from "../format";
import { selection, snapshot } from "../store";
import { credentialChanges, FLEET_GUI_CIDRS, guiChanges, guiRules, overlaySubnet, REDACTED, ROUTING_PATHS, secretChanges, secretSource, type Changes, type GuiRule, type SecretSource } from "../settingsModel";

const ORDER = ["node", "network", "identity", "address", "tun", "transport", "peer", "nat", "underlay", "discovery", "relay", "routes", "export", "proxy", "forward", "dns", "acl", "camouflage", "limits", "l2", "log", "control", "gui"];
const GROUPED = new Set(["network.secret_file", "network.credential", "identity.private_key_file", "identity.credential_root", "control.secret_file", "gui.open", "acl.tcp_ports", "acl.udp_ports"]);

function text(option: OptionSpec, value: any): string {
  if (value == null) return "";
  if (["list", "intlist"].includes(option.kind)) return value.join("\n");
  if (["table", "tables"].includes(option.kind)) {
    const keys = option.path.split(".");
    const doc: any = {};
    let table = doc;
    for (const part of keys.slice(0, -1)) table = table[part] = {};
    table[keys[keys.length - 1]] = value;
    return toToml(doc);
  }
  return String(value);
}

function parsed(option: OptionSpec, input: string): unknown {
  const trimmed = input.trim();
  if (!trimmed) return null;
  switch (option.kind) {
    case "int": {
      const number = Number(trimmed);
      if (!Number.isInteger(number)) throw new Error(`${option.path}: "${trimmed}" is not an integer.`);
      return number;
    }
    case "list":
      return trimmed.split(/[\n,]/).map((item) => item.trim()).filter(Boolean);
    case "intlist":
      return trimmed.split(/[\n,]/).map((item) => item.trim()).filter(Boolean).map((item) => {
        const number = item.startsWith("0x") ? parseInt(item.slice(2), 16) : Number(item);
        if (!Number.isInteger(number)) throw new Error(`${option.path}: "${item}" is not an integer.`);
        return number;
      });
    case "table":
    case "tables": {
      const value = lookup(fromToml(trimmed), option.path);
      if (value == null) throw new Error(`${option.path}: use ${option.kind === "table" ? `[${option.path}]` : `[[${option.path}]]`} tables.`);
      return value;
    }
    default:
      return trimmed;
  }
}

export default function Settings(props: { onRouting: () => void }) {
  onMount(loadSchema);
  const [filter, setFilter] = createSignal("");
  const [raw, setRaw] = createSignal(false);
  const [pending, setPending] = createStore<Record<string, any>>({});
  const [access, setAccess] = createSignal<GuiRule[] | null>(null);
  const draft = (path: string) => path in pending ? pending[path] : configured(path);
  const credentialMode = () => draft("network.credential") != null;
  const fleet = () => draft("network.name") === "lt-";
  const subnet = () => overlaySubnet(draft("address.ipv4") || snapshot()?.node?.node?.ipv4_addr);
  const accessRules = () => access() ?? guiRules(configured("gui.allow"), configured("gui.open"));
  const changed = () => Object.keys(pending).length + (access() ? 1 : 0);
  const editMany = (changes: Changes) => setPending(produce((draft) => Object.assign(draft, changes)));
  const undo = (paths: string[]) => setPending(produce((draft) => paths.forEach((path) => delete draft[path])));
  const edit = (path: string, value: unknown) => {
    if (path === "network.credential") editMany(credentialChanges(String(value)));
    else setPending(path, value);
  };
  const discard = () => {
    undo(Object.keys(pending));
    setAccess(null);
  };
  // Drafts belong to the selected daemon and instance.
  const target = createMemo(() => JSON.stringify([selection().node, selection().instance, snapshot()?.instance]));
  createEffect(on(target, discard, { defer: true }));

  const matches = (paths: string[], extra = "") => {
    const query = filter().trim().toLowerCase();
    return !query || `${extra} ${schema().filter((option) => paths.includes(option.path)).map((option) => `${option.path} ${option.doc}`).join(" ")}`.toLowerCase().includes(query);
  };
  const sections = createMemo(() => {
    const groups = new Map<string, OptionSpec[]>();
    for (const option of schema()) {
      if (GROUPED.has(option.path) || ROUTING_PATHS.has(option.path)) continue;
      const paths = option.path === "network.secret" ? [option.path, "network.secret_file", "network.credential"]
        : option.path === "identity.private_key" ? [option.path, "identity.private_key_file", "identity.credential_root"]
        : option.path === "control.secret" ? [option.path, "control.secret_file"]
        : option.path === "gui.allow" ? [option.path, "gui.open"]
        : option.path === "acl" ? [option.path, "acl.tcp_ports", "acl.udp_ports"] : [option.path];
      if (!matches(paths, option.path === "network.credential_file" ? "Issued credential store" : "")) continue;
      const section = option.path.split(".")[0];
      if (!groups.has(section)) groups.set(section, []);
      groups.get(section)!.push(option);
    }
    return [...groups.entries()].sort(([a], [b]) => {
      const rank = (name: string) => ORDER.indexOf(name) + 1 || ORDER.length + 1;
      return rank(a) - rank(b);
    });
  });

  const save = async () => {
    try {
      const changes: Changes = {};
      for (const [path, value] of Object.entries(pending)) {
        const option = schema().find((item) => item.path === path)!;
        changes[path] = typeof value === "string" ? parsed(option, value) : value;
      }
      for (const path of ["network.secret", "identity.private_key", "control.secret"]) {
        if (path === "network.secret" && credentialMode()) continue;
        const source = secretSource(draft(path), draft(`${path}_file`));
        const selected = source === "file" ? `${path}_file` : path;
        if (source !== "automatic" && selected in changes && changes[selected] == null) throw new Error(`Enter ${source === "file" ? "a file path" : "a value"} for ${path}.`);
      }
      if (credentialMode() && "network.credential" in changes && changes["network.credential"] == null) throw new Error("Enter a signed credential.");
      if (access()) Object.assign(changes, guiChanges(access()!, subnet(), fleet()));
      if (await apply(changes)) discard();
    } catch (caught) {
      say(caught instanceof Error ? caught.message : String(caught), true);
    }
  };

  const Applies = (props: { paths: string[] }) => (
    <span class="applies" classList={{ pending: props.paths.some(restartPending) }}>
      {props.paths.some(restartPending) ? "restart pending" : schema().find((option) => option.path === props.paths[0])?.apply}
    </span>
  );

  const Row = (props: { option: OptionSpec; label?: string; help?: string; resetLabel?: string }) => {
    const path = props.option.path;
    const value = () => configured(path);
    const edited = () => path in pending;
    const name = path.split(".").slice(1).join(".") || path;
    return (
      <div class="row" classList={{ edited: edited() }}>
        <div class="label"><b>{props.label ?? words(name)}</b><code>{path}</code><p>{props.help ?? props.option.doc}</p></div>
        <div class="control" classList={{ column: ["list", "intlist", "tables", "table"].includes(props.option.kind) }}>
          <Pick fallback={
            <input type={props.option.secret ? "password" : "text"} autocomplete="off" spellcheck={false} aria-label={path}
              placeholder={props.option.secret ? (value() === REDACTED ? "Set, unchanged" : props.resetLabel ?? "Not set") : props.option.default || props.option.type}
              value={props.option.secret ? (edited() ? draft(path) ?? "" : "") : edited() ? draft(path) ?? "" : text(props.option, value())}
              onInput={(event) => edit(path, event.currentTarget.value)} />
          }>
            <Match when={props.option.kind === "enum"}><Segmented label={path} values={props.option.values} value={draft(path) ?? props.option.default} onChange={(value) => edit(path, value)} /></Match>
            <Match when={props.option.kind === "bool"}><Switch label={path} checked={(draft(path) ?? props.option.default === "true") === true} onChange={(checked) => edit(path, checked)} /></Match>
            <Match when={["list", "intlist", "tables", "table"].includes(props.option.kind)}>
              <textarea rows={props.option.kind === "tables" || props.option.kind === "table" ? 6 : 3} spellcheck={false} aria-label={path}
                placeholder={props.option.kind === "table" ? `[${path}]` : props.option.kind === "tables" ? `[[${path}]]\n${props.option.fields.map((field) => `${field} = ""`).join("\n")}` : "One per line"}
                value={edited() ? draft(path) ?? "" : text(props.option, value())} onInput={(event) => edit(path, event.currentTarget.value)} />
            </Match>
          </Pick>
          <span class="row-meta"><Applies paths={[path]} />
            <Show when={value() != null && !edited() && path !== "network.credential"}><button type="button" class="link" onClick={() => edit(path, null)}>{props.resetLabel ?? "Reset"}</button></Show>
            <Show when={edited()}><button type="button" class="link" onClick={() => undo(path === "network.credential" ? Object.keys(credentialChanges("")) : [path])}>Undo</button></Show>
          </span>
        </div>
      </div>
    );
  };

  const Secret = (props: { path: string; label: string; automatic?: string }) => {
    const paths = [props.path, `${props.path}_file`, ...(props.path === "identity.private_key" ? ["identity.public_key"] : [])];
    const source = () => secretSource(draft(props.path), draft(`${props.path}_file`));
    const selected = () => source() === "file" ? `${props.path}_file` : props.path;
    const choose = (next: SecretSource) => {
      if (next === secretSource(configured(props.path), configured(`${props.path}_file`))) undo(paths);
      else editMany(secretChanges(props.path, next));
    };
    return (
      <div class="row" classList={{ edited: paths.some((path) => path in pending) }}>
        <div class="label"><b>{props.label}</b><p>{props.path === "identity.private_key" ? "The public key comes from this identity key." : "Choose one source for this secret."}</p></div>
        <div class="control column">
          <select aria-label={`${props.label} source`} value={source()} onChange={(event) => choose(event.currentTarget.value as SecretSource)}>
            <Show when={props.automatic} fallback={<option value="automatic" disabled>Choose a source</option>}><option value="automatic">{props.automatic}</option></Show>
            <option value="value">Value</option><option value="file">File</option>
          </select>
          <Show when={source() !== "automatic"}>
            <input type={source() === "value" ? "password" : "text"} autocomplete="off" spellcheck={false} aria-label={selected()}
              placeholder={source() === "file" ? "Path on this node" : configured(props.path) === REDACTED && !(props.path in pending) ? "Set, unchanged" : "Enter a value"}
              value={source() === "file" ? draft(selected()) ?? "" : selected() in pending ? draft(selected()) ?? "" : ""}
              onInput={(event) => editMany(secretChanges(props.path, source(), event.currentTarget.value))} />
            <code>{selected()}</code>
          </Show>
          <Show when={source() === "automatic" && props.automatic}><p class="hint">{props.path === "identity.private_key" ? "A key is generated when no key is stored. Clearing a stored key changes the node identity after restart." : "Remote control uses the configured key permissions."}</p></Show>
          <span class="row-meta"><Applies paths={paths} /><Show when={paths.some((path) => path in pending)}><button type="button" class="link" onClick={() => undo(paths)}>Undo</button></Show></span>
        </div>
      </div>
    );
  };

  const Authentication = () => {
    const paths = Object.keys(credentialChanges(""));
    const choose = (credential: boolean) => {
      if (credential === (configured("network.credential") != null)) undo(paths);
      else if (credential) editMany(credentialChanges(""));
      else editMany({ "network.credential": null, "network.secret": "", "network.secret_file": null });
    };
    return <>
      <div class="row"><div class="label"><b>Network authentication</b><p>Use a shared secret or a signed credential.</p></div>
        <div class="control"><select aria-label="Network authentication" value={credentialMode() ? "credential" : "secret"} onChange={(event) => choose(event.currentTarget.value === "credential")}>
          <option value="secret">Shared secret</option><option value="credential">Signed credential</option>
        </select></div>
      </div>
      <Show when={credentialMode()} fallback={<Secret path="network.secret" label="Network secret" />}>
        <Row option={schema().find((option) => option.path === "network.credential")!} label="Signed credential" help="The bundle supplies the identity key and root metadata. An explicit root pin must match the bundle." />
      </Show>
      <Show when={paths.some((path) => path in pending)}><p class="hint">Authentication changes take effect after an instance restart.</p></Show>
    </>;
  };

  const Access = () => {
    const locked = (rule: GuiRule) => fleet() && FLEET_GUI_CIDRS.includes(rule.cidr);
    const change = (index: number, value: Partial<GuiRule>) => setAccess(accessRules().map((rule, at) => at === index ? { ...rule, ...value } : { ...rule }));
    return <div class="row" classList={{ edited: access() != null }}>
      <div class="label"><b>Source networks</b><p>Each source network may require an access key. Any matching rule without a key takes priority.</p><code>gui.allow · gui.open</code></div>
      <div class="control column">
        <div class="access-rules">
          <div class="access-rule access-heading"><span>Source CIDR</span><span>Require key</span><span /></div>
          <Index each={accessRules()}>{(rule, index) => <div class="access-rule">
            <Show when={!rule().overlayDefault} fallback={<span>Overlay subnet {subnet() ? `(${subnet()})` : "(automatic)"}</span>}>
              <input type="text" aria-label={`Source CIDR ${index + 1}`} value={rule().cidr} readOnly={locked(rule())} placeholder="192.0.2.0/24" onInput={(event) => change(index, { cidr: event.currentTarget.value })} />
            </Show>
            <Switch label={`Require key for source ${index + 1}`} checked={rule().requireKey} disabled={locked(rule())} onChange={(requireKey) => change(index, { requireKey })} />
            <button type="button" class="link" disabled={locked(rule())} aria-label={`Remove source ${index + 1}`} onClick={() => setAccess(accessRules().filter((_, at) => at !== index).map((rule) => ({ ...rule })))}>Remove</button>
          </div>}</Index>
        </div>
        <div class="row-meta"><button type="button" class="link" onClick={() => setAccess([...accessRules().map((rule) => ({ ...rule })), { cidr: "", requireKey: true }])}>Add source</button>
          <button type="button" class="link" onClick={() => setAccess(guiRules(undefined, fleet() ? FLEET_GUI_CIDRS : []))}>Use default overlay access</button>
          <Show when={access()}><button type="button" class="link" onClick={() => setAccess(null)}>Undo</button></Show><Applies paths={["gui.allow", "gui.open"]} />
        </div>
        <Show when={fleet()}><p class="hint">The three fleet source networks keep access without a key.</p></Show>
      </div>
    </div>;
  };

  const Option = (props: { option: OptionSpec }) => <Pick fallback={<Row option={props.option} />}>
    <Match when={props.option.path === "network.secret"}><Authentication /></Match>
    <Match when={props.option.path === "network.credential_file"}><Row option={props.option} label="Issued credential store" help="Stores credentials issued by this node. This file does not supply a credential for joining the network." /></Match>
    <Match when={props.option.path === "identity.private_key"}>
      <Show when={!credentialMode()} fallback={<p class="hint credential-identity">The signed credential supplies the identity key.</p>}><Secret path="identity.private_key" label="Identity key" automatic="Generate automatically" /></Show>
      <Show when={credentialMode()}><details class="advanced-setting" open={filter().toLowerCase().includes("root")}><summary>Root trust pin</summary><Row option={schema().find((option) => option.path === "identity.credential_root")!} label="Root trust pin" help="Optional trusted root. A replacement credential must match this pin." /></details></Show>
    </Match>
    <Match when={props.option.path === "identity.public_key"}>
      <div class="row"><div class="label"><b>Public key</b><p>Derived from the identity key. Use this value to pin this node on another peer.</p></div>
        <div class="control column"><input type="text" aria-label="identity.public_key" readOnly value={configured("identity.public_key") ?? ""} /><Show when={"identity.public_key" in pending}><p class="hint">The value updates after the identity change takes effect.</p></Show></div>
      </div>
    </Match>
    <Match when={props.option.path === "control.secret"}><Secret path="control.secret" label="Control secret" automatic="No shared secret" /></Match>
    <Match when={props.option.path === "gui.allow"}><Access /></Match>
    <Match when={props.option.path === "acl"}><Row option={props.option} label="Access rules and ports" help="Edit the complete ACL here, including tcp_ports and udp_ports. Other settings keep these rules unchanged." /></Match>
    <Match when={props.option.path === "camouflage.admission_secret"}><Row option={props.option} label="Admission secret override"
      help={credentialMode() ? "Signed credentials have no shared network secret. Decoy forwarding requires an explicit admission secret of at least 16 bytes." : "Admission can use the network secret when this override is absent. Decoy forwarding requires an explicit secret of at least 16 bytes."}
      resetLabel={credentialMode() ? "Remove override" : "Use network secret"} /></Match>
  </Pick>;

  return (
    <div class="stack settings" classList={{ dirty: changed() > 0 }}>
      <div class="toolbar"><input type="search" placeholder="Find an option" aria-label="Find an option" value={filter()} onInput={(event) => setFilter(event.currentTarget.value)} />
        <button type="button" class="quiet" aria-pressed={raw()} onClick={() => setRaw(!raw())}>{raw() ? "Show form" : "Show TOML"}</button>
      </div>
      <Show when={!raw()} fallback={<section class="panel"><pre class="toml">{config() ? toToml(config()!.desired ?? config()!.active ?? {}) : "Loading…"}</pre></section>}>
        <Show when={config()} fallback={<p class="empty">Loading settings…</p>}>
        <Show when={matches([...ROUTING_PATHS], "Routing paths groups exit")}><section class="panel routing-settings"><div><b>Routing</b><p class="hint">Manage paths, groups, route policy, relay use, transit, probe budget, and exit service on the Routing page.</p></div><button type="button" class="quiet" disabled={changed() > 0} onClick={props.onRouting}>Open Routing</button></section></Show>
        <For each={sections()}>{([section, options]) => <details class="panel settings-group" open={filter().trim() !== "" || ["node", "network", "identity", "tun"].includes(section)}>
          <summary><h2>{words(section)}</h2></summary><For each={options}>{(option) => <Option option={option} />}</For>
        </details>}</For>
        <Show when={schema().length && !sections().length && !matches([...ROUTING_PATHS], "Routing paths groups exit")}><p class="empty">No option matches.</p></Show>
        </Show>
      </Show>
      <Show when={changed()}><div class="savebar" role="region" aria-label="Unsaved changes"><span>Unsaved changes</span>
        <button type="button" class="link" onClick={discard} disabled={busy()}>Discard</button>
        <button type="button" class="primary" onClick={save} disabled={busy() || !config()}>{busy() ? "Applying…" : "Apply"}</button>
      </div></Show>
    </div>
  );
}
