import { For, Match, Show, Switch, createMemo, createSignal, onCleanup, onMount } from "solid-js";
import { parse, stringify } from "smol-toml";
import { rpc, type Doc } from "./api";
import { Mark } from "./components/icons";
import { ago, bytes, latency, rate } from "./format";
import { nativeRuntime, vpnCommand, type VpnStatus } from "./native";
import { error, peers, snapshot, start, stop, type PeerRow } from "./store";
import { THEMES, setTheme, theme, type Theme } from "./theme";

type Tab = "connect" | "machines" | "routes" | "settings";
const tabs: { id: Tab; title: string }[] = [
  { id: "connect", title: "Connect" }, { id: "machines", title: "Machines" },
  { id: "routes", title: "Routes" }, { id: "settings", title: "Settings" },
];
const labels: Record<VpnStatus["state"], string> = {
  disconnected: "Disconnected", connecting: "Connecting", connected: "VPN active",
  reconnecting: "Reconnecting", disconnecting: "Disconnecting",
};

function Glyph(props: { name: string; size?: number }) {
  const paths: Record<string, string> = {
    connect: "M12 3v9M6.3 5.8a8 8 0 1 0 11.4 0",
    machines: "M3 4h13v10H3zM6 18h7M9.5 14v4M19 9h3v12h-6v-4",
    routes: "M5 4v11a4 4 0 0 0 4 4h8M5 9h10a4 4 0 0 0 4-4V3M14 16l3 3-3 3",
    settings: "M4 6h16M4 12h16M4 18h16M8 3v6M16 9v6M10 15v6",
    arrow: "M7 17L17 7M7 7h10v10",
    shield: "M12 2l8 3v6c0 5-4 8-8 11-4-3-8-6-8-11V5zM8 12l3 3 5-6",
    plus: "M12 5v14M5 12h14",
    down: "M12 4v16M6 14l6 6 6-6",
    up: "M12 20V4M6 10l6-6 6 6",
    chevron: "M9 5l7 7-7 7",
    close: "M6 6l12 12M18 6L6 18",
  };
  return <svg width={props.size ?? 22} height={props.size ?? 22} viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d={paths[props.name] ?? paths.machines} /></svg>;
}

function NetworkForm(props: { onSave: (name: string, config: string) => Promise<void>; onClose: () => void; busy: boolean }) {
  const [mode, setMode] = createSignal("quick");
  const [failure, setFailure] = createSignal("");
  let form!: HTMLFormElement;
  const submit = async (event: SubmitEvent) => {
    event.preventDefault();
    const data = new FormData(form);
    try {
      const name = String(data.get("name") ?? "").trim();
      let text: string;
      if (mode() === "import") {
        text = String(data.get("config") ?? "");
        const doc = parse(text) as Doc;
        if (!doc.address?.ipv4) throw new Error("Set address.ipv4 in the imported configuration.");
      } else {
        const address = String(data.get("address") ?? "").trim();
        if (!/^(?:\d{1,3}\.){3}\d{1,3}\/(?:[0-9]|[12][0-9]|3[0-2])$/.test(address) ||
            address.split("/")[0].split(".").some((part) => Number(part) > 255)) {
          throw new Error("Enter an IPv4 address and prefix, such as 10.44.0.9/24.");
        }
        const peers = String(data.get("peers") ?? "").split(/\s+/).filter(Boolean);
        const trackers = String(data.get("trackers") ?? "").split(/\s+/).filter(Boolean);
        if (!peers.length && !trackers.length) throw new Error("Enter at least one peer address or discovery tracker.");
        for (const peer of peers) {
          if (!["quic:", "h2:", "wss:"].includes(new URL(peer).protocol)) throw new Error("Peer addresses must use quic://, h2://, or wss://.");
        }
        text = stringify({
          node: { hostname: "iPhone", instance_name: "ios", threads: 1 },
          network: { name: String(data.get("network") ?? "").trim(), secret: String(data.get("secret") ?? "") },
          address: { ipv4: address },
          tun: { mode: "kernel", mtu: 1280 },
          transport: { listen: ["quic://0.0.0.0:0"] },
          peer: peers.map((uri) => ({ uri })),
          ...(trackers.length ? { discovery: { trackers } } : {}),
        });
      }
      await props.onSave(name, text);
      form.reset();
      props.onClose();
    } catch (caught) {
      setFailure(caught instanceof Error ? caught.message : String(caught));
      form.querySelector<HTMLElement>("[role=alert]")?.focus();
    }
  };
  return (
    <section class="device-card setup-card" aria-labelledby="setup-heading">
      <div class="device-section-title"><h2 id="setup-heading">Add your network</h2><button type="button" class="device-icon-button" aria-label="Close network setup" onClick={props.onClose}><Glyph name="close" /></button></div>
      <form ref={form} onSubmit={submit} method="post" onInput={() => setFailure("")}>
        <fieldset class="device-mode"><legend class="sr-only">Configuration method</legend>
          <For each={[["quick", "Quick setup"], ["import", "Import TOML"]]}>{([value, label]) =>
            <label><input type="radio" name="method" value={value} checked={mode() === value} onChange={() => setMode(value)} />{label}</label>
          }</For>
        </fieldset>
        <label class="device-field">Profile name<input name="name" required maxlength="80" placeholder="My network" autocomplete="off" /></label>
        <Show when={mode() === "quick"} fallback={
          <div class="device-field"><label for="profile-config">Configuration</label><textarea id="profile-config" name="config" required rows="12" autocapitalize="none" spellcheck={false} aria-describedby="profile-config-hint" placeholder={'[network]\nname = "office"\nsecret = "..."\n\n[address]\nipv4 = "10.44.0.9/24"'} /><span id="profile-config-hint">Use the current LowTier TOML format. Include secrets directly. File references are not supported.</span></div>
        }>
          <label class="device-field">Network name<input name="network" required autocapitalize="none" spellcheck={false} placeholder="office" /></label>
          <div class="device-field"><label for="profile-secret">Network secret</label><input id="profile-secret" name="secret" type="password" required autocomplete="current-password" autocapitalize="none" aria-describedby="profile-secret-hint" /><span id="profile-secret-hint">Use the same secret as the other network members.</span></div>
          <div class="device-field"><label for="profile-address">Overlay address</label><input id="profile-address" name="address" required autocapitalize="none" spellcheck={false} inputmode="decimal" placeholder="10.44.0.9/24" aria-describedby="profile-address-hint" /><span id="profile-address-hint">Assign this iPhone its own unused address.</span></div>
          <div class="device-field"><label for="profile-peers">Peer addresses</label><textarea id="profile-peers" name="peers" rows="2" autocapitalize="none" spellcheck={false} placeholder="quic://192.0.2.10:11012" aria-describedby="profile-peers-hint" /><span id="profile-peers-hint">Enter one address per line. A tracker can replace known peer addresses.</span></div>
          <label class="device-field">Discovery trackers<textarea name="trackers" rows="2" autocapitalize="none" spellcheck={false} placeholder="https://your-tracker.example/announce" /></label>
        </Show>
        <Show when={failure()}><p class="device-error" role="alert" tabindex="-1">{failure()}</p></Show>
        <p class="device-caption"><Glyph name="shield" size={16} /> Credentials stay in the iOS Keychain.</p>
        <button class="device-primary" type="submit" disabled={props.busy}>{props.busy ? "Saving…" : "Save network"}</button>
      </form>
    </section>
  );
}

function MachineCard(props: { peer: PeerRow; expanded?: boolean; onClick: () => void }) {
  return <article class="device-peer">
    <button type="button" class="device-peer-main" onClick={props.onClick} aria-expanded={props.expanded}>
      <span class="device-machine-icon"><Glyph name="machines" /></span>
      <span class="device-peer-label"><b>{props.peer.name}</b><span>{props.peer.address || "No overlay address"}</span></span>
      <span class="device-peer-state"><span classList={{ "device-direct": props.peer.direct }}>{props.peer.direct ? "Direct" : "Relayed"}</span><small>{latency(props.peer.rtt)}</small></span>
    </button>
    <Show when={props.expanded}><dl class="device-detail">
      <div><dt>Transport</dt><dd>{props.peer.transport || "Relay"}</dd></div>
      <div><dt>Session</dt><dd>{props.peer.secure ? "Authenticated" : "Establishing"}</dd></div>
      <div><dt>Received</dt><dd>{bytes(props.peer.rxTotal)}</dd></div>
      <div><dt>Sent</dt><dd>{bytes(props.peer.txTotal)}</dd></div>
      <div><dt>Version</dt><dd>{props.peer.version || "Unknown"}</dd></div>
    </dl></Show>
  </article>;
}

export default function DeviceApp() {
  const [tab, setTab] = createSignal<Tab>("connect");
  const [status, setStatus] = createSignal<VpnStatus>({ state: "disconnected", platform: "preview", mtu: 1280, lastError: "" });
  const [busy, setBusy] = createSignal(false);
  const [failure, setFailure] = createSignal("");
  const [setup, setSetup] = createSignal(false);
  const [query, setQuery] = createSignal("");
  const [expanded, setExpanded] = createSignal<number>();
  const [logs, setLogs] = createSignal<Doc[] | null>(null);
  const [now, setNow] = createSignal(Date.now());
  let timer: number | undefined;
  let disposed = false;
  let revision = 0;
  const connected = () => status().state === "connected";
  const running = () => connected() || status().state === "reconnecting";
  const changing = () => busy() || ["connecting", "disconnecting"].includes(status().state);
  const rows = createMemo(() => connected() ? peers().filter((peer) => `${peer.name} ${peer.address}`.toLowerCase().includes(query().toLowerCase())) : []);
  const visiblePeers = () => connected() ? peers() : [];
  const node = () => connected() ? snapshot()?.node?.node : undefined;
  const incoming = () => visiblePeers().reduce((sum, peer) => sum + peer.rx, 0);
  const outgoing = () => visiblePeers().reduce((sum, peer) => sum + peer.tx, 0);

  const applyStatus = (next: VpnStatus) => {
    setStatus(next);
    if (next.state === "connected" && !document.hidden) start();
    else stop();
  };
  const refresh = async () => {
    window.clearTimeout(timer);
    const mine = revision;
    try {
      const next = await vpnCommand<VpnStatus>("status");
      if (!disposed && mine === revision) applyStatus(next);
    } catch (caught) {
      if (!disposed && mine === revision) setFailure(String(caught));
    }
    if (!disposed && !document.hidden) timer = window.setTimeout(refresh, 2000);
  };
  const action = async (name: string, payload: Record<string, unknown> = {}, formHandlesError = false) => {
    setBusy(true);
    setFailure("");
    revision++;
    try { applyStatus(await vpnCommand<VpnStatus>(name, payload)); }
    catch (caught) { if (!formHandlesError) setFailure(caught instanceof Error ? caught.message : String(caught)); throw caught; }
    finally { setBusy(false); refresh(); }
  };
  const toggle = () => {
    if (!status().profile) { setSetup(true); return }
    void action(running() ? "disconnect" : "connect").catch(() => {});
  };
  onMount(() => {
    document.body.classList.add("device-mode-active");
    refresh();
    const clock = window.setInterval(() => setNow(Date.now()), 1000);
    const visibility = () => {
      revision++;
      window.clearTimeout(timer);
      if (document.hidden) stop();
      else refresh();
    };
    document.addEventListener("visibilitychange", visibility);
    onCleanup(() => {
      disposed = true;
      revision++;
      window.clearTimeout(timer);
      window.clearInterval(clock);
      stop();
      document.removeEventListener("visibilitychange", visibility);
      document.body.classList.remove("device-mode-active");
    });
  });

  return <div class="device-shell">
    <header class="device-header">
      <a href="#connect" class="device-brand" onClick={(event) => { event.preventDefault(); setTab("connect"); }}><Mark size={30} /><span>lowertier<span class="device-brand-tag">YOUR PRIVATE NETWORK</span></span></a>
      <span class="device-platform">{nativeRuntime ? "iOS" : "Preview"}</span>
    </header>
    <main class="device-main" id="device-content">
      <Show when={!nativeRuntime}><p class="device-preview">Layout preview. VPN controls require the iOS app.</p></Show>
      <Show when={failure() || status().lastError}><p role="alert" class="device-error">{failure() || status().lastError}</p></Show>
      <div class="device-heading"><div><p class="device-eyebrow">{tab() === "connect" ? "OVERVIEW" : "YOUR NETWORK"}</p><h1>{tab() === "connect" ? "Your private network" : tabs.find((item) => item.id === tab())?.title}</h1></div></div>
      <Switch>
        <Match when={tab() === "connect"}>
          <div class="device-overview">
            <section class="device-connection" classList={{ online: connected() }} aria-label="VPN connection">
              <div class="device-connection-top"><span class="device-status" classList={{ online: connected() }}><span />{labels[status().state]}</span><Glyph name="shield" /></div>
              <button type="button" class="device-power" aria-label={running() ? "Disconnect VPN" : status().profile ? "Connect VPN" : "Add a network"} disabled={changing()} onClick={toggle}><Glyph name="connect" size={46} /></button>
              <div class="device-connection-title"><h2>{status().profile?.name || "Connect this iPhone"}</h2><p>{connected() ? visiblePeers().length ? `${visiblePeers().length} machines available` : "Looking for network members…" : status().profile ? "Ready to connect this iPhone." : "Connect your iPhone to your machines."}</p></div>
              <button type="button" class="device-connect-button" disabled={changing()} onClick={toggle}>{changing() ? `${labels[status().state]}…` : running() ? "Disconnect" : status().profile ? "Connect" : "Add a network"}<Glyph name={running() ? "connect" : "arrow"} size={18} /></button>
              <Show when={connected() && status().connectedAt}><p class="device-connected-time">Active for {ago(now() - status().connectedAt!)}</p></Show>
            </section>
            <div class="device-overview-side">
              <section class="device-card device-network-card"><div class="device-section-title"><h2>This iPhone</h2><span class="device-label">PRIVATE</span></div><p class="device-address">{node()?.ipv4_addr?.split("/")[0] || "No address yet"}</p><p class="device-secondary">{status().profile?.name || "No network configured"}</p><div class="device-network-footer"><span>MTU {status().mtu}</span><span>Native packet tunnel</span></div></section>
              <section class="device-traffic" aria-label="Current traffic">
                <div class="device-card"><span class="device-traffic-icon"><Glyph name="down" size={19} /></span><span class="device-secondary">Download</span><b>{rate(incoming())}</b></div>
                <div class="device-card"><span class="device-traffic-icon upload"><Glyph name="up" size={19} /></span><span class="device-secondary">Upload</span><b>{rate(outgoing())}</b></div>
              </section>
            </div>
          </div>
          <Show when={setup()}><NetworkForm busy={busy()} onClose={() => setSetup(false)} onSave={async (name, config) => { await action("saveProfile", { name, config }, true); }} /></Show>
          <section class="device-card device-members"><div class="device-section-title"><h2>Machines <span class="device-count">{visiblePeers().length}</span></h2><button type="button" class="device-text-button" onClick={() => setTab("machines")}>View all<Glyph name="chevron" size={15} /></button></div>
            <For each={visiblePeers().slice(0, 3)} fallback={<div class="device-empty"><span class="device-empty-icon"><Glyph name="machines" size={28} /></span><h3>{connected() ? "Finding your machines" : "Your machines will appear here"}</h3><p>{connected() ? "Keep a network member online. Check its peer address or discovery tracker." : "Connect to see live connections and routes."}</p></div>}>
              {(peer) => <MachineCard peer={peer} expanded={expanded() === peer.id} onClick={() => setExpanded(expanded() === peer.id ? undefined : peer.id)} />}
            </For>
          </section>
          <p class="device-footer-note"><Glyph name="shield" size={15} /> Encrypted links. Native iOS networking.</p>
        </Match>
        <Match when={tab() === "machines"}>
          <label class="device-field device-search"><span class="sr-only">Search machines</span><input type="search" placeholder="Search name or address" value={query()} onInput={(event) => setQuery(event.currentTarget.value)} /></label>
          <Show when={connected() && error()}><p class="device-error" role="status">{error()?.message}</p></Show>
          <section class="device-card device-members"><For each={rows()} fallback={<div class="device-empty"><Glyph name="machines" size={34} /><h2>{connected() ? "No matching machines" : "Connect to see your machines"}</h2><p>Machine details come from the running VPN extension.</p></div>}>{(peer) => <MachineCard peer={peer} expanded={expanded() === peer.id} onClick={() => setExpanded(expanded() === peer.id ? undefined : peer.id)} />}</For></section>
        </Match>
        <Match when={tab() === "routes"}>
          <section class="device-card"><div class="device-section-title"><h2>Active overlay routes</h2><span class="device-label">LIVE</span></div><p class="device-secondary">These routes describe the overlay. iOS captures the profile subnet and its explicit routes.</p>
            <For each={connected() ? snapshot()?.routes ?? [] : []} fallback={<div class="device-empty"><Glyph name="routes" size={34} /><h3>No active routes</h3><p>Connect to read the current forwarding state.</p></div>}>{(route: Doc) => <div class="device-route"><Glyph name="routes" /><div><b>{route.destination || route.route?.hostname || "Overlay route"}</b><span>{route.effective_policy || route.policy || "Automatic"} · {route.path_peer_ids?.length || 1} hops</span></div><span>{latency(route.measured_rtt_us)}</span></div>}</For>
          </section>
        </Match>
        <Match when={tab() === "settings"}>
          <section class="device-card"><div class="device-section-title"><h2>Network profile</h2><Glyph name="shield" /></div><p class="device-profile-name">{status().profile?.name || "No network configured"}</p><p class="device-secondary">The Keychain stores configuration, credentials, and node identity. Replacing a profile creates a new identity unless you import its private key.</p><button type="button" class="device-secondary-button" disabled={running() || changing()} onClick={() => setSetup(!setup())}>{status().profile ? "Replace configuration" : "Add network"}<Glyph name="plus" size={18} /></button></section>
          <Show when={setup()}><NetworkForm busy={busy()} onClose={() => setSetup(false)} onSave={async (name, config) => { await action("saveProfile", { name, config }, true); }} /></Show>
          <section class="device-card"><div class="device-section-title"><h2>Appearance</h2></div><fieldset class="device-mode"><legend class="sr-only">Theme</legend><For each={THEMES}>{(value) => <label><input type="radio" name="theme" value={value} checked={theme() === value} onChange={() => setTheme(value as Theme)} />{value}</label>}</For></fieldset></section>
          <section class="device-card"><div class="device-section-title"><h2>Diagnostics</h2><span class="device-label">ON DEVICE</span></div><dl class="device-detail"><div><dt>VPN backend</dt><dd>Network Extension</dd></div><div><dt>Overlay MTU</dt><dd>{status().mtu}</dd></div><div><dt>Protocol</dt><dd>QUIC · H2 · WSS</dd></div></dl><button type="button" class="device-secondary-button" disabled={!connected()} onClick={async () => { try { setLogs((await rpc("ReadLogs", { page: { limit: 100 } })).logs ?? []); } catch (caught) { setFailure(String(caught)); } }}>Read recent logs<Glyph name="chevron" size={18} /></button><Show when={logs()}><div class="device-logs" aria-label="Recent VPN logs"><For each={logs()} fallback={<p>No recent log entries.</p>}>{(line) => <p><b>{line.level}</b> {line.message}</p>}</For></div></Show></section>
        </Match>
      </Switch>
    </main>
    <nav class="device-tabs" aria-label="Main navigation"><For each={tabs}>{(item) => <button type="button" aria-current={tab() === item.id ? "page" : undefined} onClick={() => { setTab(item.id); window.scrollTo({ top: 0 }); }}><Glyph name={item.id} /><span>{item.title}</span></button>}</For></nav>
  </div>;
}
