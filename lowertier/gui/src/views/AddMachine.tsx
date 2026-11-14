// Join codes and install commands for a new machine. Any member can produce them: the code
// carries the network name, admission material, and bootstrap peers this machine can vouch for.
import { For, Show, createMemo, createSignal } from "solid-js";
import { rpc, type Doc } from "../api";
import { Copy, Dialog, Segmented } from "../components/controls";
import { configured, readDefaultBootstrapPeers, writeDefaultBootstrapPeers } from "../config";
import { snapshot } from "../store";

const REPO = "lowertier/lowerTier";
const RAW = `https://raw.githubusercontent.com/${REPO}/main/script`;
const SYSTEMS = ["Linux", "macOS", "Windows", "Installed"] as const;
type System = (typeof SYSTEMS)[number];
const LIFETIMES: Record<string, number> = { "1 hour": 3600, "1 day": 86_400, "7 days": 604_800, "30 days": 2_592_000 };
const DEFAULT_TRACKERS = [
  "udp://tracker.opentrackr.org:1337/announce",
  "http://tracker.opentrackr.org:1337/announce",
  "https://tracker.nekomi.cn:443/announce",
];

interface Candidate {
  uri: string;
  source: string;
}

const unspecified = (host: string) => ["0.0.0.0", "[::]", "::", ""].includes(host);
const loopback = (host: string) => host.startsWith("127.") || host === "[::1]" || host === "localhost";

/** Reachable URIs for this machine and the bootstrap peers it uses itself. */
export function candidates(): Candidate[] {
  const found = new Map<string, string>();
  const add = (uri: string, source: string) => {
    if (!found.has(uri)) found.set(uri, source);
  };
  for (const uri of (configured("transport.advertise") ?? []) as string[]) add(uri, "advertised");
  const node = snapshot()?.node?.node ?? {};
  const publics = ((node.stun_info?.public_ip ?? []) as string[]).map((ip) => (ip.includes(":") ? `[${ip}]` : ip));
  for (const listener of (node.listeners ?? []) as string[]) {
    let url: URL;
    try {
      url = new URL(listener);
    } catch {
      continue;
    }
    if (!url.port || url.port === "0" || loopback(url.hostname)) continue;
    const scheme = url.protocol.replace(/:$/, "");
    const path = url.pathname && url.pathname !== "/" ? url.pathname : "";
    if (unspecified(url.hostname)) for (const ip of publics) add(`${scheme}://${ip}:${url.port}${path}`, "this machine");
    else add(`${scheme}://${url.host}${path}`, "this machine");
  }
  for (const peer of (configured("peer") ?? []) as Doc[]) {
    if (typeof peer.uri !== "string") continue;
    try {
      const url = new URL(peer.uri);
      if (!unspecified(url.hostname) && !loopback(url.hostname) && url.port) add(peer.uri, "bootstrap peer");
    } catch {}
  }
  return [...found].map(([uri, source]) => ({ uri, source }));
}

function commands(system: System, code: string, version: string): { label: string; text: string }[] {
  const tag = version ? `v${version}` : "";
  switch (system) {
    case "Linux":
      return [{ label: "Install, join, and start the service", text: `curl -fsSL ${RAW}/install.sh | sudo bash -s -- install --join ${code}` }];
    case "macOS":
      return [
        {
          label: "Download this machine's release",
          text: tag
            ? `curl -fsSLo lowertier.zip https://github.com/${REPO}/releases/download/${tag}/lowertier-macos-$(uname -m | sed s/arm64/aarch64/)-${tag}.zip\nunzip -o lowertier.zip lowertier && sudo install -m 0755 lowertier /usr/local/bin/lowertier`
            : `# Download a release from https://github.com/${REPO}/releases`,
        },
        {
          label: "Join and start the service",
          text: `sudo lowertier init /usr/local/etc/lowertier/node.toml --join ${code}\nsudo lowertier service install -- -c /usr/local/etc/lowertier/node.toml\nsudo lowertier service start`,
        },
      ];
    case "Windows":
      return [
        { label: "Install, in PowerShell as Administrator", text: `irm ${RAW}/install.ps1 | iex` },
        {
          label: "Join and start the service",
          text: `lowertier init "$env:ProgramData\\LowTier\\node.toml" --join ${code}\nlowertier service install -- -c "$env:ProgramData\\LowTier\\node.toml"\nlowertier service start`,
        },
      ];
    case "Installed":
      return [
        {
          label: "Write a configuration and run in the foreground",
          text: `sudo lowertier init lowertier.toml --join ${code}\nsudo lowertier run -c lowertier.toml`,
        },
      ];
  }
}

export default function AddMachine(props: { onClose: () => void }) {
  const credentialNode = () => configured("network.credential") != null;
  const issuer = () => configured("network.credential_file") != null;
  const admission = () => configured("camouflage.admission_secret") != null;
  const canIssue = () => issuer() && admission();
  const [mode, setMode] = createSignal<"secret" | "credential">(credentialNode() ? "credential" : "secret");
  const [lifetime, setLifetime] = createSignal("1 day");
  const [reusable, setReusable] = createSignal(false);
  const [groups, setGroups] = createSignal("");
  const networkName = () => String(configured("network.name") ?? "default").trim() || "default";
  const initialDefaults = readDefaultBootstrapPeers(networkName());
  const offered = createMemo(candidates);
  const offeredSet = new Set(offered().map((item) => item.uri));
  const [chosen, setChosen] = createSignal<Set<string>>(new Set(initialDefaults));
  const [extra, setExtra] = createSignal<string[]>(initialDefaults.filter((uri) => !offeredSet.has(uri)));
  const [defaultSaved, setDefaultSaved] = createSignal("");
  const [custom, setCustom] = createSignal("");
  const configuredTrackers = [
    ...((configured("discovery.trackers") ?? []) as string[]),
    ...((configured("discovery.private_trackers") ?? []) as string[]),
  ];
  const [useTrackers, setUseTrackers] = createSignal(!credentialNode());
  const [trackerText, setTrackerText] = createSignal(
    (configuredTrackers.length ? configuredTrackers : DEFAULT_TRACKERS).join("\n"),
  );
  const [system, setSystem] = createSignal<System>("Linux");
  const [result, setResult] = createSignal<Doc | null>(null);
  const [error, setError] = createSignal("");
  const [working, setWorking] = createSignal(false);
  const peersChosen = () => [...offered().map((item) => item.uri), ...extra()].filter((uri) => chosen().has(uri));
  const trackersChosen = () =>
    trackerText()
      .split(/[\n,]+/)
      .map((item) => item.trim())
      .filter(Boolean);
  const canCreate = () =>
    mode() === "credential"
      ? peersChosen().length > 0
      : (useTrackers() && trackersChosen().length > 0) || peersChosen().length > 0;
  const version = () => (snapshot()?.node?.node?.version as string | undefined) ?? "";

  const toggle = (uri: string, on: boolean) => {
    const next = new Set(chosen());
    on ? next.add(uri) : next.delete(uri);
    setChosen(next);
  };
  const addCustom = () => {
    const uri = custom().trim();
    if (!uri) return;
    try {
      const url = new URL(uri);
      if (!url.port) throw new Error();
    } catch {
      setError("Enter a peer URI with a port, for example quic://203.0.113.7:11012.");
      return;
    }
    setError("");
    if (!extra().includes(uri) && !offered().some((item) => item.uri === uri)) setExtra([...extra(), uri]);
    toggle(uri, true);
    setCustom("");
  };
  const create = async () => {
    setWorking(true);
    setError("");
    try {
      const credential = mode() === "credential";
      const response = await rpc("CreateJoinCode", {
        peers: peersChosen(),
        trackers: !credential && useTrackers() ? trackersChosen() : [],
        use_credential: credential,
        ...(credential
          ? {
              ttl_seconds: LIFETIMES[lifetime()],
              reusable: reusable(),
              groups: groups()
                .split(/[\s,]+/)
                .filter(Boolean),
            }
          : {}),
      });
      setResult(response);
    } catch (caught) {
      setError(caught instanceof Error ? caught.message : String(caught));
    } finally {
      setWorking(false);
    }
  };

  return (
    <Dialog title="Add a machine" onClose={props.onClose} wide>
      <Show
        when={result()}
        fallback={
          <form
            class="join-form"
            onSubmit={(event) => {
              event.preventDefault();
              create();
            }}
          >
            <p class="lead">
              A join code lets a new machine enter <b>{configured("network.name") ?? "default"}</b> without a coordination server. It
              carries the network&apos;s admission material, tracker discovery, and optional bootstrap peers.
            </p>

            <fieldset>
              <legend>Admission</legend>
              <label class="choice">
                <input type="radio" name="mode" checked={mode() === "secret"} disabled={credentialNode()} onChange={() => setMode("secret")} />
                <span>
                  <b>Network secret</b>
                  <span class="sub">{credentialNode() ? "This machine joined with a credential and holds no secret." : "The new machine shares the secret. It never expires."}</span>
                </span>
              </label>
              <label class="choice">
                <input type="radio" name="mode" checked={mode() === "credential"} disabled={!canIssue()} onChange={() => setMode("credential")} />
                <span>
                  <b>Signed credential</b>
                  <span class="sub">
                    {!issuer()
                      ? "Needs network.credential_file on a credential issuer."
                      : !admission()
                        ? "Needs camouflage.admission_secret, shared by every member: credential machines hold no network secret."
                        : "Issued now, with its own identity. Expires and can be revoked."}
                  </span>
                </span>
              </label>
              <Show when={mode() === "credential"}>
                <div class="credential-options">
                  <label class="field">
                    <span>Expires after</span>
                    <Segmented label="Credential lifetime" values={Object.keys(LIFETIMES)} value={lifetime()} onChange={setLifetime} />
                  </label>
                  <label class="check">
                    <input type="checkbox" checked={reusable()} onChange={(event) => setReusable(event.currentTarget.checked)} /> Reusable: more than one machine may join with it
                  </label>
                  <label class="field">
                    <span>Groups</span>
                    <input type="text" placeholder="Optional, comma separated" value={groups()} onInput={(event) => setGroups(event.currentTarget.value)} />
                  </label>
                </div>
              </Show>
            </fieldset>

            <Show when={mode() === "secret"}>
              <fieldset>
                <legend>Tracker discovery</legend>
                <label class="check">
                  <input type="checkbox" checked={useTrackers()} onChange={(event) => setUseTrackers(event.currentTarget.checked)} /> Use
                  trackers (recommended when no node has a public IP)
                </label>
                <Show when={useTrackers()}>
                  <label class="field">
                    <span>Trackers (one URL per line)</span>
                    <textarea
                      rows={3}
                      spellcheck={false}
                      value={trackerText()}
                      onInput={(event) => setTrackerText(event.currentTarget.value)}
                    />
                  </label>
                </Show>
              </fieldset>
            </Show>

            <fieldset>
              <legend>{mode() === "secret" && useTrackers() ? "Bootstrap peers (optional)" : "Bootstrap peers"}</legend>
              <Show when={mode() === "secret" && useTrackers()}>
                <p class="hint">
                  Trackers and in-mesh peer gossip maintain the mesh automatically. Optionally select reachable peers to dial first.
                </p>
              </Show>
              <details class="advanced-setting" open={!useTrackers() && offered().length <= 3}>
                <summary>
                  Bootstrap peers ({peersChosen().length} selected / {offered().length + extra().length} available)
                </summary>
                <Show when={offered().length || extra().length} fallback={<p class="hint">No public listener was detected. Add a reachable peer URI if needed.</p>}>
                  <ul class="choices">
                    <For each={[...offered(), ...extra().map((uri) => ({ uri, source: "added" }))]}>
                      {(item) => (
                        <li>
                          <label class="check">
                            <input type="checkbox" checked={chosen().has(item.uri)} onChange={(event) => toggle(item.uri, event.currentTarget.checked)} />
                            <span class="mono">{item.uri}</span>
                            <span class="sub">{item.source}</span>
                          </label>
                        </li>
                      )}
                    </For>
                  </ul>
                </Show>
                <div class="inline-add">
                  <input
                    type="text"
                    placeholder="quic://203.0.113.7:11012"
                    aria-label="Add a bootstrap peer URI"
                    value={custom()}
                    onInput={(event) => setCustom(event.currentTarget.value)}
                    onKeyDown={(event) => {
                      if (event.key === "Enter") {
                        event.preventDefault();
                        addCustom();
                      }
                    }}
                  />
                  <button type="button" onClick={addCustom}>
                    Add peer
                  </button>
                  <button
                    type="button"
                    class="quiet"
                    onClick={() => {
                      const saved = writeDefaultBootstrapPeers(networkName(), peersChosen());
                      setDefaultSaved(saved.length ? `Saved ${saved.length} default peer(s) for ${networkName()}.` : `Cleared defaults for ${networkName()}.`);
                    }}
                  >
                    Save as default for {networkName()}
                  </button>
                </div>
                <Show when={defaultSaved()}><p class="hint">{defaultSaved()}</p></Show>
              </details>
            </fieldset>

            <Show when={error()}>
              <p class="hint bad" role="alert">
                {error()}
              </p>
            </Show>
            <div class="dialog-actions">
              <button type="submit" class="primary" disabled={working() || !canCreate()}>
                {working() ? "Creating…" : "Create join code"}
              </button>
              <Show when={!canCreate()}>
                <span class="hint">
                  {mode() === "credential"
                    ? "Choose at least one bootstrap peer for a credential code."
                    : "Enable at least one tracker or choose a bootstrap peer."}
                </span>
              </Show>
            </div>
          </form>
        }
      >
        {(made) => (
          <div class="join-result">
            <div class="code-block">
              <div class="code-head">
                <span>
                  Join code for <b>{made().network_name}</b>
                  <Show when={made().credential_id}>
                    {" "}
                    · credential <span class="mono">{made().credential_id}</span>, expires {new Date(made().expires_unix * 1000).toLocaleString()}
                  </Show>
                </span>
                <Copy text={made().code} label="Copy join code">
                  <span>Copy</span>
                </Copy>
              </div>
              <code class="join-code">{made().code}</code>
            </div>
            <p class="hint warn-text">Anyone with this code can join the network. Share it the way you would share a password.</p>

            <div class="system-tabs">
              <Segmented label="Operating system" values={[...SYSTEMS]} value={system()} onChange={(value) => setSystem(value as System)} />
            </div>
            <ol class="steps">
              <For each={commands(system(), made().code, version())}>
                {(step) => (
                  <li>
                    <span class="step-label">{step.label}</span>
                    <div class="command">
                      <pre>{step.text}</pre>
                      <Copy text={step.text} label={`Copy: ${step.label}`} class="command-copy" />
                    </div>
                  </li>
                )}
              </For>
            </ol>
            <p class="hint">The new machine appears under Machines once it reaches a bootstrap peer.</p>
            <div class="dialog-actions">
              <button type="button" class="primary" onClick={props.onClose}>
                Done
              </button>
              <button type="button" class="link" onClick={() => setResult(null)}>
                Change options
              </button>
            </div>
          </div>
        )}
      </Show>
    </Dialog>
  );
}
