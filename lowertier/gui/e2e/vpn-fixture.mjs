// This fixture supplies browser test data. It does not run a VPN.
export function installVpnFixture(options = {}) {
  const runtime = window;
  runtime.isTauri = true;
  let state = options.state ?? "disconnected";
  let profile = options.profile;
  let sequence = 0;
  let connectionGeneration = 0;
  runtime.nativeRequests = [];
  runtime.activeVpnPolls = 0;
  runtime.maxVpnPolls = 0;
  runtime.setVpnState = (next) => { state = next; connectionGeneration++; };
  const status = () => ({
    state, platform: "ios", mtu: 1280, connectionGeneration, lastError: "", profile,
    ...(state === "connected" ? { connectedAt: Date.now() - 185_000 } : {}),
  });
  const snapshot = () => ({
    sampled_at_unix_ms: Date.now(), instance: "ios",
    node: { node: { hostname: "iPhone", ipv4_addr: "10.44.0.9/24", inst_id: "fixture-phone", peer_id: 1 } },
    peers: options.members ? [
      { peer_id: 2, peer_key: "fixture-key-2", path_peer_ids: [1, 2], end_to_end_session_ready: true,
        route: { hostname: "Mac Studio", ipv4_addr: { address: { addr: 170655746 } }, inst_id: "fixture-mac", version: "0.01" },
        conns: [{ conn_id: "fixture-quic", tunnel: { tunnel_type: "QUIC" }, stats: {
          rx_bytes: String(sequence * 750_000), tx_bytes: String(sequence * 250_000), latency_us: 3200,
        } }] },
      { peer_id: 3, peer_key: "fixture-key-3", path_peer_ids: [1, 3], end_to_end_session_ready: true,
        route: { hostname: "Lab server", ipv4_addr: { address: { addr: 170655747 } }, inst_id: "fixture-lab", version: "0.01" },
        conns: [{ conn_id: "fixture-h2", tunnel: { tunnel_type: "H2" }, stats: {
          rx_bytes: String(sequence * 250_000), tx_bytes: String(sequence * 125_000), latency_us: 14600,
        } }] },
      { peer_id: 4, peer_key: "fixture-key-4", path_peer_ids: [1, 3, 4], end_to_end_session_ready: true,
        route: { hostname: "Home NAS", ipv4_addr: { address: { addr: 170655748 } }, inst_id: "fixture-nas", version: "0.01", next_hop_peer_id: 3 },
        conns: [], rtt_us: 28600 },
    ] : [],
    routes: options.members ? [
      { destination: "2", policy: "hop", effective_policy: "hop", path_peer_ids: [1, 2], measured_rtt_us: 3200,
        route: { peer_id: 2, hostname: "Mac Studio", ipv4_addr: { address: { addr: 170655746 } } } },
      { destination: "3", policy: "hop", effective_policy: "hop", path_peer_ids: [1, 3], measured_rtt_us: 14600,
        route: { peer_id: 3, hostname: "Lab server", ipv4_addr: { address: { addr: 170655747 } } } },
      { destination: "4", policy: "hop", effective_policy: "hop", path_peer_ids: [1, 3, 4], measured_rtt_us: 28600,
        route: { peer_id: 4, hostname: "Home NAS", ipv4_addr: { address: { addr: 170655748 } } } },
      { destination: "5", policy: "hop", path_peer_ids: [], path_error: "No path",
        route: { peer_id: 5, hostname: "Remote workstation", ipv4_addr: { address: { addr: 170655749 } } } },
    ] : [],
  });
  runtime.__TAURI_INTERNALS__ = {
    invoke: async (command, args) => {
      if (command !== "plugin:lowertier-vpn|execute") throw new Error("Unexpected native command.");
      if (!args.payload || typeof args.payload !== "object") throw new Error("The native payload must be an object.");
      const body = args.payload;
      runtime.nativeRequests.push({ action: args.action, body });
      if (args.action === "saveProfile") {
        profile = { id: "fixture-profile", name: body.name };
        return status();
      }
      if (args.action === "connect") { state = "connecting"; connectionGeneration++; return status(); }
      if (args.action === "disconnect") { state = "disconnected"; connectionGeneration++; return status(); }
      if (args.action === "poll") {
        runtime.activeVpnPolls++;
        runtime.maxVpnPolls = Math.max(runtime.maxVpnPolls, runtime.activeVpnPolls);
        sequence++;
        const result = { status: status(), ...(state === "connected" ? { snapshot: snapshot() } : {}) };
        if (runtime.blockNextVpnPoll) {
          runtime.blockNextVpnPoll = false;
          await new Promise((resolve) => { runtime.releaseVpnPoll = resolve; });
        }
        runtime.activeVpnPolls--;
        return result;
      }
      if (args.action === "request" && body.path === "rpc/ReadLogs") {
        if (runtime.blockNextVpnLogs) {
          runtime.blockNextVpnLogs = false;
          await new Promise((resolve) => { runtime.releaseVpnLogs = resolve; });
        }
        if (runtime.failNextVpnLogs) {
          runtime.failNextVpnLogs = false;
          throw new Error("The old connection log request failed.");
        }
        return { logs: [
          { level: "INFO", message: "Fixture: packet interface attached at MTU 1280." },
          { level: "INFO", message: "Fixture: authenticated QUIC connection established." },
        ] };
      }
      throw new Error("Unexpected native action: " + args.action);
    },
  };
}
