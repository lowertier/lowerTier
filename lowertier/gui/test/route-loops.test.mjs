import assert from "node:assert/strict";
import test from "node:test";
import { disambiguatePeerNames, sanitizeHops, selectViaPeerId } from "../src/routeLoops.ts";

test("sanitizeHops strips self and collapses cyclic detours", () => {
  assert.deepEqual(sanitizeHops([10, 20, 30, 20, 40], 10, 40), [20, 40]);
  assert.deepEqual(sanitizeHops([10, 10], 10, 99), [99]);
  assert.deepEqual(sanitizeHops([10], 10, 10), []);
});

test("selectViaPeerId blocks self-via, direct peers, and same-incarnation loops", () => {
  const peersById = new Map([
    [1, { key: "k-self", inst: "inst-self" }],
    [2, { key: "k-peer", inst: "inst-peer" }],
    [3, { key: "k-peer-old", inst: "inst-peer" }],
    [4, { key: "k-self-old", inst: "inst-self" }],
    [5, { key: "k-relay", inst: "inst-relay" }],
  ]);

  // Direct peer never gets a via label.
  assert.equal(
    selectViaPeerId({
      peerId: 2,
      peerKey: "k-peer",
      peerInst: "inst-peer",
      direct: true,
      pathPeerIds: [1, 5, 2],
      routeNextHop: 5,
      selfId: 1,
      selfInst: "inst-self",
      selfKey: "k-self",
      peersById,
    }),
    undefined,
  );

  // Fallback next_hop_peer_id === self is rejected instead of showing "via <this node>".
  assert.equal(
    selectViaPeerId({
      peerId: 2,
      direct: false,
      pathPeerIds: [1],
      routeNextHop: 1,
      selfId: 1,
      peersById,
    }),
    undefined,
  );

  // Hop sharing peer's inst_id or key is rejected (stale incarnation loop).
  assert.equal(
    selectViaPeerId({
      peerId: 2,
      peerKey: "k-peer",
      peerInst: "inst-peer",
      direct: false,
      pathPeerIds: [1, 3, 2],
      routeNextHop: 3,
      selfId: 1,
      peersById,
    }),
    undefined,
  );

  // Hop sharing self's inst_id or key is rejected.
  assert.equal(
    selectViaPeerId({
      peerId: 2,
      direct: false,
      pathPeerIds: [1, 4, 2],
      routeNextHop: 4,
      selfId: 1,
      selfInst: "inst-self",
      selfKey: "k-self",
      peersById,
    }),
    undefined,
  );

  // Distinct relay hop is preserved.
  assert.equal(
    selectViaPeerId({
      peerId: 2,
      peerKey: "k-peer",
      peerInst: "inst-peer",
      direct: false,
      pathPeerIds: [1, 5, 2],
      routeNextHop: 5,
      selfId: 1,
      selfInst: "inst-self",
      selfKey: "k-self",
      peersById,
    }),
    5,
  );
});

test("disambiguatePeerNames qualifies dual-instance same-hostname peers without affecting aliases", () => {
  const names = disambiguatePeerNames(
    [
      { id: 1960438006, alias: "", hostname: "boyus-Mac-Studio.local", address: "10.126.126.202/24" },
      { id: 3379560202, alias: "", hostname: "861jp", address: "10.126.126.81/24" },
      { id: 4008033949, alias: "custom-yutoms", hostname: "861jp", address: "10.126.126.70/24" },
    ],
    "boyus-Mac-Studio.local",
  );
  assert.equal(names.get(1960438006), "boyus-Mac-Studio.local (10.126.126.202)");
  assert.equal(names.get(3379560202), "861jp");
  assert.equal(names.get(4008033949), "custom-yutoms");

  // Remote view where two distinct instances share the same hostname.
  const remoteNames = disambiguatePeerNames(
    [
      { id: 3883748651, alias: "", hostname: "boyus-Mac-Studio.local", address: "10.126.126.2/24" },
      { id: 1960438006, alias: "", hostname: "boyus-Mac-Studio.local", address: "10.126.126.202/24" },
    ],
    "jpaws",
  );
  assert.equal(remoteNames.get(3883748651), "boyus-Mac-Studio.local (10.126.126.2)");
  assert.equal(remoteNames.get(1960438006), "boyus-Mac-Studio.local (10.126.126.202)");
});
