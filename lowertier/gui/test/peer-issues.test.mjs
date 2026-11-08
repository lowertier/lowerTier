import assert from "node:assert/strict";
import test from "node:test";
import { issuesOf, olderVersion } from "../src/peerIssues.ts";

const current = "2.6.4-v2.6.4-lowertier.6-199-g4a5b7dfe";
const older = "2.6.4-v2.6.4-lowertier.6-198-g12345678";
const peer = (changes = {}) => ({ id: 1, name: "peer", direct: true, version: current, ...changes });

test("latency, loss, and missing measurements do not add direct peers", () => {
  const rows = [peer({ rtt: 5_000_000 }), peer({ loss: 900_000 }), peer({ rtt: undefined })];
  assert.deepEqual(issuesOf(rows, current), []);
});

test("a peer without an active direct connection needs attention", () => {
  const row = peer({ direct: false, via: undefined, rtt: 1000 });
  assert.deepEqual(issuesOf([row], current).map((issue) => issue.reason), ["No direct connection"]);
});

test("older peers appear once with all applicable reasons", () => {
  const issues = issuesOf([peer({ direct: false, version: older }), peer({ id: 2, version: older })], current);
  assert.equal(issues.length, 2);
  assert.equal(issues[0].reason, "No direct connection; Older LowTier version");
  assert.equal(issues[1].reason, "Older LowTier version");
});

test("versions compare release numbers, prereleases, and Git tag distances numerically", () => {
  for (const [left, right] of [
    ["2.6.3", "2.6.4"],
    ["2.6.9", "2.6.10"],
    ["v2.6.4-lowertier.9", "v2.6.4-lowertier.10"],
    [older, current],
    ["2.6.4-rc.1", "2.6.4"],
    ["2.6.4-alpha", "2.6.4-beta"],
    ["2.6.4-rc.1", "2.6.4-rc.1.1"],
    ["2.6.4-1", "2.6.4-alpha"],
  ]) {
    assert.equal(olderVersion(left, right), true, `${left} < ${right}`);
    assert.equal(olderVersion(right, left), false, `${right} >= ${left}`);
  }
});

test("equal or newer versions and unknown versions do not add direct peers", () => {
  for (const value of [current, current + "~", "2.6.4-v2.6.4-lowertier.6-200-g12345678", "", "unknown", "4a5b7dfe", "2.6.4-4a5b7dfe", "2.6.4-eeeeeeee~"]) {
    assert.deepEqual(issuesOf([peer({ version: value })], current), [], value);
  }
  assert.equal(olderVersion(older, "unknown"), false);
  assert.equal(olderVersion(older, "2.6.4-4a5b7dfe"), false);
});

test("commit IDs and build metadata do not establish version age", () => {
  assert.equal(olderVersion("2.6.4-v2.6.4-lowertier.6-199-g00000000", current), false);
  assert.equal(olderVersion("2.6.4+build.1", "2.6.4+build.2"), false);
});
