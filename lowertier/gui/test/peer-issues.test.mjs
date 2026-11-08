import assert from "node:assert/strict";
import test from "node:test";
import { issuesOf, olderVersion } from "../src/peerIssues.ts";

const current = "0.01";
const older = "0.00";
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

test("versions compare software release numbers numerically", () => {
  for (const [left, right] of [
    ["0.01", "0.02"],
    ["0.09", "0.10"],
    ["0.99", "0.100"],
    ["0.99", "1.00"],
    [older, current],
  ]) {
    assert.equal(olderVersion(left, right), true, `${left} < ${right}`);
    assert.equal(olderVersion(right, left), false, `${right} >= ${left}`);
  }
});

test("equal or newer versions and unknown versions do not add direct peers", () => {
  for (const value of [current, current + "~", "0.02", "", "unknown", "0", "0.1", "1.2.3"]) {
    assert.deepEqual(issuesOf([peer({ version: value })], current), [], value);
  }
  assert.equal(olderVersion(older, "unknown"), false);
  assert.equal(olderVersion(older, "0.01-build"), false);
});

test("build metadata and unsafe numeric components do not establish version age", () => {
  assert.equal(olderVersion("0.01+build.1", "0.01+build.2"), false);
  assert.equal(olderVersion("0.9007199254740992", "0.9007199254740993"), false);
});
