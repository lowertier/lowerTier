import assert from "node:assert/strict";
import test from "node:test";
import { offlineRows } from "../src/offlineMachines.ts";
import { retentionSeconds } from "../src/retention.ts";

test("offline records expire, merge with returning instances, and contain no live metrics", () => {
  const record = {
    id: "instance:builder:key:key", peer_key: "key",
    route: { inst_id: "builder", hostname: "builder", version: "0.02" },
    offline_retention: "3600", last_seen_unix_ms: "1000",
  };
  const rows = offlineRows([record], [], 2000, () => -2, () => "Build machine");
  assert.equal(rows[0].name, "Build machine");
  assert.equal(rows[0].online, false);
  assert.equal(rows[0].secure, false);
  assert.equal(rows[0].rtt, undefined);
  assert.equal(rows[0].via, undefined);
  assert.equal(rows[0].rx, 0);
  assert.deepEqual(rows[0].hops, []);
  assert.deepEqual(offlineRows([record], [], 3_601_000, () => -2, () => undefined), []);
  const returning = { key: "key", raw: { route: { inst_id: "builder" } } };
  assert.deepEqual(offlineRows([record], [returning], 2000, () => -2, () => undefined), []);
  const otherKey = { key: "other-key", raw: { route: { inst_id: "builder" } } };
  assert.equal(offlineRows([record], [otherKey], 2000, () => -2, () => undefined).length, 1);
  const otherInstance = { key: "key", raw: { route: { inst_id: "other-builder" } } };
  assert.equal(offlineRows([record], [otherInstance], 2000, () => -2, () => undefined).length, 1);
  assert.equal(offlineRows([{ ...record, offline_retention: "-1" }], [], 1e15, () => -2, () => undefined).length, 1);
  assert.equal(retentionSeconds("temporary", 3600), 0);
  assert.equal(retentionSeconds("permanent", 3600), -1);
  assert.equal(retentionSeconds("retained", 3600), 3600);
});
