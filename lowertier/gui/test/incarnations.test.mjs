import assert from "node:assert/strict";
import test from "node:test";
import { currentIncarnations } from "../src/incarnations.ts";

const peer = (peer_id, inst_id, conns, path) => ({ peer_id, route: { inst_id }, conns, path_peer_ids: path });

test("ghost routes of restarted instances are hidden", () => {
  const live = [{ is_closed: false }];
  const rows = currentIncarnations(
    [
      peer(1, "self", [], [9, 1]),
      peer(2, "other", [], [9, 5, 2]),
      peer(3, "other", live, [9, 3]),
      peer(4, "lone", [], [9, 6, 4]),
      peer(5, undefined, [], []),
    ],
    "self",
    9,
  );
  assert.deepEqual(rows.map((row) => row.peer_id).sort(), [3, 4, 5]);
});
