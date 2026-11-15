import assert from "node:assert/strict";
import test from "node:test";
import { bytes, clock, counterShares, latency, NONE, numeric, rate } from "../src/format.ts";

test("protobuf integer strings use the same display units as numeric values", () => {
  assert.equal(bytes("42"), "42 B");
  assert.equal(bytes("1024"), "1.00 KiB");
  assert.equal(rate("2000000"), "2.00 Mbit/s");
  assert.equal(latency("1250"), "1.3 ms");
  assert.equal(clock("1700000000000"), clock(1700000000000));
});

test("absent or invalid measurements remain absent", () => {
  assert.equal(numeric(null), undefined);
  assert.equal(bytes(), NONE);
  assert.equal(rate("invalid"), NONE);
  assert.equal(latency(), NONE);
  assert.equal(bytes("0"), "0 B");
});

test("path shares sum integer strings without concatenation", () => {
  assert.deepEqual(counterShares(["10", "30"]), [0.25, 0.75]);
  assert.deepEqual(counterShares(["18446744073709551615", "18446744073709551615"]), [0.5, 0.5]);
  assert.deepEqual(counterShares(["0", 0]), [0, 0]);
  assert.deepEqual(counterShares([]), []);
});
