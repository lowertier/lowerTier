import assert from "node:assert/strict";
import test from "node:test";
import { parse, stringify } from "smol-toml";
import { credentialChanges, FLEET_GUI_CIDRS, guiChanges, guiRules, optionPatch, overlaySubnet, secretChanges } from "../src/settingsModel.ts";

test("ACL child updates retain the exact path through TOML serialization", () => {
  const body = parse(stringify(optionPatch({ "acl.tcp_ports": ["22"], "acl.udp_ports": null })));
  assert.deepEqual(Object.entries(body.set), [["acl.tcp_ports", ["22"]]]);
  assert.deepEqual(body.clear, ["acl.udp_ports"]);
  assert.throws(() => optionPatch({ acl: {}, "acl.tcp_ports": null }), /Overlapping settings/);
});

test("credential source changes clear the conflicting source and derived public key", () => {
  assert.deepEqual(secretChanges("control.secret", "file", "/private/control.secret"), {
    "control.secret": null, "control.secret_file": "/private/control.secret",
  });
  assert.deepEqual(secretChanges("identity.private_key", "value", "new-key"), {
    "identity.private_key": "new-key", "identity.private_key_file": null, "identity.public_key": null,
  });
  const credential = credentialChanges("signed-bundle");
  assert.equal(credential["network.secret"], null);
  assert.equal(credential["identity.private_key"], null);
  assert.equal(credential["identity.private_key_file"], null);
  assert.equal(credential["identity.public_key"], null);
  assert.equal(credential["network.credential"], "signed-bundle");
  assert.equal("identity.credential_root" in credential, false);
});

test("GUI access rules preserve key requirements and explicit empty access", () => {
  const rules = guiRules(["192.0.2.0/24", "198.51.100.0/24"], ["198.51.100.0/24"]);
  assert.equal(rules.length, 2);
  assert.deepEqual(guiChanges(rules), {
    "gui.allow": ["192.0.2.0/24", "198.51.100.0/24"], "gui.open": ["198.51.100.0/24"],
  });
  assert.deepEqual(guiChanges(guiRules([])), { "gui.allow": [], "gui.open": [] });
  assert.deepEqual(guiChanges(guiRules(undefined)), { "gui.allow": null, "gui.open": [] });
  assert.throws(() => guiChanges([...rules, rules[0]]), /Duplicate source CIDR/);
});

test("adding a keyed source preserves the default overlay subnet", () => {
  const subnet = overlaySubnet("10.201.70.2/24");
  assert.equal(subnet, "10.201.70.0/24");
  const changes = guiChanges([...guiRules(undefined), { cidr: "192.0.2.0/24", requireKey: true }], subnet);
  assert.deepEqual(changes, { "gui.allow": ["192.0.2.0/24", "10.201.70.0/24"], "gui.open": [] });
  assert.throws(() => guiChanges([...guiRules(undefined), { cidr: "192.0.2.0/24", requireKey: true }]), /Wait for the overlay address/);
});

test("fleet source networks remain in both arrays without a key", () => {
  const changes = guiChanges([{ cidr: "192.0.2.0/24", requireKey: true }], undefined, true);
  assert.deepEqual(changes["gui.open"], FLEET_GUI_CIDRS);
  for (const cidr of FLEET_GUI_CIDRS) assert.equal(changes["gui.allow"].includes(cidr), true);
  assert.equal(changes["gui.open"].includes("192.0.2.0/24"), false);
});
