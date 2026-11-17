import { expect, test } from "@playwright/test";

test.use({ viewport: { width: 1280, height: 900 }, isMobile: false, hasTouch: false });

async function installFixture(page: import("@playwright/test").Page) {
  const requests: { path: string; body: any }[] = [];
  const current: Record<string, any> = {
    revision: 1,
    active: { network: { name: "web-fixture" }, identity: { public_key: "self-key" } },
  };
  const offline = {
    id: "instance:offline-vm:key:offline-key",
    peer_key: "offline-key",
    route: { hostname: "Offline VM", inst_id: "offline-vm", ipv4_addr: { address: { addr: 170655747 } }, version: "0.02" },
    last_seen_unix_ms: String(Date.now() - 3_600_000),
    offline_retention: "604800",
  };
  const snapshot: Record<string, any> = {
    instance: "web-fixture",
    node: { node: { peer_id: 1, hostname: "Control node", inst_id: "self", ipv4_addr: "10.44.0.1/24", version: "0.02" } },
    peers: [{
      peer_id: 2, peer_key: "live-key", path_peer_ids: [1, 2],
      route: { hostname: "Online server", inst_id: "online-server", offline_retention: "-1", ipv4_addr: { address: { addr: 170655746 } } },
      conns: [{ conn_id: "live", tunnel: { tunnel_type: "quic" } }],
    }],
    offline_machines: [offline],
  };
  await page.route("**/api/**", async (route) => {
    const path = new URL(route.request().url()).pathname.replace("/api/", "");
    const body = route.request().postDataJSON();
    requests.push({ path, body });
    let response: Record<string, any> = {};
    if (path === "snapshot") response = { ...snapshot, sampled_at_unix_ms: Date.now() };
    if (path === "config") {
      if (body?.set?.note) current.active.note = body.set.note;
      response = current;
    }
    if (path === "nodes") response = { nodes: [] };
    if (path === "schema") response = { options: [] };
    if (path === "rpc/CreateJoinCode") {
      response = { code: "lt1.fixture", network_name: "web-fixture", offline_retention: String(body.offline_retention) };
    }
    if (path === "rpc/ForgetMachine") snapshot.offline_machines = [];
    await route.fulfill({ json: response });
  });
  await page.goto("/#key=fixture");
  await expect(page.getByText("Online server", { exact: true })).toBeVisible();
  return { requests, current, snapshot };
}

test("onboarding carries each retention policy into the join request", async ({ page }, info) => {
  const { requests } = await installFixture(page);
  await page.getByRole("button", { name: "Add machine", exact: true }).click();
  const dialog = page.getByRole("dialog", { name: "Add a machine", exact: true });
  await expect(dialog.getByLabel("Keep for a period", { exact: false })).toBeChecked();
  await expect(dialog.getByLabel("Remove after being offline for")).toHaveValue("604800");
  await page.screenshot({ path: info.outputPath("onboarding-desktop.png"), fullPage: true });
  await dialog.getByLabel("Temporary", { exact: false }).check();
  await dialog.getByRole("button", { name: "Create join code", exact: true }).click();
  await expect(dialog.getByRole("status")).toContainText("Temporary");
  expect(requests.find((request) => request.path === "rpc/CreateJoinCode")?.body.offline_retention).toBe(0);
  for (const [choice, expected] of [["Keep until removed", -1], ["Keep for a period", 3600]] as const) {
    await dialog.getByRole("button", { name: "Change options" }).click();
    await dialog.getByLabel(choice, { exact: false }).check();
    if (expected > 0) await dialog.getByLabel("Remove after being offline for").selectOption("3600");
    await dialog.getByRole("button", { name: "Create join code", exact: true }).click();
    expect(requests.filter((request) => request.path === "rpc/CreateJoinCode").at(-1)?.body.offline_retention).toBe(expected);
  }
  await dialog.getByRole("button", { name: "Change options" }).click();
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: info.outputPath("onboarding-mobile.png"), fullPage: true });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await expect(dialog.getByLabel("Remove after being offline for")).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).not.toBeVisible();
});

test("offline rows retain their last seen time and support local retention and removal", async ({ page }, info) => {
  const { requests } = await installFixture(page);
  await page.getByRole("radio", { name: "Offline", exact: true }).click();
  const row = page.getByRole("row").filter({ hasText: "Offline VM" });
  await expect(row).toBeVisible();
  await expect(row).toContainText("1h ago");
  await expect(page.getByRole("row").filter({ hasText: "Online server" })).toHaveCount(0);
  await row.getByRole("button", { name: "Actions for Offline VM" }).click();
  await expect(page.getByRole("menuitem", { name: "Manage node" })).toBeDisabled();
  await page.getByRole("menuitem", { name: "Offline retention…" }).click();
  const dialog = page.getByRole("dialog", { name: "Offline retention for Offline VM" });
  await dialog.getByLabel("Keep until removed", { exact: false }).check();
  await dialog.getByRole("button", { name: "Save retention" }).click();
  await expect(dialog).not.toBeVisible();
  expect(requests.find((request) => request.path === "config" && request.body)?.body.set.note)
    .toEqual([{ peer: "offline-key", offline_retention: -1 }]);
  await row.click();
  await expect(page.getByRole("heading", { name: "Offline", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Connections", exact: true })).toHaveCount(0);
  await page.screenshot({ path: info.outputPath("offline-machine.png"), fullPage: true });
  await row.getByRole("button", { name: "Actions for Offline VM" }).click();
  await page.getByRole("menuitem", { name: "Forget offline record" }).click();
  await expect(row).not.toBeVisible();
  expect(requests.find((request) => request.path === "rpc/ForgetMachine")?.body).toEqual({ id: "instance:offline-vm:key:offline-key" });
});
