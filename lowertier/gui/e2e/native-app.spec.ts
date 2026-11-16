import { expect, test } from "@playwright/test";

test("the shared app layout reflows and keeps browser VPN controls inactive", async ({ page }, info) => {
  const failures: string[] = [];
  page.on("pageerror", (error) => failures.push(error.message));
  await page.goto("/?layout=app");
  await expect(page.getByRole("heading", { name: "Your private network" })).toBeVisible();
  for (const width of [320, 390, 820]) {
    await page.setViewportSize({ width, height: 844 });
    expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  }
  await page.setViewportSize({ width: 390, height: 844 });
  await page.screenshot({ path: info.outputPath("ios-layout.png"), fullPage: true });
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: "Settings" }).click();
  await page.getByRole("radio", { name: "Night" }).check();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
  await page.getByRole("navigation", { name: "Main navigation" }).getByRole("button", { name: "Connect", exact: true }).click();
  await page.screenshot({ path: info.outputPath("ios-layout-dark.png"), fullPage: true });
  await page.getByRole("button", { name: "Add a network", exact: true }).last().click();
  await page.getByRole("radio", { name: "Import TOML" }).check();
  await page.getByRole("textbox", { name: "Profile name" }).fill("Local fixture");
  await page.getByRole("textbox", { name: "Configuration", exact: true }).fill('[address]\nipv4 = "10.44.0.9/24"');
  await page.getByRole("button", { name: "Save network" }).click();
  await expect(page.getByText("VPN controls require the iOS app.", { exact: true })).toBeVisible();
  await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
  await page.setViewportSize({ width: 320, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  expect(failures).toEqual([]);
});

test("native IPC owns profile storage and the system VPN state controls the connection display", async ({ page }) => {
  await page.addInitScript(() => {
    const runtime = window as any;
    runtime.isTauri = true;
    let state = "disconnected";
    let profile: { id: string; name: string } | undefined;
    runtime.nativeRequests = [];
    runtime.setVpnState = (next: string) => { state = next; };
    const status = () => ({ state, platform: "ios", mtu: 1280, lastError: "", profile });
    runtime.__TAURI_INTERNALS__ = {
      invoke: async (command: string, args: { action: string; payload: string }) => {
        if (command !== "plugin:lowertier-vpn|execute") throw new Error("Unexpected native command.");
        const body = JSON.parse(args.payload);
        runtime.nativeRequests.push({ action: args.action, body });
        if (args.action === "saveProfile") {
          profile = { id: "fixture-profile", name: body.name };
          return status();
        }
        if (args.action === "connect") { state = "connecting"; return status(); }
        if (args.action === "disconnect") { state = "disconnected"; return status(); }
        if (args.action === "request") return {
          sampled_at_unix_ms: Date.now(),
          node: { node: { hostname: "iPhone", ipv4_addr: "10.44.0.9/24", inst_id: "fixture", peer_id: 1 } },
          peers: [], routes: [], paths: [],
        };
        return status();
      },
    };
  });
  await page.goto("/");
  await page.getByRole("button", { name: "Add a network", exact: true }).last().click();
  await page.getByRole("textbox", { name: "Profile name" }).fill("Fixture network");
  await page.getByRole("textbox", { name: "Network name", exact: true }).fill("fixture");
  await page.getByLabel("Network secret", { exact: true }).fill("fixture-secret-not-for-storage");
  await page.getByRole("textbox", { name: "Overlay address" }).fill("10.44.0.9/24");
  await page.getByRole("textbox", { name: "Peer addresses" }).fill("quic://127.0.0.1:11012");
  await page.getByRole("button", { name: "Save network" }).click();
  await expect(page.getByRole("heading", { name: "Fixture network" })).toBeVisible();
  expect(await page.evaluate(() => JSON.stringify({ ...localStorage, ...sessionStorage }))).not.toContain("fixture-secret");
  const config = await page.evaluate(() => (window as any).nativeRequests.find((call: any) => call.action === "saveProfile").body.config);
  expect(config).toContain('secret = "fixture-secret-not-for-storage"');
  expect(config).toContain('ipv4 = "10.44.0.9/24"');
  await page.getByRole("button", { name: "Connect", exact: true }).first().click();
  await expect(page.locator(".device-status")).toHaveText("Connecting");
  await expect(page.locator(".device-status")).not.toHaveText("VPN active");
  await page.evaluate(() => (window as any).setVpnState("connected"));
  await expect(page.locator(".device-status")).toHaveText("VPN active");
  await expect(page.getByText("10.44.0.9", { exact: true })).toBeVisible();
  await page.evaluate(() => (window as any).setVpnState("reconnecting"));
  await expect(page.locator(".device-status")).toHaveText("Reconnecting");
  await expect(page.getByRole("button", { name: "Disconnect", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await expect(page.locator(".device-status")).toHaveText("Disconnected");
  await expect(page.getByText("No address yet")).toBeVisible();
});
