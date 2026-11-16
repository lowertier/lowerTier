import { expect, test } from "@playwright/test";
import { installVpnFixture } from "./vpn-fixture.mjs";

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
  await expect(page.getByRole("heading", { name: "Add your network" })).toBeInViewport();
  await expect(page.locator(".device-overview")).toHaveCount(0);
  await page.getByRole("radio", { name: "Import TOML" }).check();
  await page.getByRole("textbox", { name: "Profile name" }).fill("Local fixture");
  await page.getByRole("textbox", { name: "Configuration", exact: true }).fill('[address]\nipv4 = "10.44.0.9/24"');
  await page.getByRole("button", { name: "Save network" }).click();
  await expect(page.getByText("VPN controls require the iOS app.", { exact: true })).toBeVisible();
  await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
  await page.setViewportSize({ width: 320, height: 844 });
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)).toBe(true);
  await page.getByRole("navigation").getByRole("button", { name: "Machines" }).click();
  await expect(page.getByRole("heading", { name: "Machines", exact: true })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Add your network" })).toHaveCount(0);
  expect(failures).toEqual([]);
});

test("native IPC owns profile storage and the system VPN state controls the connection display", async ({ page }) => {
  await page.addInitScript(installVpnFixture);
  await page.goto("/");
  await page.getByRole("button", { name: "Add a network", exact: true }).last().click();
  await page.getByRole("textbox", { name: "Profile name" }).fill("Fixture network");
  await page.getByRole("textbox", { name: "Network name", exact: true }).fill("fixture");
  await page.getByLabel("Network secret", { exact: true }).fill("fixture-secret-not-for-storage");
  await page.getByRole("textbox", { name: "Overlay address" }).fill("10.44.0.9/24");
  await page.getByRole("textbox", { name: "Peer addresses" }).fill("quic://127.0.0.1:11012");
  await page.getByRole("button", { name: "Save network" }).click();
  await expect(page.getByRole("heading", { name: "Fixture network" })).toBeVisible();
  await page.getByRole("navigation").getByRole("button", { name: "Settings" }).click();
  await page.getByRole("button", { name: "Replace configuration" }).click();
  await expect(page.getByRole("heading", { name: "Network setup" })).toBeVisible();
  await page.getByRole("button", { name: "Close network setup" }).click();
  await expect(page.getByRole("heading", { name: "Network profile", exact: true })).toBeVisible();
  await page.getByRole("navigation").getByRole("button", { name: "Connect", exact: true }).click();
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

test("one visible poll owns sampling and discards a reply from before disconnect", async ({ page }) => {
  await page.clock.install();
  await page.addInitScript(installVpnFixture, {
    state: "connected", profile: { id: "fixture-profile", name: "Fixture network" }, members: true,
  });
  await page.goto("/");
  await expect(page.getByText("3 machines available")).toBeVisible();
  await page.clock.runFor(3100);
  const calls = await page.evaluate(() => (window as any).nativeRequests);
  expect(calls.map((call: any) => call.action)).toEqual(["poll", "poll", "poll", "poll"]);

  await page.getByRole("navigation").getByRole("button", { name: "Routes" }).click();
  await expect(page.locator(".device-route").first()).toContainText("Mac Studio");
  await expect(page.locator(".device-route").first()).toContainText("10.44.0.2");
  await expect(page.locator(".device-route").first()).toContainText("1 hop");
  await expect(page.locator(".device-route").nth(2)).toContainText("2 hops");
  await expect(page.locator(".device-route").last()).toContainText("Path unavailable");
  await page.evaluate(() => {
    const runtime = window as any;
    runtime.fixtureHidden = true;
    Object.defineProperty(document, "hidden", { configurable: true, get: () => runtime.fixtureHidden });
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await page.clock.runFor(6000);
  expect(await page.evaluate(() => (window as any).nativeRequests.length)).toBe(4);
  await page.evaluate(() => {
    (window as any).fixtureHidden = false;
    document.dispatchEvent(new Event("visibilitychange"));
  });
  await expect.poll(() => page.evaluate(() => (window as any).nativeRequests.length)).toBe(5);
  await page.evaluate(() => { (window as any).blockNextVpnPoll = true; });
  await page.clock.runFor(1000);
  expect(await page.evaluate(() => (window as any).activeVpnPolls)).toBe(1);
  await page.getByRole("navigation").getByRole("button", { name: "Settings" }).click();
  await page.evaluate(() => { (window as any).blockNextVpnLogs = true; });
  await page.getByRole("button", { name: "Read recent logs" }).click();
  await page.getByRole("navigation").getByRole("button", { name: "Connect", exact: true }).click();
  await page.getByRole("button", { name: "Disconnect", exact: true }).click();
  await expect(page.locator(".device-status")).toHaveText("Disconnected");
  await page.evaluate(() => (window as any).releaseVpnPoll());
  await page.evaluate(() => (window as any).releaseVpnLogs());
  await expect.poll(() => page.evaluate(() => (window as any).activeVpnPolls)).toBe(0);
  await expect(page.getByText("No address yet")).toBeVisible();
  await page.getByRole("navigation").getByRole("button", { name: "Settings" }).click();
  await expect(page.getByRole("button", { name: "Read recent logs" })).toBeDisabled();
  await expect(page.getByLabel("Recent VPN logs")).toHaveCount(0);
  expect(await page.evaluate(() => (window as any).maxVpnPolls)).toBe(1);
});

test("a system connection generation invalidates logs without a local VPN action", async ({ page }) => {
  await page.clock.install();
  await page.addInitScript(installVpnFixture, {
    state: "connected", profile: { id: "fixture-profile", name: "Fixture network" }, members: true,
  });
  await page.goto("/");
  await expect(page.getByText("3 machines available")).toBeVisible();
  await page.getByRole("navigation").getByRole("button", { name: "Settings" }).click();
  for (const failure of [false, true]) {
    await page.evaluate(() => { (window as any).blockNextVpnLogs = true; });
    await page.getByRole("button", { name: "Read recent logs" }).click();
    await page.evaluate(() => (window as any).setVpnState("connected"));
    await page.clock.runFor(1000);
    await page.evaluate((fail) => {
      (window as any).failNextVpnLogs = fail;
      (window as any).releaseVpnLogs();
    }, failure);
    await expect(page.getByLabel("Recent VPN logs")).toHaveCount(0);
    await expect(page.getByRole("alert")).toHaveCount(0);
  }
  await page.getByRole("button", { name: "Read recent logs" }).click();
  await expect(page.getByLabel("Recent VPN logs")).toContainText("Fixture: packet interface attached");
});
