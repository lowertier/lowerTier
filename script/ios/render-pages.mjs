import { createServer } from "node:http";
import { createRequire } from "node:module";
import { mkdir, readFile, writeFile } from "node:fs/promises";
import { dirname, extname, join, relative, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { installVpnFixture } from "../../lowertier/gui/e2e/vpn-fixture.mjs";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "../..");
const frontend = join(root, "lowertier/gui");
const output = resolve(process.argv[2] ?? join(root, "docs/ios-app-preview"));
const evidence = join(root, "benchmark-results/.work/ios-review-20261116/renders");
const require = createRequire(join(frontend, "package.json"));
const { webkit } = require("@playwright/test");
const pages = [
  { file: "connect", title: "Connect", tab: "Connect", state: "connected" },
  { file: "machines", title: "Machines", tab: "Machines", state: "connected" },
  { file: "routes", title: "Routes", tab: "Routes", state: "connected" },
  { file: "settings", title: "Settings", tab: "Settings", state: "connected", logs: true },
  { file: "machine-detail", title: "Machine details", tab: "Machines", state: "connected", detail: true },
  { file: "connect-dark", title: "Connect · dark appearance", tab: "Connect", state: "connected", dark: true },
  { file: "unconfigured", title: "No network configured", tab: "Connect" },
  { file: "disconnected", title: "Saved network · disconnected", tab: "Connect", state: "disconnected" },
  { file: "connecting", title: "Connecting", tab: "Connect", state: "connecting" },
  { file: "reconnecting", title: "Reconnecting", tab: "Connect", state: "reconnecting" },
  { file: "quick-setup", title: "Quick setup", tab: "Connect", setup: "quick" },
  { file: "import-setup", title: "Import TOML", tab: "Connect", setup: "import" },
];
const reviewCss = `
.render-note { margin: 0; padding: .75rem max(1rem, env(safe-area-inset-left)); background: var(--device-card);
  color: var(--device-ink); border-block-end: 1px solid var(--device-line); font: .8rem/1.5 system-ui; overflow-wrap: anywhere; }
.render-note a { color: var(--device-blue); margin-inline-end: 1rem; }
.device-tabs a { display: grid; justify-items: center; align-content: center; gap: .3rem; padding: .4rem .15rem;
  font-size: .65rem; font-weight: 500; color: var(--device-muted); text-decoration: none; min-block-size: 2.75rem; }
.device-tabs a[aria-current] { color: var(--device-blue); }
.render-gallery { max-inline-size: 68rem; margin: auto; padding: 2rem 1.25rem; color: var(--device-ink); }
.render-gallery h1 { font-size: 2rem; margin-block-end: 1rem; }
.render-gallery h2 { font-size: 1.2rem; margin-block: 1.5rem .75rem; }
.render-gallery p { max-inline-size: 70ch; margin-block: .75rem; }
.render-pages { display: grid; grid-template-columns: repeat(auto-fit, minmax(min(100%, 15rem), 1fr)); gap: .75rem;
  list-style: none; padding: 0; }
.render-pages a { display: block; border: 1px solid var(--device-line); border-radius: .8rem; padding: 1rem;
  color: var(--device-blue); background: var(--device-card); text-decoration: none; min-block-size: 3rem; }
.render-path { display: flex; flex-wrap: wrap; gap: .5rem; align-items: center; padding: 1rem 0; }
.render-path span { border: 1px solid var(--device-line); border-radius: .5rem; padding: .5rem .75rem; background: var(--device-card); }
.render-gallery table { border-collapse: collapse; inline-size: 100%; table-layout: fixed; text-align: start; }
.render-gallery th, .render-gallery td { border-block-end: 1px solid var(--device-line); padding: .75rem .5rem;
  vertical-align: top; overflow-wrap: anywhere; white-space: normal; }
`;

await mkdir(output, { recursive: true });
await mkdir(evidence, { recursive: true });
await writeFile(join(output, "app.css"), await readFile(join(frontend, "dist/app.css"), "utf8") + reviewCss);
const server = createServer(async (request, response) => {
  try {
    const pathname = decodeURIComponent(new URL(request.url, "http://localhost").pathname);
    const review = pathname.startsWith("/review/");
    const base = review ? output : join(frontend, "dist");
    const name = (review ? pathname.slice(8) : pathname.slice(1)) || "index.html";
    const target = resolve(base, name);
    if (relative(base, target).startsWith("..")) throw new Error("Invalid artifact path.");
    const body = await readFile(target);
    response.writeHead(200, { "content-type": {
      ".html": "text/html; charset=utf-8", ".css": "text/css; charset=utf-8", ".js": "text/javascript",
    }[extname(target)] ?? "application/octet-stream" });
    response.end(body);
  } catch {
    response.writeHead(404);
    response.end("Not found");
  }
});
await new Promise((done) => server.listen(0, "127.0.0.1", done));
const origin = `http://127.0.0.1:${server.address().port}`;
const browser = await webkit.launch();
const results = [];
try {
  for (const spec of pages) {
    const context = await browser.newContext({
      viewport: { width: 390, height: 844 }, deviceScaleFactor: 1, isMobile: true,
      colorScheme: spec.dark ? "dark" : "light",
    });
    const page = await context.newPage();
    await page.clock.install({ time: new Date("2026-11-16T00:00:00Z") });
    const errors = [];
    page.on("pageerror", (error) => errors.push(error.message));
    if (spec.state) {
      await page.addInitScript(installVpnFixture, {
        state: spec.state, profile: { id: "fixture-profile", name: "Studio network" }, members: true,
      });
    }
    await page.goto(origin + "/?layout=app");
    await page.getByRole("heading", { name: "Your private network" }).waitFor();
    if (spec.state === "connected") {
      await page.clock.runFor(1000);
      await page.waitForFunction(() => window.nativeRequests?.filter((call) => call.action === "poll").length >= 2);
    }
    if (spec.tab !== "Connect") {
      await page.getByRole("navigation").getByRole("button", { name: spec.tab, exact: true }).click();
    }
    if (spec.setup) {
      await page.getByRole("button", { name: "Add a network", exact: true }).last().click();
      if (spec.setup === "import") await page.getByRole("radio", { name: "Import TOML" }).check();
    }
    if (spec.detail) await page.locator(".device-peer-main").first().click();
    if (spec.logs) await page.getByRole("button", { name: "Read recent logs" }).click();
    const html = await page.evaluate(({ title, fixture }) => {
      const clone = document.documentElement.cloneNode(true);
      clone.dataset.theme = document.documentElement.dataset.theme || (matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light");
      clone.querySelector("title").textContent = `LowTier iOS · ${title}`;
      clone.querySelectorAll("script, link[rel=modulepreload]").forEach((element) => element.remove());
      clone.querySelectorAll('link[rel="stylesheet"]').forEach((element) => element.remove());
      const stylesheet = document.createElement("link");
      stylesheet.rel = "stylesheet";
      stylesheet.href = "app.css";
      clone.querySelector("head").append(stylesheet);
      const policy = document.createElement("meta");
      policy.httpEquiv = "Content-Security-Policy";
      policy.content = "default-src 'none'; style-src 'self' 'unsafe-inline'; img-src data:; form-action 'none'; base-uri 'none'";
      clone.querySelector("head").prepend(policy);
      const note = document.createElement("aside");
      note.className = "render-note";
      const index = document.createElement("a");
      index.href = "index.html";
      index.textContent = "All page renders";
      note.append(index, document.createTextNode(
        fixture ? "Fixture data · Static HTML · No VPN session." : "Browser preview · Static HTML · No VPN session.",
      ));
      clone.querySelector("body").prepend(note);
      const liveInputs = document.querySelectorAll("input");
      clone.querySelectorAll("input").forEach((input, index) => {
        input.toggleAttribute("checked", liveInputs[index].checked);
        input.setAttribute("value", input.type === "password" ? "" : liveInputs[index].value);
      });
      clone.querySelectorAll("form").forEach((form) => { form.inert = true; });
      clone.querySelectorAll("button").forEach((button) => {
        button.type = "button";
        button.setAttribute("aria-disabled", "true");
      });
      clone.querySelectorAll(".device-tabs button").forEach((button) => {
        const anchor = document.createElement("a");
        anchor.href = `${button.textContent.trim().toLowerCase()}.html`;
        if (button.hasAttribute("aria-current")) anchor.setAttribute("aria-current", "page");
        anchor.append(...button.childNodes);
        button.replaceWith(anchor);
      });
      clone.querySelector(".device-brand").href = "connect.html";
      for (const parent of [clone.querySelector("head"), clone.querySelector("body")]) {
        for (const node of [...parent.childNodes]) {
          if (node.nodeType === Node.TEXT_NODE && !node.textContent.trim()) node.remove();
        }
      }
      return "<!doctype html>\n" + clone.outerHTML + "\n";
    }, { title: spec.title, fixture: Boolean(spec.state) });
    await writeFile(join(output, `${spec.file}.html`), html);
    await page.goto(`${origin}/review/${spec.file}.html`);
    const widths = [];
    for (const width of [320, 390, 820]) {
      await page.setViewportSize({ width, height: 844 });
      if (!await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)) {
        throw new Error(`${spec.file} exceeds the ${width}px viewport.`);
      }
      widths.push(width);
    }
    await page.setViewportSize({ width: 390, height: 844 });
    await page.screenshot({ path: join(evidence, `${spec.file}.png`), fullPage: true });
    await page.evaluate(() => { document.documentElement.style.fontSize = "200%"; });
    await page.setViewportSize({ width: 320, height: 844 });
    if (!await page.evaluate(() => document.documentElement.scrollWidth <= innerWidth)) {
      throw new Error(`${spec.file} exceeds the enlarged-text viewport.`);
    }
    if (errors.length) throw new Error(errors.join("\n"));
    results.push({ page: spec.file, title: spec.title, fixture: Boolean(spec.state), widths, enlargedText: true, errors });
    await context.close();
  }
  const links = pages.map((page) => `<li><a href="${page.file}.html">${page.title}</a></li>`).join("\n");
  await writeFile(join(output, "index.html"), `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'self'; form-action 'none'; base-uri 'none'">
<title>LowTier iOS app review</title><link rel="stylesheet" href="app.css"></head>
<body class="device-mode-active"><main class="render-gallery">
<h1>LowTier iOS app review</h1>
<p>These HTML pages come from the production frontend. Connected states use explicit browser fixtures.
These renders do not establish a working VPN session. The page links work without JavaScript.</p>
<ul class="render-pages">${links}</ul>
<h2>Control path</h2>
<div class="render-path" aria-label="Control path"><span>Solid UI</span> → <span>Tauri IPC and async Rust adapter</span> →
<span>Swift main queue</span> → <span>OS provider message</span> → <span>Extension control queue</span> →
<span>C FFI control API</span> → <span>Rust core</span></div>
<p>One visible poll returns system state and a network snapshot. The Rust command awaits the mobile plugin.
The Swift manager and provider retain their ownership queues.
Provider admission remains closed after a timeout until the callback returns or the VPN disconnects.
Connection generations reject old snapshots and logs.</p>
<h2>Removed work</h2>
<table><thead><tr><th scope="col">Operation</th><th scope="col">Before</th><th scope="col">After</th></tr></thead><tbody>
<tr><th scope="row">Connected UI polling</th><td>Two loops</td><td>One loop</td></tr>
<tr><th scope="row">Blocking Rust worker</th><td>One per command</td><td>None</td></tr>
<tr><th scope="row">Preference callback dispatches</th><td>Two redundant dispatches per connect</td><td>None</td></tr>
<tr><th scope="row">Nested payload JSON</th><td>Extra string encoding and parsing</td><td>Object payload</td></tr>
<tr><th scope="row">Core calls per snapshot</th><td>Four</td><td>Three</td></tr>
<tr><th scope="row">Steady status Keychain reads</th><td>One per status sample</td><td>None after initial metadata load</td></tr>
<tr><th scope="row">App chart history</th><td>Up to 120 samples per series</td><td>No chart history</td></tr>
<tr><th scope="row">Direct route label</th><td>Two hops</td><td>One hop</td></tr>
</tbody></table>
<h2>Packet path</h2>
<div class="render-path" aria-label="Packet path"><span>iOS packet flow</span> → <span>Swift batch adapter</span> →
<span>C FFI</span> → <span>Bounded core ring</span> → <span>NIC forwarding</span> → <span>Authenticated transport</span></div>
<div class="render-path" aria-label="Packet output path"><span>Authenticated transport</span> → <span>NIC writer</span> →
<span>Bounded core ring</span> → <span>Borrowed C callback</span> → <span>Swift Data copy</span> → <span>iOS packet flow</span></div>
<p>Packets do not enter JavaScript. The adapter keeps 64-packet batches and 128-packet rings.
The shutdown barrier protects borrowed callback data. Device throughput, memory use, and signed operation remain unmeasured.</p>
</main></body></html>\n`);
  const index = await browser.newPage({ viewport: { width: 390, height: 844 }, colorScheme: "light" });
  await index.goto(`${origin}/review/index.html`);
  for (const width of [320, 390, 820]) {
    await index.setViewportSize({ width, height: 844 });
    if (!await index.evaluate(() => document.documentElement.scrollWidth <= innerWidth)) {
      throw new Error(`The index exceeds the ${width}px viewport.`);
    }
  }
  await index.setViewportSize({ width: 820, height: 1000 });
  await index.screenshot({ path: join(evidence, "index.png"), fullPage: true });
  await index.close();
  await writeFile(join(evidence, "validation.json"), JSON.stringify({
    generatedAt: new Date().toISOString(), source: "Production dist with explicit native IPC fixtures", pages: results,
  }, null, 2) + "\n");
  console.log(JSON.stringify({ output, pages: results.length, validation: join(evidence, "validation.json") }));
} finally {
  await browser.close();
  server.closeAllConnections();
  await new Promise((done) => server.close(done));
}
