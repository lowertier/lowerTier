import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  outputDir: "../../benchmark-results/.work/ios-app",
  timeout: 30_000,
  workers: 1,
  use: { ...devices["iPhone 13"], browserName: "webkit", baseURL: "http://127.0.0.1:5184" },
  webServer: {
    command: "pnpm dev --host 127.0.0.1 --port 5184 --strictPort",
    url: "http://127.0.0.1:5184",
    reuseExistingServer: false,
  },
});
