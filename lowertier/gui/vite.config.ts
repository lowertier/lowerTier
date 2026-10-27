import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// Fixed file names: the lowertier binary embeds index.html, app.js and app.css.
export default defineConfig({
  plugins: [solid()],
  build: {
    target: "es2022",
    outDir: "dist",
    emptyOutDir: true,
    modulePreload: { polyfill: false },
    cssCodeSplit: false,
    assetsInlineLimit: 0,
    rollupOptions: {
      output: {
        entryFileNames: "app.js",
        assetFileNames: "app[extname]",
        codeSplitting: false,
      },
    },
  },
  // Development: open http://localhost:5173/#key=... with the key printed by `lowertier gui`.
  // The proxy presents the request as same-origin, as the embedded page would be.
  server: {
    proxy: {
      "/api": {
        target: process.env.LOWTIER_GUI ?? "http://127.0.0.1:15880",
        changeOrigin: true,
        configure: (proxy) => proxy.on("proxyReq", (request) => request.removeHeader("origin")),
      },
    },
  },
});
