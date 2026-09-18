import { defineConfig } from "vite";

// Built as a GitHub Pages project site: https://<user>.github.io/agent-trust-layer/
export default defineConfig({
  root: "web",
  base: "/agent-trust-layer/",
  build: {
    // Built output is pushed to a dedicated `gh-pages` branch (see package.json's
    // web:deploy script), never committed on main — keeps this out of the way
    // of docs/ (the project's markdown documentation).
    outDir: "../web-dist",
    emptyOutDir: true,
  },
});
