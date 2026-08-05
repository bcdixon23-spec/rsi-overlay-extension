import { build } from "esbuild";
import { cpSync, mkdirSync, rmSync } from "node:fs";

const DIST = "dist";

rmSync(DIST, { recursive: true, force: true });
mkdirSync(DIST, { recursive: true });

const ENTRIES = [
  ["src/background/background.ts", `${DIST}/background.js`],
  ["src/content/content-script.ts", `${DIST}/content-script.js`],
  ["src/popup/popup.ts", `${DIST}/popup.js`],
];

for (const [entryPoint, outfile] of ENTRIES) {
  await build({
    entryPoints: [entryPoint],
    outfile,
    bundle: true,
    format: "iife",
    target: "chrome110",
    platform: "browser",
    sourcemap: true,
    logLevel: "info",
  });
}

cpSync("manifest.json", `${DIST}/manifest.json`);
cpSync("icons", `${DIST}/icons`, { recursive: true });
cpSync("src/content/content-style.css", `${DIST}/content-style.css`);
cpSync("src/popup/popup.html", `${DIST}/popup.html`);
cpSync("src/popup/popup.css", `${DIST}/popup.css`);

console.log("Build complete → dist/");
