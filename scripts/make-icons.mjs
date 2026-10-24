// Renders the app icons (home screen, install prompt, iPhone) from the SVGs in public/brand.
// Run after changing the logo: node scripts/make-icons.mjs  (needs Playwright + Chromium, dev only)
import { createRequire } from "node:module";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const { chromium } = createRequire(import.meta.url)("playwright");
const BRAND = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "public", "brand");
const svg = (f) => fs.readFileSync(path.join(BRAND, f), "utf8");
const out = [
  ["icon-192.png", 192, svg("icon.svg")],
  ["icon-512.png", 512, svg("icon.svg")],
  // Android crops "maskable" icons to a circle or squircle: full-bleed background, logo in the safe middle.
  ["icon-maskable-512.png", 512, svg("icon-maskable.svg")],
  // iPhone rounds the corners itself and shows transparency as black, so use the full-bleed version.
  ["apple-touch-icon.png", 180, svg("icon-maskable.svg")],
];

const browser = await chromium.launch();
const page = await browser.newPage();
for (const [name, size, s] of out) {
  await page.setViewportSize({ width: size, height: size });
  await page.setContent(`<html><body style="margin:0;background:transparent">${s.replace("<svg ", `<svg width="${size}" height="${size}" `)}</body></html>`);
  await page.locator("svg").screenshot({ path: path.join(BRAND, name), omitBackground: true });
  console.log("wrote", name);
}
await browser.close();
