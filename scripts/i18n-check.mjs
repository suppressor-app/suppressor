// Lists the English text that each language still needs (-v shows it), and writes i18n/en.json:
// every text unit on the site plus every t("…") string in the browser code.
// Run: node scripts/i18n-check.mjs   (--list prints the numbered list that i18n-import.mjs reads)
import fs from "node:fs";
import path from "node:path";
import { findUnits, LANGS, NOTICE, I18N_DIR, catalog } from "../src/i18n.js";

const ROOT = path.join(I18N_DIR, "..");
// Owner-only pages stay in English.
const PAGES = ["site/index.html", "site/privacy.html", "site/terms.html", "site/roadmap.html", "site/rooms/index.html", "site/agents/index.html", "site/mcp/index.html"];
const SCRIPTS = ["web/rooms-app.js", "site/agents/agents.js", "public/brand/i18n.js"];

export function sourceStrings() {
  const html = new Set([NOTICE]);
  for (const p of PAGES) for (const u of findUnits(fs.readFileSync(path.join(ROOT, p), "utf8"))) html.add(u.key);
  const js = new Set();
  for (const p of SCRIPTS) for (const m of fs.readFileSync(path.join(ROOT, p), "utf8").matchAll(/\bt\(\s*("(?:[^"\\]|\\.)*")/g)) js.add(JSON.parse(m[1]));
  return { html: [...html], js: [...js] };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const src = sourceStrings();
  if (process.argv.includes("--list")) { [...src.html, ...src.js].forEach((k, i) => console.log(`${i}|${k.replace(/\n/g, "\\n")}`)); process.exit(0); }
  fs.writeFileSync(path.join(I18N_DIR, "en.json"), JSON.stringify({ html: Object.fromEntries(src.html.map((k) => [k, k])), js: Object.fromEntries(src.js.map((k) => [k, k])) }, null, 1) + "\n");
  for (const l of LANGS.slice(1)) {
    const c = catalog(l.code);
    const missing = [...src.html.filter((k) => !c.html?.[k]), ...src.js.filter((k) => !c.js?.[k])];
    console.log(`${l.code}: ${missing.length ? missing.length + " missing" : "complete"}`);
    if (process.argv.includes("-v")) for (const k of missing) console.log("   ", k);
  }
}
