// Turns a numbered translation list ("N|text" per line, numbered as in `i18n-check.mjs --list`)
// into i18n/<lang>.json, after checking that every tag and {placeholder} survived.
// Run: node scripts/i18n-import.mjs <lang> <file>
import fs from "node:fs";
import path from "node:path";
import { I18N_DIR, langInfo } from "../src/i18n.js";
import { sourceStrings } from "./i18n-check.mjs";

export const tokens = (s) => [...s.matchAll(/<[^>]+>|\{\w+\}|%[A-Z_]+%/g)].map((m) => m[0]).sort();

const [lang, file] = process.argv.slice(2);
const src = sourceStrings();
const keys = [...src.html.map((k) => ["html", k]), ...src.js.map((k) => ["js", k])];
const lines = fs.readFileSync(file, "utf8").split("\n").filter((l) => /^\d+\|/.test(l));
const out = { _meta: { language: langInfo(lang).name, status: "machine translation: needs review by a native speaker before marketing use" }, html: {}, js: {} };
const errors = [];
for (const line of lines) {
  const i = Number(line.slice(0, line.indexOf("|")));
  const text = line.slice(line.indexOf("|") + 1).replace(/\\n/g, "\n");
  if (!keys[i]) { errors.push(`${i}: no such line`); continue; }
  const [sec, en] = keys[i];
  if (out[sec][en] !== undefined) errors.push(`${i}: duplicate`);
  if (tokens(en).join() !== tokens(text).join()) errors.push(`${i}: tags or placeholders differ\n   en: ${en}\n   ${lang}: ${text}`);
  out[sec][en] = text;
}
keys.forEach(([sec, en], i) => { if (out[sec][en] === undefined) errors.push(`${i}: missing (${en.slice(0, 50)})`); });
if (errors.length) { console.error(errors.join("\n")); process.exit(1); }
fs.writeFileSync(path.join(I18N_DIR, `${lang}.json`), JSON.stringify(out, null, 1) + "\n");
console.log(`${lang}: ${lines.length} strings written`);
