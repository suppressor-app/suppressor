// Translations for the website and rooms app. English in the site/*.html files is the source;
// i18n/<lang>.json maps each English text unit to its translation. Pages are translated on the
// server, before %BRAND% tokens are filled in, so there's no flash of English and no cookie.
// Run `node scripts/i18n-check.mjs` to list text that still needs translating.
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
export const I18N_DIR = path.join(ROOT, "i18n");

// Order is the order in the language menu. English is the legal source and the fallback.
export const LANGS = [
  { code: "en", name: "English", dir: "ltr" },
  { code: "ko", name: "한국어", dir: "ltr" },
  { code: "uk", name: "Українська", dir: "ltr" },
  { code: "ar", name: "العربية", dir: "rtl" },
  { code: "vi", name: "Tiếng Việt", dir: "ltr" },
  { code: "fil", name: "Filipino", dir: "ltr" },
  { code: "ja", name: "日本語", dir: "ltr" },
  { code: "zh-Hant", name: "繁體中文", dir: "ltr" },
];
const BY_CODE = new Map(LANGS.map((l) => [l.code.toLowerCase(), l.code]));

// Shown at the top of every translated page. Translations must keep the link.
export const NOTICE = 'This page is translated for convenience. If it differs from the English version, the English version controls, including the terms, privacy policy, prices and fees. <a href="?lang=en">Read in English</a>';

// Maps a language tag ("ko-KR", "zh-TW", "tl") to a supported code, or null.
export function matchLang(tag) {
  const t = String(tag || "").trim().toLowerCase();
  if (!t) return null;
  if (BY_CODE.has(t)) return BY_CODE.get(t);
  const [base, ...rest] = t.split("-");
  if (base === "zh") return rest.some((r) => ["hant", "tw", "hk", "mo"].includes(r)) ? "zh-Hant" : null; // no Simplified Chinese yet
  if (base === "tl") return "fil";
  return BY_CODE.get(base) || null;
}

// ?lang= wins (the switcher sets it), then the browser's Accept-Language, then English.
export function pickLang(query, acceptLanguage) {
  const q = matchLang(typeof query === "string" ? query : "");
  if (q) return q;
  const prefs = String(acceptLanguage || "").split(",").map((part, i) => {
    const [tag, ...params] = part.trim().split(";");
    const qv = params.map((p) => p.trim()).find((p) => p.startsWith("q="));
    return { tag, q: qv ? Number(qv.slice(2)) || 0 : 1, i };
  }).filter((p) => p.tag && p.q > 0).sort((a, b) => b.q - a.q || a.i - b.i);
  for (const p of prefs) {
    if (p.tag.trim().toLowerCase().startsWith("en")) return "en";
    const m = matchLang(p.tag);
    if (m) return m;
  }
  return "en";
}

export const langInfo = (code) => LANGS.find((l) => l.code === code) || LANGS[0];

// ---- finding the text in a page ---------------------------------------------------------
// A "unit" is a run of text and inline tags (links, bold, code…) inside one block, translated
// as a whole so word order can change. Attributes people read (placeholder, title…) are units too.
const VOID = new Set(["area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"]);
const RAW = new Set(["script", "style", "textarea"]);
const INLINE = new Set(["a", "abbr", "b", "br", "code", "em", "i", "kbd", "mark", "s", "small", "span", "strong", "sub", "sup", "time", "u"]);
const SKIP = new Set(["script", "style", "pre", "svg", "noscript", "template"]);
const ATTRS = new Set(["title", "placeholder", "aria-label", "alt"]);
const META = new Set(["description", "og:title", "og:description"]);
const hasWords = (s) => /\p{L}/u.test(s.replace(/<code>[\s\S]*?<\/code>/g, "").replace(/%[A-Z_]+%/g, "").replace(/<[^>]*>/g, ""));
export const normalize = (s) => s.trim().replace(/\s+/g, " ");

function parse(html) {
  const root = { tag: "#root", children: [], attrs: [] };
  const stack = [root];
  const re = /<!--[\s\S]*?-->|<!(?:[^>]*)>|<\/([a-zA-Z][\w-]*)\s*>|<([a-zA-Z][\w-]*)((?:\s+[^\s=>/]+(?:\s*=\s*(?:"[^"]*"|'[^']*'|[^\s>]+))?)*)\s*(\/?)>/g;
  let pos = 0, m;
  const text = (start, end) => { if (end > start) stack.at(-1).children.push({ text: true, start, end }); };
  while ((m = re.exec(html))) {
    text(pos, m.index);
    pos = re.lastIndex;
    if (m[1]) { // closing tag: pop to the matching element
      const tag = m[1].toLowerCase();
      const at = stack.findLastIndex((n) => n.tag === tag);
      if (at > 0) { for (let i = stack.length - 1; i >= at; i--) stack[i].closeStart ??= m.index; stack.length = at; }
      continue;
    }
    if (!m[2]) continue; // comment or doctype
    const tag = m[2].toLowerCase();
    const attrs = [];
    const attrStart = m.index + 1 + m[2].length;
    const are = /([^\s=>/]+)(?:\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>]+)))?/g;
    let a;
    while ((a = are.exec(m[3] || ""))) {
      const value = a[2] ?? a[3] ?? a[4] ?? "";
      const quoted = a[2] != null || a[3] != null;
      const vEnd = attrStart + a.index + a[0].length - (quoted ? 1 : 0);
      attrs.push({ name: a[1].toLowerCase(), value, start: vEnd - value.length, end: vEnd });
    }
    const node = { tag, attrs, start: m.index, openEnd: pos, children: [] };
    stack.at(-1).children.push(node);
    if (VOID.has(tag) || m[4]) continue;
    if (RAW.has(tag)) {
      const close = html.toLowerCase().indexOf(`</${tag}`, pos);
      node.closeStart = close < 0 ? html.length : close;
      re.lastIndex = pos = close < 0 ? html.length : html.indexOf(">", close) + 1;
      continue;
    }
    stack.push(node);
  }
  text(pos, html.length);
  return root;
}

const attr = (n, name) => n.attrs?.find((a) => a.name === name)?.value;
const skipped = (n) => SKIP.has(n.tag) || attr(n, "translate") === "no" || /\bnotranslate\b/.test(attr(n, "class") || "");
const isInline = (n) => n.text || (INLINE.has(n.tag) && !skipped(n) && n.children.every(isInline));

// Returns [{ start, end, key }] for every translatable span of the page, in document order.
export function findUnits(html) {
  const out = [];
  const add = (start, end) => {
    const raw = html.slice(start, end);
    if (!hasWords(raw)) return;
    const lead = raw.length - raw.trimStart().length, trail = raw.length - raw.trimEnd().length;
    out.push({ start: start + lead, end: end - trail, key: normalize(raw) });
  };
  const attrsOf = (n) => {
    for (const a of n.attrs || []) {
      if ((ATTRS.has(a.name) || (a.name === "content" && n.tag === "meta" && META.has(attr(n, "name") || attr(n, "property")))) && hasWords(a.value)) out.push({ start: a.start, end: a.end, key: normalize(a.value), attr: true });
    }
  };
  const walk = (n) => {
    attrsOf(n);
    if (skipped(n) || RAW.has(n.tag) || n.tag === "code") return; // code inside a sentence is kept as is
    let run = [];
    const flush = () => {
      if (!run.length) return;
      const direct = run.some((c) => c.text && /\S/.test(html.slice(c.start, c.end)));
      if (direct) add(run[0].start, run.at(-1).end);
      else run.forEach((c) => !c.text && walk(c));
      run = [];
    };
    for (const c of n.children) {
      if (isInline(c)) { if (!c.text) c.end = c.closeStart != null ? html.indexOf(">", c.closeStart) + 1 : c.openEnd; run.push(c); }
      else { flush(); walk(c); }
    }
    flush();
  };
  walk(parse(html));
  return out.sort((a, b) => a.start - b.start);
}

// ---- catalogs ---------------------------------------------------------------------------
const catalogs = new Map();
export function catalog(lang) {
  if (lang === "en") return { html: {}, js: {} };
  if (!catalogs.has(lang) || process.env.DEV_SKIP_PAYMENTS === "1") {
    let c = { html: {}, js: {} };
    try { c = JSON.parse(fs.readFileSync(path.join(I18N_DIR, `${lang}.json`), "utf8")); } catch {}
    catalogs.set(lang, c);
  }
  return catalogs.get(lang);
}

// Translates a page's English text units. Anything missing stays in English.
export function translateHtml(html, lang) {
  const dict = catalog(lang).html || {};
  let out = "", pos = 0;
  for (const u of findUnits(html)) {
    const tr = dict[u.key];
    if (!tr) continue;
    out += html.slice(pos, u.start) + (u.attr ? tr.replace(/"/g, "&quot;") : tr);
    pos = u.end;
  }
  return out + html.slice(pos);
}

// Everything a page needs to be shown in `lang`: translated text, lang/dir on <html>, the
// "English controls" notice, alternate-language links, the switcher and the app's strings.
export function localizePage(html, lang, { url = "", publicUrl = "" } = {}) {
  const info = langInfo(lang);
  const c = catalog(lang);
  let out = lang === "en" ? html : translateHtml(html, lang);
  out = out.replace(/<html\b[^>]*>/i, `<html lang="${info.code}" dir="${info.dir}">`);
  const pagePath = url.split("?")[0];
  const alts = LANGS.map((l) => `<link rel="alternate" hreflang="${l.code}" href="${publicUrl}${pagePath}?lang=${l.code}">`).join("");
  const strings = lang === "en" ? "" : `<script type="application/json" id="i18n-strings">${JSON.stringify(c.js || {}).replace(/</g, "\\u003c")}</script>`;
  out = out.replace(/<\/head>/i, `${alts}${strings}<script src="/brand/i18n.js" defer></script>\n</head>`);
  if (lang !== "en") out = out.replace(/<body\b[^>]*>/i, (b) => `${b}\n<div class="i18n-note" role="note">${(c.html || {})[NOTICE] || NOTICE}</div>`);
  return out;
}
