// Watches the live site for signs of tampering. Run by .github/workflows/security-watch.yml every 30 minutes.
//   SITE_URL=https://example.app node scripts/security-watch.mjs [deployed-checkout-dir]
// Checks: the site is up; payments haven't been switched off; the security headers (CSP etc.) are intact;
// the JavaScript the site sends browsers is byte-for-byte the code in the repo; the HTTPS certificate isn't expiring.
// Exits 1 with a plain-English list of problems (after a "PROBLEMS:" line) if anything is wrong.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import tls from "node:tls";

const SITE = (process.env.SITE_URL || "").replace(/\/+$/, "");
const DIR = path.resolve(process.argv[2] || ".");
if (!SITE) { console.log("SITE_URL is not set; nothing to check."); process.exit(0); }

const problems = [];
const notes = [];
const sha = (buf) => crypto.createHash("sha256").update(buf).digest("hex");
const get = async (p, tries = 3) => {
  for (let i = 1; ; i++) {
    try { return await fetch(SITE + p, { redirect: "follow", signal: AbortSignal.timeout(20000), headers: { "user-agent": "suppressor-security-watch" } }); }
    catch (e) { if (i >= tries) throw e; await new Promise((r) => setTimeout(r, 5000 * i)); }
  }
};

// 1. Up, and still charging. Payments silently switched off would mean someone changed the server's settings.
try {
  const r = await get("/health");
  const h = r.ok ? await r.json() : null;
  if (!h?.ok) problems.push(`The site's health check failed (HTTP ${r.status}). The site may be down.`);
  else if (h.payments === false) problems.push("The live site reports payments are OFF. Someone may have changed the server settings (DEV_SKIP_PAYMENTS).");
  else notes.push("health ok");
} catch (e) {
  problems.push(`Could not reach ${SITE} at all (${e.cause?.code || e.message}). The site may be down.`);
}

// 2. Security headers. A loosened Content-Security-Policy is how injected third-party scripts would get in.
try {
  const r = await get("/");
  const src = fs.readFileSync(path.join(DIR, "src/server.js"), "utf8");
  const want = src.match(/"Content-Security-Policy": "([^"]+)"/)?.[1];
  const csp = (r.headers.get("content-security-policy") || "").replace(/[^\x20-\x7e]/g, "?").slice(0, 2000).replace(/; upgrade-insecure-requests$/, "");
  if (want && csp !== want) problems.push(`The Content-Security-Policy header doesn't match the code.\n  expected: ${want}\n  live:     ${csp || "(missing)"}`);
  for (const [k, v] of [["x-frame-options", "DENY"], ["x-content-type-options", "nosniff"], ["referrer-policy", "no-referrer"]])
    if (r.headers.get(k) !== v) problems.push(`Security header ${k} is "${r.headers.get(k) ?? "missing"}", expected "${v}".`);
  if (SITE.startsWith("https://") && !r.headers.get("strict-transport-security")) notes.push("HSTS header missing (set PUBLIC_URL to the https address on the server)");
  notes.push("headers checked");
} catch (e) {
  if (!problems.length) problems.push(`Could not load the home page (${e.message}).`);
}

// 3. Code integrity: every script the site serves to browsers must match the repo exactly.
// RECENT_DEPLOY=1 (set by the workflow for 20 minutes after a push) tolerates a deploy still rolling out.
// The page's encryption runs in these files, so a changed file could leak keys. HTML is skipped
// because the server fills in the brand name.
const files = [
  ["/rooms/app.js", "site/rooms/app.js"],
  ["/agents/agents.js", "site/agents/agents.js"],
  ["/admin/admin.js", "site/admin/admin.js"],
  ["/sw.js", "site/sw.js"],
  ["/mcp/suppressor-mcp.mjs", "site/mcp/suppressor-mcp.mjs"],
  ...fs.readdirSync(path.join(DIR, "clients")).filter((f) => f.endsWith(".js")).map((f) => [`/clients/${f}`, `clients/${f}`]),
];
let matched = 0;
for (const [url, local] of files) {
  const file = path.join(DIR, local);
  if (!fs.existsSync(file)) continue;
  try {
    const r = await get(url);
    if (r.status === 404) { notes.push(`${url} not served`); continue; }
    if (!r.ok) { problems.push(`${url} returned HTTP ${r.status}.`); continue; }
    const live = Buffer.from(await r.arrayBuffer());
    if (sha(live) === sha(fs.readFileSync(file))) matched++;
    else if (process.env.RECENT_DEPLOY === "1") notes.push(`${url} differs, but a deploy is probably still rolling out`);
    else problems.push(`TAMPER CHECK: ${url} on the live site is different from ${local} in the repo (live ${live.length} bytes, repo ${fs.statSync(file).size} bytes). Either a deploy is out of date or the served code was changed.`);
  } catch (e) { problems.push(`Could not fetch ${url} (${e.message}).`); }
}
notes.push(`${matched} script file(s) match the repo`);

// 4. HTTPS certificate. An expired certificate takes the site down and trains people to click through warnings.
if (SITE.startsWith("https://")) {
  const host = new URL(SITE).hostname;
  try {
    const cert = await new Promise((ok, fail) => {
      const s = tls.connect({ host, port: 443, servername: host, timeout: 15000 }, () => { ok(s.getPeerCertificate()); s.end(); });
      s.on("error", fail).on("timeout", () => { s.destroy(); fail(new Error("timeout")); });
    });
    const days = Math.floor((new Date(cert.valid_to) - Date.now()) / 864e5);
    if (days < 10) problems.push(`The HTTPS certificate for ${host} expires in ${days} day(s).`);
    else notes.push(`certificate ok for ${days} days`);
  } catch (e) { notes.push(`certificate not checked (${e.message})`); }
}

console.log(`Checked ${SITE}: ${notes.join("; ")}`);
if (problems.length) {
  console.log(`\nPROBLEMS:\n${problems.map((p) => `- ${p}`).join("\n")}`);
  process.exit(1);
}
console.log("All clear.");
