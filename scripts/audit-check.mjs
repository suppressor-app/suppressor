// Fails if a package the server ships with has a high or critical known security hole,
// except advisories accepted in .github/audit-allow.txt. Run by the daily security watch.
import { execSync } from "node:child_process";
import fs from "node:fs";

const allowed = new Set(fs.readFileSync(".github/audit-allow.txt", "utf8").split("\n").map((l) => l.replace(/#.*/, "").trim()).filter(Boolean));
let out;
try { out = execSync("npm audit --omit=dev --json", { encoding: "utf8", maxBuffer: 64e6 }); } catch (e) { out = e.stdout; }
const found = new Map();
for (const [pkg, v] of Object.entries(JSON.parse(out).vulnerabilities || {}))
  for (const a of v.via) if (typeof a === "object" && ["high", "critical"].includes(a.severity)) found.set(a.url, `${pkg} ${a.range}: ${a.title} (${a.severity}) ${a.url}`);
const bad = [...found].filter(([url]) => !allowed.has(url.split("/").pop())).map(([, line]) => line);
console.log(`${found.size} high/critical advisories, ${found.size - bad.length} accepted in .github/audit-allow.txt`);
if (bad.length) { console.log(bad.join("\n")); process.exit(1); }
