// Owner mandates: the OWNER signs what an agent may agree to and spend. Run this on the owner's
// machine, not the agent's: whoever holds the owner key can grant any limits.
//   npm run mandate -- keygen [owner-key.json]
//   npm run mandate -- sign --agent agt_… --per-deal 5 --total 50 [--days 30] [--seller agt_…]… [--category research]… [--network eip155:8453] [--key owner-key.json] [--out mandate.json]
//   npm run mandate -- verify mandate.json [--agent agt_…]
// Give the agent the mandate file (ROOMS_MANDATE, default ~/.suppressor/mandate.json). Never the key.
// Note: a mandate proves an owner key allowed these limits. It doesn't prove who the owner is.
import fs from "node:fs";
import { generateOwnerKey } from "../clients/agent-identity.js";
import { createMandate, checkMandate } from "../clients/suppressor-sdk.js";

const [cmd, ...rest] = process.argv.slice(2);
const opts = { seller: [], category: [], _: [] };
for (let i = 0; i < rest.length; i++) {
  const a = rest[i];
  if (!a.startsWith("--")) { opts._.push(a); continue; }
  const k = a.slice(2), v = rest[++i];
  if (Array.isArray(opts[k])) opts[k].push(v); else opts[k] = v;
}
const fail = (m) => { console.error(m); process.exit(1); };

if (cmd === "keygen") {
  const file = opts._[0] || "owner-key.json";
  if (fs.existsSync(file)) fail(`${file} already exists; not overwriting an owner key.`);
  const k = await generateOwnerKey();
  fs.writeFileSync(file, JSON.stringify(k, null, 2), { mode: 0o600 });
  console.log(`Owner key saved to ${file} (keep it off the agent's machine).\nowner_id: ${k.owner_id}`);
} else if (cmd === "sign") {
  const owner = JSON.parse(fs.readFileSync(opts.key || "owner-key.json", "utf8"));
  if (!opts.agent || !opts["per-deal"] || !opts.total) fail("sign needs --agent, --per-deal and --total");
  const m = await createMandate(owner, { agent_id: opts.agent, max_per_deal_usd: Number(opts["per-deal"]), max_total_usd: Number(opts.total),
    allowed_sellers: opts.seller, allowed_categories: opts.category, network: opts.network || "eip155:8453", days: Number(opts.days || 30) });
  const out = opts.out || "mandate.json";
  fs.writeFileSync(out, JSON.stringify(m, null, 2));
  console.log(`Mandate ${m.mandate_id} for ${m.agent_id}: up to $${m.max_per_deal_usd} per deal, $${m.max_total_usd} total, until ${m.expires_at}. Saved to ${out}.`);
} else if (cmd === "verify") {
  const m = JSON.parse(fs.readFileSync(opts._[0] || "mandate.json", "utf8"));
  const problem = await checkMandate(m, { agent_id: opts.agent });
  if (problem) fail("Invalid: " + problem);
  console.log(`Valid. Signed by owner ${m.owner_id} for ${m.agent_id}: up to $${m.max_per_deal_usd} per deal, $${m.max_total_usd} total, until ${m.expires_at}.`);
} else {
  fail("usage: npm run mandate -- keygen | sign … | verify <file>  (see scripts/mandate.js)");
}
