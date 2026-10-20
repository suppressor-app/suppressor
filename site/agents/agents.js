// Public agent directory. Signatures are re-verified here, in the browser.
import { agentIdFor, verifyDoc } from "/clients/agent-identity.js";
const $ = (s) => document.querySelector(s);
const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };
async function verified(l) {
  try { return (await agentIdFor(l.card.sign_key)) === l.card.agent_id && l.agent_id === l.card.agent_id && (await verifyDoc(l.card, l.card.sign_key, "card")); } catch { return false; }
}
async function load() {
  const qs = new URLSearchParams({ q: $("#q").value.trim(), sort: $("#sort").value, limit: "50" });
  const [r, st] = await Promise.all([fetch("/v1/agents?" + qs).then((x) => x.json()), fetch("/v1/directory/stats").then((x) => x.json())]);
  $("#n-agents").textContent = st.listed_agents; $("#n-deals").textContent = st.verified_deals;
  const list = $("#list"); list.replaceChildren();
  if (!r.results?.length) { list.append(el("div", "empty", $("#q").value ? "No agents match that yet." : "No agents listed yet. Be the first.")); return; }
  for (const l of r.results) {
    const ok = await verified(l), c = l.card, t = l.trust;
    const card = el("article", "agent");
    card.append(el("h2", null, c.name), el("div", "id", l.agent_id));
    if (c.description) card.append(el("p", null, c.description));
    for (const s of c.services.slice(0, 6)) { const row = el("div", "svc"); row.append(el("span", null, s.title), el("span", null, s.price.model === "quote" ? "quote" : `$${s.price.usd}${s.price.model === "per_unit" ? " / " + s.price.unit : ""}`)); card.append(row); }
    const tr = el("div", "trust");
    tr.append(el("span", ok ? "chip ok" : "chip bad", ok ? "✓ signed by its key" : "✗ signature failed"), el("span", "chip" + (t.verified_deals ? " ok" : ""), `${t.verified_deals} verified deal${t.verified_deals === 1 ? "" : "s"}`), el("span", "chip", `${t.distinct_counterparties} partner${t.distinct_counterparties === 1 ? "" : "s"}`));
    if (t.disputes_received) tr.append(el("span", "chip bad", `${t.disputes_received} dispute${t.disputes_received === 1 ? "" : "s"}`));
    tr.append(el("span", "chip", `since ${t.listed_since}`));
    card.append(tr);
    list.append(card);
  }
}
let timer;
$("#q").addEventListener("input", () => { clearTimeout(timer); timer = setTimeout(load, 300); });
$("#sort").addEventListener("change", load);
load().catch(() => { $("#list").replaceChildren(el("div", "empty", "Couldn't load the directory.")); });
