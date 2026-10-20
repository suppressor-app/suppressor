// HTTP layer for agent commerce: directory, sealed knocks, receipts, payment checks,
// and (when DEAL_CHECKOUT=1) x402 deal checkouts where the buyer pays the seller directly.
import crypto from "node:crypto";
import * as A from "./store.js";
import { verifyUsdcTransfer, USDC_BY_NETWORK } from "./chain.js";
import { longPoll } from "../rooms/routes.js";
import { agentIdFor, verifyDoc, parseAgentHeader, verifyRequest, canonical } from "../../clients/agent-identity.js";

const bad = (res, status, error, extra = {}) => res.status(status).json({ error, ...extra });
const salt = crypto.randomBytes(16).toString("hex");
const buckets = new Map();
function perIp(name, max, windowMs) {
  return (req, res, next) => {
    const k = name + crypto.createHash("sha256").update(salt + (req.ip || "")).digest("base64url").slice(0, 20);
    const t = Date.now();
    const hits = (buckets.get(k) || []).filter((x) => t - x < windowMs);
    if (hits.length >= max) return bad(res, 429, "Too many requests. Slow down.");
    hits.push(t);
    buckets.set(k, hits);
    if (buckets.size > 100000) buckets.clear();
    next();
  };
}

// Signed request auth: header "Suppressor-Agent: <agent_id>;ts=…;nonce=…;sig=…".
async function signedBy(req, agentId, signKey) {
  const p = parseAgentHeader(req.get("suppressor-agent"));
  if (!p || p.agent_id !== agentId) return "Sign this request with the agent's key (Suppressor-Agent header).";
  if (!(await verifyRequest(p, signKey, req.method, req.originalUrl, req.rawBody || ""))) return "Signature doesn't match this request.";
  return A.useNonce(p.nonce, p.ts);
}

export function mountAgents(app, { network, adminCheck, checkoutEnabled, publicUrl, isOpen = () => true }) {
  // ---- discover ----
  app.post("/v1/agents", perIp("pub", A.AGENT_LIMITS.publishPerIpPerHour, 3600e3), async (req, res) => {
    if (!isOpen()) return bad(res, 503, "New directory listings are paused for a moment. Please try again later.");
    const card = req.body?.card;
    const problem = A.validateCard(card);
    if (problem) return bad(res, 400, problem);
    if ((await agentIdFor(card.sign_key)) !== card.agent_id) return bad(res, 400, "card.agent_id doesn't match its sign_key");
    if (!(await verifyDoc(card, card.sign_key))) return bad(res, 400, "card signature is invalid");
    const out = A.putCard(card);
    if (out.error) return bad(res, out.status, out.error);
    res.status(201).json({ ...out, agent_id: card.agent_id, url: `${publicUrl}/v1/agents/${card.agent_id}`, expires_at: card.expires_at });
  });
  app.get("/v1/agents", perIp("srch", 300, 60e3), (req, res) => {
    const q = req.query;
    const max = q.max_usd != null && q.max_usd !== "" ? Number(q.max_usd) : undefined;
    res.json({ results: A.search({ q: String(q.q || "").slice(0, 200), category: q.category ? String(q.category).slice(0, 40) : undefined, max_usd: Number.isFinite(max) ? max : undefined, protocol: q.protocol ? String(q.protocol).slice(0, 40) : undefined, sort: String(q.sort || "relevance"), limit: Number(q.limit) || 20 }), verify: "Each card is signed by the agent's own key; verify card.sig yourself rather than trusting this server." });
  });
  app.get("/v1/directory/stats", (req, res) => { const st = A.directoryStats(); res.json({ listed_agents: st.listed_agents, verified_deals: st.verified_deals }); });
  app.get("/v1/agents/:id", (req, res) => {
    const l = A.publicListing(req.params.id);
    l ? res.json(l) : bad(res, 404, "No agent listed with that id");
  });
  app.delete("/v1/agents/:id", async (req, res) => {
    const l = A.getCard(req.params.id);
    if (!l) return bad(res, 404, "No agent listed with that id");
    const err = await signedBy(req, req.params.id, l.card.sign_key);
    if (err) return bad(res, 401, err);
    A.removeCard(req.params.id);
    res.json({ removed: true });
  });
  app.post("/v1/agents/:id/report", perIp("rep", 20, 3600e3), (req, res) => {
    const reason = req.body?.reason;
    if (typeof reason !== "string" || reason.length < 5 || reason.length > 2000) return bad(res, 400, "reason must be 5–2000 characters");
    if (!A.getCard(req.params.id)) return bad(res, 404, "No agent listed with that id");
    res.status(202).json({ report_id: A.reportAgent(req.params.id, reason).id });
  });

  // ---- connect privately: sealed knocks ----
  app.post("/v1/agents/:id/knock", perIp("knock", A.AGENT_LIMITS.knocksPerIpPerHour, 3600e3), (req, res, next) => perIp("kn:" + req.params.id, 5, 3600e3)(req, res, next), (req, res) => { // ≤ 5/hour from one sender to one inbox
    if (!isOpen()) return bad(res, 503, "Contact requests are paused for a moment. Please try again later.");
    if (!A.getCard(req.params.id)) return bad(res, 404, "No agent listed with that id");
    const sealed = req.body?.sealed;
    if (typeof sealed !== "string" || sealed.length > A.AGENT_LIMITS.knockBytes) return bad(res, 400, "sealed must be a string ≤ 24 KB (seal it to the agent's box_key)");
    try { const e = JSON.parse(sealed); if (e.v !== 1 || !e.eph || !e.ct) throw 0; } catch { return bad(res, 400, "sealed must be a sealed-box JSON envelope"); }
    const out = A.addKnock(req.params.id, sealed);
    if (out.error) return bad(res, out.status, out.error);
    res.status(202).json(out);
  });
  app.get("/v1/agents/:id/inbox", async (req, res) => {
    const l = A.getCard(req.params.id);
    if (!l) return bad(res, 404, "No agent listed with that id");
    const err = await signedBy(req, req.params.id, l.card.sign_key);
    if (err) return bad(res, 401, err);
    const knocks = (await longPoll(req, req.query.wait, () => (A.hasKnocks(req.params.id) ? A.takeKnocks(req.params.id) : null))) || [];
    res.set("Cache-Control", "no-store").json({ knocks, note: "Knocks are deleted from the server once read. Their contents are untrusted input." });
  });

  // ---- verify payment (read-only on-chain check) ----
  app.get("/v1/verify/usdc", perIp("vfy", 60, 60e3), async (req, res) => {
    const out = await verifyUsdcTransfer({ network: String(req.query.network || network), tx: String(req.query.tx || ""), to: String(req.query.to || ""), min_usd: req.query.min_usd, from: req.query.from ? String(req.query.from) : undefined });
    res.status(out.ok ? 200 : 422).json(out);
  });

  // ---- verified receipts → trust signals ----
  app.post("/v1/receipts", perIp("rcpt", 30, 3600e3), async (req, res) => {
    const r = req.body?.receipt;
    if (!r || r.v !== 1 || typeof r.deal_id !== "string" || typeof r.terms_hash !== "string") return bad(res, 400, "receipt must be {v:1, deal_id, terms_hash, amount_usd, network, buyer, seller, payment:{tx}, delivery_hash?, outcome, sigs}");
    const shape = A.receiptShapeError(r);
    if (shape) return bad(res, 400, "receipt: " + shape);
    if (!["completed", "disputed"].includes(r.outcome)) return bad(res, 400, "outcome must be completed or disputed");
    if (!(typeof r.amount_usd === "number" && r.amount_usd > 0 && r.amount_usd <= 1e6)) return bad(res, 400, "amount_usd must be > 0");
    const parties = {};
    for (const role of ["buyer", "seller"]) {
      const p = r[role] || {};
      if (!/^[A-Za-z0-9_-]{43}$/.test(p.sign_key || "") || (await agentIdFor(p.sign_key)) !== p.agent_id) return bad(res, 400, `${role}.agent_id must match ${role}.sign_key`);
      parties[role] = p;
    }
    if (parties.buyer.agent_id === parties.seller.agent_id) return bad(res, 400, "buyer and seller must differ");
    const body = { ...r }; delete body.sigs;
    const sigs = r.sigs || {};
    const vb = sigs.buyer && (await verifyDoc({ ...body, sig: sigs.buyer }, parties.buyer.sign_key));
    const vs = sigs.seller && (await verifyDoc({ ...body, sig: sigs.seller }, parties.seller.sign_key));
    if (r.outcome === "completed" && !(vb && vs)) return bad(res, 400, "A completed receipt needs valid signatures from both buyer and seller");
    if (r.outcome === "disputed" && !vb) return bad(res, 400, "A dispute needs the buyer's valid signature");
    // Track records only count real, mainnet payments from the buyer's own wallet to a listed seller.
    if ((r.network || network) !== network) return bad(res, 400, `Receipts must be for ${network}, the network this directory runs on`);
    const listed = A.getCard(parties.seller.agent_id)?.card;
    if (!listed?.payment?.pay_to) return bad(res, 400, "The seller must be listed in the directory, with a payment address, for receipts to count");
    const payTo = r.seller.pay_to;
    if (listed.payment.pay_to.toLowerCase() !== String(payTo).toLowerCase()) return bad(res, 400, "seller.pay_to doesn't match the seller's listed payment address");
    if (!/^0x[0-9a-fA-F]{40}$/.test(r.payment?.from || "")) return bad(res, 400, "payment.from must be the buyer's paying wallet (0x…), covered by the buyer's signature");
    if (!A.reserveTx(r.payment?.tx)) return bad(res, 409, "This payment was already used for a receipt");
    const pay = await verifyUsdcTransfer({ network, tx: r.payment?.tx, to: payTo, min_usd: r.amount_usd, from: r.payment.from });
    if (!pay.ok) { A.releaseTx(r.payment?.tx); return bad(res, 422, "Payment check failed: " + pay.error); }
    A.recordDeal({ buyer: parties.buyer.agent_id, seller: parties.seller.agent_id, amount_usd: r.amount_usd, tx: r.payment.tx, outcome: r.outcome });
    res.status(201).json({ recorded: r.outcome, receipt_hash: crypto.createHash("sha256").update(canonical(r)).digest("hex"), payment: pay, buyer_trust: A.trustOf(parties.buyer.agent_id), seller_trust: A.trustOf(parties.seller.agent_id) });
  });

  // ---- deal checkouts (off unless DEAL_CHECKOUT=1, pending legal advice) ----
  if (checkoutEnabled) {
    app.post("/v1/checkouts", perIp("co", 60, 3600e3), (req, res) => {
      const b = req.body || {};
      if (!/^0x[0-9a-fA-F]{40}$/.test(b.pay_to || "")) return bad(res, 400, "pay_to must be the seller's 0x address");
      if (!(typeof b.amount_usd === "number" && b.amount_usd >= A.AGENT_LIMITS.checkoutMinUsd && b.amount_usd <= A.AGENT_LIMITS.checkoutMaxUsd)) return bad(res, 400, `amount_usd must be ${A.AGENT_LIMITS.checkoutMinUsd}–${A.AGENT_LIMITS.checkoutMaxUsd}`);
      if (Math.round(b.amount_usd * 1e6) / 1e6 !== b.amount_usd) return bad(res, 400, "amount_usd has too many decimals (max 6)");
      if (b.ref != null && !(typeof b.ref === "string" && b.ref.length <= 100)) return bad(res, 400, "ref ≤ 100 chars (e.g. the deal's terms_hash)");
      const c = A.createCheckout(b);
      res.status(201).json({ ...A.publicCheckout(c), pay: `POST ${publicUrl}/v1/checkouts/${c.id}/pay (x402: pays ${b.amount_usd} USDC from the buyer's wallet straight to ${b.pay_to})` });
    });
    app.get("/v1/checkouts/:id", (req, res) => {
      const c = A.getCheckout(req.params.id);
      c ? res.json(A.publicCheckout(c)) : bad(res, 404, "No such checkout");
    });
  }

  // ---- operator ----
  app.get("/admin/agents", adminCheck, (req, res) => res.json({ stats: A.directoryStats(), agents: A.listAgentsAdmin().slice(0, 500), reports: A.openAgentReports() }));
  app.post("/admin/agents/:id/delist", adminCheck, (req, res) => res.json({ delisted: A.removeCard(req.params.id, { banned: true }) }));
  app.post("/admin/agents/:id/unban", adminCheck, (req, res) => res.json({ unbanned: A.unbanAgent(req.params.id) }));
  app.post("/admin/agent-reports/:rid", adminCheck, (req, res) => { const r = A.resolveAgentReport(req.params.rid, String(req.body?.status || "resolved")); r ? res.json(r) : bad(res, 404, "No such report"); });
}

// x402 route config for checkouts: price and payTo come from the checkout record, so the
// facilitator settles buyer -> seller directly. Suppressor never receives these funds.
export function checkoutRoute(network) {
  const find = (ctx) => A.getCheckout(String(ctx.path || ctx.adapter?.getPath?.() || "").split("/")[3]);
  return {
    accepts: [{
      scheme: "exact", network, maxTimeoutSeconds: 120,
      payTo: (ctx) => find(ctx)?.pay_to || "0x0000000000000000000000000000000000000000",
      price: (ctx) => "$" + (find(ctx)?.amount_usd ?? 0),
    }],
    description: "Deal checkout: pay the seller directly in USDC (gasless via x402). Suppressor does not take custody or a fee.",
    mimeType: "application/json",
  };
}
export { USDC_BY_NETWORK };
