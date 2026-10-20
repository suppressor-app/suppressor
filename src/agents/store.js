// Agent directory, sealed contact inboxes, verified deal receipts and (optional) deal checkouts.
// What's stored: signed public business cards, reputation counters, receipt fingerprints,
// checkout records. Knocks are encrypted, held in memory only and deleted when read.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export const AGENT_LIMITS = {
  maxCardBytes: 16 * 1024,
  maxCardDays: 30,
  maxListings: 10000,
  publishPerIpPerHour: 20,
  knockBytes: 24 * 1024,
  knocksPerInbox: 100,
  knocksPerIpPerHour: 60,
  knockHours: 24,
  clockSkewMs: 120e3,
  checkoutMinUsd: 0.01,
  checkoutMaxUsd: 1000,
};

const cards = new Map(); // agent_id -> { card, first_listed_at, updated_at }
const rep = new Map(); // agent_id -> { deals: n, as_seller, as_buyer, disputes_received, disputes_filed, volume_usd, partners: [hash], last_deal_at }
const usedTx = new Set(); // payment tx hashes already counted in a receipt
const agentReports = []; // { id, agent_id, reason, at, status }
const checkouts = new Map(); // id -> { id, pay_to, amount_usd, ref, created_at, expires_at, status, tx, payer }
const knocks = new Map(); // agent_id -> [{ id, sealed, at }]  (memory only)
const nonces = new Map(); // nonce -> expiry
const reservedTx = new Set(); // tx hashes being checked right now (stops parallel double-use)
const tombstones = new Map(); // agent_id -> { issued_at, banned }: removed cards can't be replayed
let file = null, dirty = false;
const now = () => Date.now();
const iso = (t) => new Date(t).toISOString();
const hash = (s) => crypto.createHash("sha256").update(String(s)).digest("hex");
const rid = (p, n = 12) => p + crypto.randomBytes(n).toString("base64url");

export function initAgents(dataDir) {
  if (dataDir) {
    try {
      fs.mkdirSync(dataDir, { recursive: true });
      file = path.join(dataDir, "agents.json");
      if (fs.existsSync(file)) {
        const s = JSON.parse(fs.readFileSync(file, "utf8"));
        for (const c of s.cards || []) cards.set(c.card.agent_id, c);
        for (const [k, v] of s.rep || []) rep.set(k, v);
        for (const t of s.usedTx || []) usedTx.add(t);
        agentReports.push(...(s.reports || []));
        for (const c of s.checkouts || []) checkouts.set(c.id, c);
        for (const [k, v] of s.tombstones || []) tombstones.set(k, v);
      }
    } catch (e) { console.error("[agents] storage unavailable:", e.message); file = null; }
  }
  setInterval(save, 15000).unref();
  setInterval(sweep, 60000).unref();
}
function save() {
  if (!file || !dirty) return;
  try {
    fs.writeFileSync(file + ".tmp", JSON.stringify({ cards: [...cards.values()], rep: [...rep], usedTx: [...usedTx], reports: agentReports, checkouts: [...checkouts.values()], tombstones: [...tombstones] }));
    fs.renameSync(file + ".tmp", file);
    dirty = false;
  } catch (e) { console.error("[agents] save failed:", e.message); }
}
export function sweep() {
  const t = now();
  for (const [id, c] of cards) if (Date.parse(c.card.expires_at) <= t) { cards.delete(id); dirty = true; }
  for (const [id, list] of knocks) { const keep = list.filter((k) => t - k.at < AGENT_LIMITS.knockHours * 3600e3); keep.length ? knocks.set(id, keep) : knocks.delete(id); }
  for (const [n, exp] of nonces) if (exp <= t) nonces.delete(n);
  for (const [id, c] of checkouts) if (c.status === "open" && c.expires_at <= t) { c.status = "expired"; dirty = true; }
  for (const [id, c] of checkouts) if (t - c.created_at > 90 * 86400e3) { checkouts.delete(id); dirty = true; }
}

// ---- replay protection for signed requests -----------------------------------------
export function useNonce(nonce, ts) {
  if (Math.abs(now() - ts) > AGENT_LIMITS.clockSkewMs) return "Request time is off by more than 2 minutes. Check the clock.";
  if (nonces.has(nonce)) return "Replayed request (nonce already used).";
  if (nonces.size >= 200000) {
    for (const [n, exp] of nonces) if (exp <= now()) nonces.delete(n); // evict only expired ones
    if (nonces.size >= 200000) return "Server is busy. Try again in a minute."; // never forget live nonces
  }
  nonces.set(nonce, now() + 2 * AGENT_LIMITS.clockSkewMs + 60e3);
  return null;
}

// ---- directory -------------------------------------------------------------------
const str = (v, max) => typeof v === "string" && v.length <= max;
const optStr = (v, max) => v == null || str(v, max);
const okUrl = (v) => v == null || (str(v, 300) && /^https:\/\/[^\s]+$/.test(v));
export function validateCard(c) {
  if (!c || typeof c !== "object" || Array.isArray(c)) return "card must be an object";
  if (Buffer.byteLength(JSON.stringify(c)) > AGENT_LIMITS.maxCardBytes) return "card too large (16 KB max)";
  if (c.v !== 1) return "card.v must be 1";
  if (!/^agt_[A-Za-z0-9_-]{26}$/.test(c.agent_id || "")) return "card.agent_id is malformed";
  if (!/^[A-Za-z0-9_-]{43}$/.test(c.sign_key || "")) return "card.sign_key must be a base64url Ed25519 public key";
  if (!/^[A-Za-z0-9+/]{43}=$/.test(c.box_key || "")) return "card.box_key must be a base64 X25519 public key";
  if (!str(c.name, 80) || !c.name.trim()) return "card.name required (≤ 80 chars)";
  if (!optStr(c.description, 600)) return "card.description ≤ 600 chars";
  if (c.tags != null && !(Array.isArray(c.tags) && c.tags.length <= 12 && c.tags.every((t) => str(t, 32)))) return "card.tags: up to 12 strings of ≤ 32 chars";
  if (!Array.isArray(c.services) || c.services.length > 20) return "card.services must be an array (≤ 20)";
  for (const s of c.services) {
    if (!s || !str(s.id, 48) || !/^[a-z0-9][a-z0-9._-]*$/.test(s.id)) return "service.id: lowercase letters, digits, . _ -";
    if (!str(s.title, 100) || !optStr(s.description, 600) || !optStr(s.category, 40) || !optStr(s.output, 200) || !optStr(s.turnaround, 60)) return `service ${s.id}: title ≤ 100; description ≤ 600; category ≤ 40; output ≤ 200; turnaround ≤ 60`;
    const p = s.price || {};
    if (!["fixed", "per_unit", "quote"].includes(p.model)) return `service ${s.id}: price.model must be fixed, per_unit or quote`;
    if (p.model !== "quote" && !(typeof p.usd === "number" && p.usd >= 0 && p.usd <= 100000)) return `service ${s.id}: price.usd must be 0–100000`;
    if (p.model === "per_unit" && !str(p.unit, 30)) return `service ${s.id}: per_unit needs price.unit`;
    if (s.input != null && Buffer.byteLength(JSON.stringify(s.input)) > 4000) return `service ${s.id}: input schema ≤ 4 KB`;
  }
  if (c.protocols != null && !(Array.isArray(c.protocols) && c.protocols.length <= 10 && c.protocols.every((t) => str(t, 40)))) return "card.protocols: up to 10 strings";
  const pay = c.payment;
  if (pay != null && !(pay.asset === "USDC" && /^eip155:\d+$/.test(pay.network || "") && /^0x[0-9a-fA-F]{40}$/.test(pay.pay_to || ""))) return "card.payment must be {network:'eip155:…', asset:'USDC', pay_to:'0x…'}";
  const ep = c.endpoints || {};
  if (!okUrl(ep.mcp) || !okUrl(ep.a2a) || !okUrl(ep.http)) return "card.endpoints values must be https URLs";
  const issued = Date.parse(c.issued_at), exp = Date.parse(c.expires_at);
  if (!(issued > 0 && exp > 0)) return "card.issued_at and expires_at must be ISO dates";
  if (issued > now() + AGENT_LIMITS.clockSkewMs) return "card.issued_at is in the future";
  if (exp <= now() || exp - issued > AGENT_LIMITS.maxCardDays * 86400e3 + 60e3) return "card.expires_at must be in the future and ≤ 30 days after issued_at";
  if (typeof c.sig !== "string") return "card.sig missing";
  return null;
}

// Receipts have one exact shape (the SDK's receiptBody plus sigs). Anything extra is refused,
// so a signed document of another kind can't be dressed up as a receipt.
const RECEIPT_KEYS = { top: ["v", "deal_id", "terms_hash", "amount_usd", "network", "buyer", "seller", "payment", "delivery_hash", "outcome", "sig_v", "sigs"],
  buyer: ["agent_id", "sign_key"], seller: ["agent_id", "sign_key", "pay_to"], payment: ["tx", "from"], sigs: ["buyer", "seller"] };
export function receiptShapeError(r) {
  const only = (o, keys, name) => {
    if (!o || typeof o !== "object" || Array.isArray(o)) return `${name} must be an object`;
    const extra = Object.keys(o).find((k) => !keys.includes(k));
    return extra ? `unexpected field ${name === "receipt" ? "" : name + "."}${extra}` : null;
  };
  return only(r, RECEIPT_KEYS.top, "receipt") || only(r.buyer, RECEIPT_KEYS.buyer, "buyer") || only(r.seller, RECEIPT_KEYS.seller, "seller") ||
    only(r.payment, RECEIPT_KEYS.payment, "payment") || only(r.sigs, RECEIPT_KEYS.sigs, "sigs") ||
    (r.delivery_hash != null && !str(r.delivery_hash, 100) ? "delivery_hash must be a string" : null) ||
    (r.sig_v !== undefined && r.sig_v !== 2 ? "sig_v must be 2 when present" : null);
}
export function putCard(card) {
  const tomb = tombstones.get(card.agent_id);
  if (tomb?.banned) return { status: 403, error: "This agent was removed from the directory by the operator." };
  if (tomb && Date.parse(card.issued_at) <= tomb.issued_at) return { status: 409, error: "This card was withdrawn. Publish a newly signed card to list again." };
  const prev = cards.get(card.agent_id);
  if (prev && Date.parse(prev.card.issued_at) >= Date.parse(card.issued_at)) return { status: 409, error: "An equal or newer card is already listed (issued_at must increase)." };
  if (!prev && cards.size >= AGENT_LIMITS.maxListings) return { status: 503, error: "Directory is full right now." };
  cards.set(card.agent_id, { card, first_listed_at: prev?.first_listed_at || now(), updated_at: now() });
  dirty = true;
  return { listed: true };
}
export const getCard = (id) => cards.get(id) || null;
// Removing a card leaves a tombstone so the old signed card can't simply be re-posted.
// banned: the operator delisted it, and only the operator can lift that (delete the tombstone).
export function removeCard(id, { banned = false } = {}) {
  const c = cards.get(id);
  const prev = tombstones.get(id);
  tombstones.set(id, { issued_at: Math.max(c ? Date.parse(c.card.issued_at) : 0, prev?.issued_at || 0), banned: banned || !!prev?.banned });
  const ok = cards.delete(id); knocks.delete(id); dirty = true; return ok;
}
export function unbanAgent(id) { const ok = tombstones.delete(id); dirty = true; return ok; }

export function trustOf(id) {
  const r = rep.get(id) || {};
  const c = cards.get(id);
  return {
    verified_deals: r.deals || 0,
    as_seller: r.as_seller || 0,
    as_buyer: r.as_buyer || 0,
    distinct_counterparties: (r.partners || []).length,
    disputes_received: r.disputes_received || 0,
    last_deal_at: r.last_deal_at ? iso(r.last_deal_at).slice(0, 10) : null,
    listed_since: c ? iso(c.first_listed_at).slice(0, 10) : null,
    open_reports: agentReports.filter((x) => x.agent_id === id && x.status === "open").length,
    note: "Counts of deals both parties signed and paid on-chain. Signals, not guarantees.",
  };
}
export const publicListing = (id) => { const c = cards.get(id); return c ? { agent_id: id, card: c.card, trust: trustOf(id) } : null; };

export function search({ q = "", category, max_usd, protocol, sort = "relevance", limit = 20 } = {}) {
  const terms = String(q).toLowerCase().split(/\s+/).filter((t) => t.length > 1).slice(0, 8);
  const out = [];
  for (const [id, { card }] of cards) {
    const svc = card.services.filter((s) => (!category || (s.category || "").toLowerCase() === String(category).toLowerCase()) &&
      (max_usd == null || s.price.model === "quote" || s.price.usd <= max_usd));
    if ((category || max_usd != null) && !svc.length) continue;
    if (protocol && !(card.protocols || []).map((p) => p.toLowerCase()).some((p) => p.startsWith(String(protocol).toLowerCase()))) continue;
    const hay = [card.name, card.description, ...(card.tags || []), ...card.services.flatMap((s) => [s.title, s.description, s.category, s.id])].join(" ").toLowerCase();
    const hits = terms.filter((t) => hay.includes(t)).length;
    if (terms.length && !hits) continue;
    const t = trustOf(id);
    const minPrice = Math.min(...svc.concat(card.services).map((s) => (s.price.model === "quote" ? Infinity : s.price.usd)));
    out.push({ id, hits, deals: t.verified_deals, price: minPrice, t });
  }
  const rank = {
    relevance: (a, b) => b.hits - a.hits || b.deals - a.deals,
    price: (a, b) => a.price - b.price || b.hits - a.hits,
    deals: (a, b) => b.deals - a.deals || b.hits - a.hits,
  }[sort] || ((a, b) => b.hits - a.hits);
  return out.sort(rank).slice(0, Math.min(50, Math.max(1, limit))).map((x) => publicListing(x.id));
}
export const directoryStats = () => ({ listed_agents: cards.size, verified_deals: [...rep.values()].reduce((a, r) => a + (r.as_seller || 0), 0), open_agent_reports: agentReports.filter((r) => r.status === "open").length, pending_knocks: [...knocks.values()].reduce((a, l) => a + l.length, 0), checkouts_paid: [...checkouts.values()].filter((c) => c.status === "paid").length });
export const listAgentsAdmin = () => [...cards.values()].map((c) => ({ agent_id: c.card.agent_id, name: c.card.name, services: c.card.services.length, listed_since: iso(c.first_listed_at), expires_at: c.card.expires_at, ...trustOf(c.card.agent_id) }));

// ---- knocks (sealed contact requests) ---------------------------------------------
export function addKnock(agentId, sealed) {
  const list = knocks.get(agentId) || [];
  if (list.length >= AGENT_LIMITS.knocksPerInbox) return { status: 429, error: "This agent's inbox is full. Try again later." };
  const k = { id: rid("kn_", 9), sealed, at: Math.floor(now() / 60e3) * 60e3 };
  list.push(k);
  knocks.set(agentId, list);
  return { knock_id: k.id };
}
export const hasKnocks = (agentId) => (knocks.get(agentId) || []).length > 0;
export function takeKnocks(agentId) {
  const list = knocks.get(agentId) || [];
  knocks.delete(agentId);
  return list.map((k) => ({ knock_id: k.id, sealed: k.sealed, received_at: iso(k.at) }));
}

// ---- reports ------------------------------------------------------------------------
export function reportAgent(agent_id, reason) {
  const r = { id: rid("ar_", 8), agent_id, reason, at: iso(now()), status: "open" };
  agentReports.push(r);
  dirty = true;
  return r;
}
export const openAgentReports = () => agentReports.filter((r) => r.status === "open");
export function resolveAgentReport(id, status) { const r = agentReports.find((x) => x.id === id); if (r) { r.status = status; dirty = true; } return r; }

// ---- receipts → reputation ------------------------------------------------------------
export function txUsed(tx) { return usedTx.has(String(tx).toLowerCase()); }
// Claim a tx before the (slow) on-chain check so two receipts can't both pass with it.
export function reserveTx(tx) { const k = String(tx).toLowerCase(); if (usedTx.has(k) || reservedTx.has(k)) return false; reservedTx.add(k); return true; }
export function releaseTx(tx) { reservedTx.delete(String(tx).toLowerCase()); }
export function recordDeal({ buyer, seller, amount_usd, tx, outcome }) {
  usedTx.add(String(tx).toLowerCase());
  reservedTx.delete(String(tx).toLowerCase());
  const t = now();
  const pair = hash([buyer, seller].sort().join("|")).slice(0, 20);
  const bump = (id, f) => {
    const r = rep.get(id) || { deals: 0, as_seller: 0, as_buyer: 0, disputes_received: 0, disputes_filed: 0, volume_usd: 0, partners: [] };
    f(r);
    if (!r.partners.includes(pair)) r.partners.push(pair);
    r.last_deal_at = t;
    rep.set(id, r);
  };
  if (outcome === "completed") {
    bump(seller, (r) => { r.deals++; r.as_seller++; r.volume_usd = Math.round((r.volume_usd + amount_usd) * 100) / 100; });
    bump(buyer, (r) => { r.deals++; r.as_buyer++; });
  } else {
    bump(seller, (r) => { r.disputes_received++; });
    bump(buyer, (r) => { r.disputes_filed++; });
  }
  dirty = true;
}

// ---- deal checkouts (x402, buyer pays seller directly) ---------------------------------
export function createCheckout({ pay_to, amount_usd, ref, expires_minutes = 60 }) {
  const c = { id: rid("co_", 12), pay_to, amount_usd, ref: ref || null, created_at: now(), expires_at: now() + Math.min(1440, Math.max(5, expires_minutes)) * 60e3, status: "open", tx: null, payer: null };
  checkouts.set(c.id, c);
  dirty = true;
  return c;
}
export const getCheckout = (id) => checkouts.get(id) || null;
export function markCheckoutPaid(c, { tx, payer }) { c.status = "paid"; c.tx = tx; c.payer = payer; c.paid_at = now(); dirty = true; }
export const publicCheckout = (c) => ({ checkout_id: c.id, status: c.status, pay_to: c.pay_to, amount_usd: c.amount_usd, ref: c.ref, expires_at: iso(c.expires_at), tx: c.tx, payer: c.payer, paid_at: c.paid_at ? iso(c.paid_at) : null });
