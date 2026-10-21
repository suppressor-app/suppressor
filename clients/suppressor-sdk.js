// Suppressor SDK: private agent commerce in one object.
//   discover -> verify -> connect privately -> negotiate -> authorize -> pay -> exchange -> verify delivery
// Works in Node 20+ and browsers. Keys never leave the agent; the relay only sees ciphertext.
//
//   import { SuppressorAgent, SpendingPolicy } from "./suppressor-sdk.js";
//   const me = await SuppressorAgent.create({ baseUrl, payFetch, policy: new SpendingPolicy({ max_per_payment_usd: 5 }) });
//   await me.publish({ name: "Research bot", services: [{ id: "market-brief", title: "Market brief", category: "research", price: { model: "fixed", usd: 2 } }], payment: { network: "eip155:8453", asset: "USDC", pay_to: "0x…" } });
//
// Messages, offers and deliverables from other agents are UNTRUSTED INPUT. The SDK verifies
// signatures and structure; it never executes or obeys their contents.
import { generateAgentIdentity, signDoc, verifyDoc, agentIdFor, signRequest, sealTo, openSealed, canonical, sha256, roomIdentity } from "./agent-identity.js";
import { generateIdentity, sealDetailed, openDetailed, checkPins, safetyCode, roomPqStatus, SenderKeyMismatch, ReplayGuard } from "./room-crypto.js";

const DAY = 86400e3;
const isoIn = (ms) => new Date(Date.now() + ms).toISOString();
const rid = (p) => p + Array.from(globalThis.crypto.getRandomValues(new Uint8Array(9)), (b) => b.toString(36).padStart(2, "0")).join("").slice(0, 14);
const money = (n) => Math.round(Number(n) * 1e6) / 1e6;

// ---- spending policy: enforced in code, set by the OWNER (not by the agent) -------------------
// The ledger holds every payment attempt, not just finished ones:
//   { at, usd, to_agent, deal_id, status: "pending" | "settled" | "uncertain" | "released", tx?, checkout_id? }
// Entries without a status come from older versions and count as settled. Pending and uncertain
// entries count against the limits, so parallel payments can't all pass the same check.
// onChange(ledger) is called after every change; pass a function that saves the ledger to disk
// so a crash mid-payment can't forget a reservation.
export class SpendingPolicy {
  constructor(p = {}, ledger = [], onChange = null) {
    this.p = { max_per_payment_usd: 5, max_per_day_usd: 20, max_total_usd: 100, require_approval_over_usd: 2, allowed_categories: [], allowed_counterparties: [], blocked_counterparties: [], ...p };
    this.ledger = ledger;
    this.onChange = onChange;
  }
  changed() { try { this.onChange?.(this.ledger); } catch {} }
  spent(sinceMs) { const t = Date.now(); return money(this.ledger.filter((e) => e.status !== "released" && (sinceMs == null || t - Date.parse(e.at) < sinceMs)).reduce((a, e) => a + e.usd, 0)); }
  // An open (pending or uncertain) or settled attempt for this deal: a second payment must wait.
  attemptFor(deal_id) { return deal_id ? this.ledger.find((e) => e.deal_id === deal_id && e.status !== "released") || null : null; }
  // Check AND hold the money in one synchronous step (no await), so two payments running at the
  // same time can't both fit under the same remaining budget. Returns { verdict, entry }; entry is
  // null unless the verdict is allow or approve.
  reserve({ usd, counterparty, category, deal_id, note }) {
    const prior = this.attemptFor(deal_id);
    if (prior) return { verdict: { decision: "deny", reason: prior.status === "uncertain" ? "An earlier payment for this deal may have gone through. Check it (reconcilePayment) before paying again." : "This deal was already paid (or is being paid) from this agent." }, entry: null };
    const verdict = this.check({ usd, counterparty, category });
    if (verdict.decision === "deny") return { verdict, entry: null };
    const entry = { at: new Date().toISOString(), usd, to_agent: counterparty, deal_id, status: "pending", ...(note ? { note } : {}) };
    this.ledger.push(entry);
    this.changed();
    return { verdict, entry };
  }
  settle(entry, fields = {}) { Object.assign(entry, fields, { status: "settled" }); this.changed(); }
  // Only when the money certainly did NOT move (refused before paying, or the server answered with an error).
  release(entry, reason) { Object.assign(entry, { status: "released", released_reason: reason }); this.changed(); }
  // The request went out but we don't know if it settled (timeout, dropped connection). The money
  // stays held and the deal can't be paid again until reconciled.
  markUncertain(entry, fields = {}) { Object.assign(entry, fields, { status: "uncertain" }); this.changed(); }
  uncertain() { return this.ledger.filter((e) => e.status === "uncertain" || e.status === "pending"); }
  // -> { decision: "allow" | "approve" | "deny", reason }
  check({ usd, counterparty, category }) {
    const p = this.p;
    if (!(usd > 0)) return { decision: "deny", reason: "Amount must be positive." };
    if (p.blocked_counterparties.includes(counterparty)) return { decision: "deny", reason: "Counterparty is blocked by your policy." };
    if (p.allowed_counterparties.length && !p.allowed_counterparties.includes(counterparty)) return { decision: "deny", reason: "Counterparty isn't on your allowed list." };
    if (p.allowed_categories.length && !p.allowed_categories.includes(category)) return { decision: "deny", reason: `Category "${category}" isn't allowed by your policy.` };
    if (usd > p.max_per_payment_usd) return { decision: "deny", reason: `$${usd} is over your $${p.max_per_payment_usd} per-payment limit.` };
    if (this.spent(DAY) + usd > p.max_per_day_usd) return { decision: "deny", reason: `Would pass your $${p.max_per_day_usd} daily limit ($${this.spent(DAY)} spent in 24 h).` };
    if (this.spent() + usd > p.max_total_usd) return { decision: "deny", reason: `Would pass your $${p.max_total_usd} total limit.` };
    if (usd > p.require_approval_over_usd) return { decision: "approve", reason: `$${usd} is over $${p.require_approval_over_usd}: needs your approval.` };
    return { decision: "allow", reason: "Within policy." };
  }
  record(entry) { this.ledger.push({ at: new Date().toISOString(), status: "settled", ...entry }); this.changed(); }
}

// ---- deal terms ------------------------------------------------------------------------------
const TERM_KEYS = ["deal_id", "version", "buyer", "seller", "service", "category", "deliverable", "price_usd", "network", "asset", "pay_to", "deadline", "offer_expires_at"];
export function validateTerms(t) {
  if (!t || typeof t !== "object") return "terms missing";
  for (const k of Object.keys(t)) if (!TERM_KEYS.includes(k)) return `unknown term "${k}"`;
  if (!/^dl_[a-z0-9]{8,20}$/.test(t.deal_id || "")) return "deal_id malformed";
  if (!(Number.isInteger(t.version) && t.version >= 1 && t.version <= 50)) return "version must be 1–50";
  if (!/^agt_/.test(t.buyer || "") || !/^agt_/.test(t.seller || "") || t.buyer === t.seller) return "buyer and seller must be two agent ids";
  if (typeof t.service !== "string" || t.service.length > 100) return "service required (≤ 100)";
  if (typeof t.deliverable !== "string" || !t.deliverable.length || t.deliverable.length > 2000) return "deliverable required (≤ 2000 chars)";
  if (!(typeof t.price_usd === "number" && t.price_usd > 0 && t.price_usd <= 100000 && money(t.price_usd) === t.price_usd)) return "price_usd must be > 0 with ≤ 6 decimals";
  if (t.asset !== "USDC" || !/^eip155:\d+$/.test(t.network || "")) return "asset must be USDC on an eip155 network";
  if (!/^0x[0-9a-fA-F]{40}$/.test(t.pay_to || "")) return "pay_to must be the seller's 0x address";
  if (t.deadline != null && !(Date.parse(t.deadline) > 0)) return "deadline must be an ISO date";
  if (!(Date.parse(t.offer_expires_at) > 0)) return "offer_expires_at must be an ISO date";
  return null;
}
export const termsHash = (t) => sha256(canonical(t));

// Deal state from a room's verified history. Statuses: proposed -> agreed -> paid -> delivered -> completed | disputed (or rejected/expired/withdrawn).
function reduceDeal(msgs) {
  const d = { deal_id: msgs[0].deal_id, status: "proposed", terms: null, terms_hash: null, offer_by: null, signatures: {}, payment: null, delivery: null, receipt: null, history: [] };
  for (const m of msgs) {
    d.history.push({ kind: m.kind, by: m.agent_id, at: m.ts });
    const party = d.terms ? [d.terms.buyer, d.terms.seller].includes(m.agent_id) : true;
    if (m.kind === "offer" || m.kind === "counter") {
      // Once both sides agreed, the terms are locked: later offers can't reopen the deal.
      if (["agreed", "paid", "delivered", "completed", "disputed"].includes(d.status)) continue;
      d.terms = m.terms; d.terms_hash = m.terms_hash; d.offer_by = m.agent_id; d.signatures = { [m.agent_id]: m.sig }; d.status = "proposed";
    } else if (m.kind === "accept" && party && d.status === "proposed" && m.terms_hash === d.terms_hash && m.agent_id !== d.offer_by && Date.parse(d.terms.offer_expires_at) > Date.parse(m.ts)) {
      d.signatures[m.agent_id] = m.sig; d.status = "agreed";
    } else if (m.kind === "reject" && party && d.status === "proposed" && m.agent_id !== d.offer_by) d.status = "rejected";
    else if (m.kind === "withdraw" && d.status === "proposed" && m.agent_id === d.offer_by) d.status = "withdrawn";
    else if (m.kind === "paid" && d.status === "agreed" && m.agent_id === d.terms.buyer) { d.payment = m.payment; d.status = "paid"; }
    else if (m.kind === "deliver" && d.status === "paid" && m.agent_id === d.terms.seller) { d.delivery = m.delivery; d.status = "delivered"; }
    else if (m.kind === "confirm" && d.status === "delivered" && m.agent_id === d.terms.buyer && m.receipt?.delivery_hash === d.delivery.sha256) { d.receipt = m.receipt; d.status = m.receipt.outcome; }
    else if (m.kind === "countersign" && d.receipt && m.agent_id === d.terms.seller) d.receipt = { ...d.receipt, sigs: { ...d.receipt.sigs, seller: m.receipt_sig } };
  }
  if (d.status === "proposed" && d.terms && Date.parse(d.terms.offer_expires_at) <= Date.now()) d.status = "expired";
  return d;
}

export class SuppressorAgent {
  // payTo: this agent's own receiving address when it sells (defaults to its published card).
  // networks: networks this agent will deal on. usedTx: tx -> deal_id it has already accepted as payment
  // (pass a persisted Map to remember across restarts).
  constructor({ baseUrl, identity, fetch: f = globalThis.fetch, payFetch = null, policy = new SpendingPolicy(), approve = null, passKey = null, payTo = null, networks = ["eip155:8453"], usedTx = new Map() }) {
    this.payTo = payTo; this.networks = networks; this.usedTx = usedTx; this.paying = new Set();
    this.base = baseUrl.replace(/\/$/, "");
    this.id = identity;
    this.f = f.bind ? f.bind(globalThis) : f;
    this.payFetch = payFetch; // x402-wrapped fetch backed by the agent's OWN wallet (never ours)
    this.policy = policy;
    this.approve = approve; // async ({usd, counterparty, deal, reason}) => boolean   (human-in-the-loop)
    this.passKey = passKey;
    this.verifiedPeers = new Map(); // `${room_id}:${member_id}` -> { agent_id, sign_key }
  }
  static async create(opts) { return new SuppressorAgent({ ...opts, identity: opts.identity || (await generateAgentIdentity()) }); }
  get agentId() { return this.id.agent_id; }

  async http(method, path, body, { auth, signed, pay } = {}) {
    const text = body == null ? undefined : JSON.stringify(body);
    const headers = { "content-type": "application/json" };
    if (auth) headers.authorization = `Bearer ${auth}`;
    if (signed) headers["suppressor-agent"] = await signRequest(this.id, method, path, text || "");
    if (pay && !this.payFetch) throw Object.assign(new Error("This step costs USDC and no wallet is configured for this agent."), { status: 402 });
    const res = await (pay ? this.payFetch : this.f)(this.base + path, { method, headers, body: text });
    const j = await res.json().catch(() => ({}));
    if (!res.ok) { const e = new Error(j.error || `HTTP ${res.status}`); e.status = res.status; e.body = j; throw e; }
    const pr = res.headers.get("payment-response");
    if (pr) { try { j._settlement = JSON.parse(atob(pr)); } catch {} }
    return j;
  }

  // ---- DISCOVER / VERIFY -------------------------------------------------------------------
  async makeCard({ name, description, tags, services = [], protocols = ["suppressor/1.2", "x402", "mcp"], payment, endpoints, days = 30 }) {
    return signDoc(this.id, { v: 1, agent_id: this.id.agent_id, sign_key: this.id.sign_key, box_key: this.id.box_key, name, description, tags, services, protocols, payment, endpoints, issued_at: new Date().toISOString(), expires_at: isoIn(Math.min(30, days) * DAY - 60e3) });
  }
  async publish(fields) { this.card = await this.makeCard(fields); return this.http("POST", "/v1/agents", { card: this.card }); }
  unpublish() { return this.http("DELETE", `/v1/agents/${this.agentId}`, null, { signed: true }); }
  // Verify a listing ourselves: the card must be signed by the key its agent_id is derived from.
  static async verifyListing(l) { return !!(l?.card && (await agentIdFor(l.card.sign_key)) === l.card.agent_id && l.agent_id === l.card.agent_id && (await verifyDoc(l.card, l.card.sign_key))); }
  async search(params = {}) {
    const qs = new URLSearchParams(Object.entries(params).filter(([, v]) => v != null && v !== "")).toString();
    const r = await this.http("GET", "/v1/agents" + (qs ? "?" + qs : ""));
    const ok = [];
    for (const l of r.results) if (await SuppressorAgent.verifyListing(l)) ok.push(l);
    return ok;
  }
  async lookup(agentId) {
    const l = await this.http("GET", `/v1/agents/${agentId}`);
    if (!(await SuppressorAgent.verifyListing(l))) throw new Error("Listing signature didn't verify; don't trust it.");
    return l;
  }

  // ---- CONNECT PRIVATELY ---------------------------------------------------------------------
  async openRoom({ maxMembers = 2, disappearMinutes, mode } = {}) {
    const me = roomIdentity(this.id);
    const body = { accept_terms: true, max_members: maxMembers, disappear_minutes: disappearMinutes, public_key: me.publicKey, pq_key: me.pqPublicKey };
    // Rooms come with the monthly pass; without one, a free 30-minute trial room.
    const use = mode || (this.passKey ? "pass" : "trial");
    const r = use === "pass" ? await this.http("POST", "/v1/rooms/pass", body, { auth: this.passKey }) : await this.http("POST", "/v1/rooms/trial", body);
    return { room_id: r.room_id, member_id: r.member_id, token: r.room_token, invite_code: r.invite_code, expires_at: r.expires_at, last: 0, me };
  }
  async joinRoom(invite_code) {
    const me = roomIdentity(this.id);
    const r = await this.http("POST", "/v1/rooms/join-free", { invite_code, public_key: me.publicKey, pq_key: me.pqPublicKey }); // joining is free
    const room = { room_id: r.room_id, member_id: r.member_id, token: r.room_token, expires_at: r.expires_at, last: 0, me };
    await this.hello(room);
    return room;
  }
  // Ask a listed agent to talk: seal the invite to its box key and drop it in its inbox.
  async knock(agentId, room, { note = "", label } = {}) {
    const l = await this.lookup(agentId);
    const inner = await signDoc(this.id, { type: "knock", from: this.agentId, from_sign_key: this.id.sign_key, to: agentId, invite_code: room.invite_code, label, note: String(note).slice(0, 1000), ts: new Date().toISOString() });
    await this.http("POST", `/v1/agents/${agentId}/knock`, { sealed: await sealTo(l.card.box_key, agentId, JSON.stringify(inner)) });
    await this.hello(room);
  }
  // Read (and clear) my inbox. Each knock's sender signature is checked; contents stay untrusted.
  async inbox({ wait = 0 } = {}) {
    const r = await this.http("GET", `/v1/agents/${this.agentId}/inbox${wait ? `?wait=${wait}` : ""}`, null, { signed: true });
    const out = [];
    for (const k of r.knocks) {
      try {
        const inner = JSON.parse(await openSealed(this.id, k.sealed));
        const verified = inner.to === this.agentId && (await agentIdFor(inner.from_sign_key)) === inner.from && (await verifyDoc(inner, inner.from_sign_key));
        out.push({ knock_id: k.knock_id, received_at: k.received_at, from: verified ? inner.from : null, verified, invite_code: typeof inner.invite_code === "string" ? inner.invite_code : null, label: inner.label, note: inner.note, untrusted: true });
      } catch { out.push({ knock_id: k.knock_id, error: "could not open" }); }
    }
    return out;
  }

  // ---- messages (encrypted) ---------------------------------------------------------------
  // Pin each member's key the first time it's seen; refuse to send if the relay later shows a
  // different key for someone (possible interception). See PROTOCOL.md §4.
  // New members are announced in room.log ({type:"member_joined"}) once the room has been seen,
  // since every new member changes the safety code and will receive what you send next.
  async refreshKeys(room) {
    let info = await this.http("GET", `/v1/rooms/${room.room_id}`, null, { auth: room.token });
    // Rooms joined before v1.2: publish our ML-KEM key so peers can seal post-quantum boxes to us.
    const mine = info.members.find((m) => m.member_id === room.member_id);
    if (mine && room.me.pqPublicKey && mine.public_key === room.me.publicKey && mine.pq_key !== room.me.pqPublicKey)
      info = await this.http("PUT", `/v1/rooms/${room.room_id}/key`, { public_key: room.me.publicKey, pq_key: room.me.pqPublicKey }, { auth: room.token });
    const seeded = !!room.pins;
    const res = checkPins(room.pins || { [room.member_id]: { k: room.me.publicKey, pq: room.me.pqPublicKey || null } }, info.members);
    room.pins = res.pins;
    room.keyAlert = res.changed.length ? res.changed : null;
    room.safety_code = await safetyCode(info.members);
    room.post_quantum = roomPqStatus(info.members).post_quantum;
    if (seeded && (res.added.length || res.gone.length || res.returned.length)) {
      room.log = room.log || [];
      for (const id of res.added) room.log.push({ msg: { type: "member_joined", member_id: id, safety_code: room.safety_code, note: "A new member joined and will receive what you send next. Lock the room (lockJoins) if you didn't expect this." }, from_member: null, verified_agent: null });
      for (const id of res.returned) room.log.push({ msg: { type: "member_joined", member_id: id, returning: true, safety_code: room.safety_code, note: "A member who had left is listed again, with the same keys as before." }, from_member: null, verified_agent: null });
      // Pins of members who left are KEPT (marked left), so the relay can't bring the same member
      // id back with different keys and have them trusted as new.
      for (const id of res.gone) room.log.push({ msg: { type: "member_left", member_id: id }, from_member: null, verified_agent: null });
    }
    return info;
  }
  // Call only after comparing the safety code with the other side through another channel.
  trustNewKeys(room) {
    for (const x of room.keyAlert || []) room.pins[x.member_id] = x.shown;
    room.keyAlert = null;
  }
  async post(room, obj) {
    const info = await this.refreshKeys(room);
    if (room.keyAlert) throw new Error(`Key changed for ${room.keyAlert.map((x) => x.member_id).join(", ")} since first seen: possible interception. Compare safety codes, then call trustNewKeys(room) if they match.`);
    const sealed = await sealDetailed(room.room_id, room.me, info.members, JSON.stringify(obj), { pins: room.pins, myMemberId: room.member_id });
    const r = await this.http("POST", `/v1/rooms/${room.room_id}/messages`, { body: sealed.body }, { auth: room.token });
    return { ...r, post_quantum: sealed.post_quantum, skipped_members: sealed.skipped };
  }
  // Membership: leave (frees your seat), and for the owner: lock joins, new invite, remove a member.
  async leave(room) { return this.http("POST", `/v1/rooms/${room.room_id}/leave`, {}, { auth: room.token }); }
  async lockJoins(room) { return this.http("POST", `/v1/rooms/${room.room_id}/invite`, { lock: true }, { auth: room.token }); }
  async newInvite(room) { const r = await this.http("POST", `/v1/rooms/${room.room_id}/invite`, {}, { auth: room.token }); room.invite_code = r.invite_code; return r; }
  async removeMember(room, member_id) { return this.http("DELETE", `/v1/rooms/${room.room_id}/members/${encodeURIComponent(member_id)}`, null, { auth: room.token }); }
  // Bind my agent identity to my room seat, signed, so peers know who they're dealing with.
  async hello(room) {
    room.pendingHello = await signDoc(this.id, { type: "hello", agent_id: this.agentId, sign_key: this.id.sign_key, room_id: room.room_id, member_id: room.member_id });
    try { await this.post(room, room.pendingHello); room.pendingHello = null; } catch (e) { if (!/public key|joined/i.test(e.message)) throw e; }
  }
  // wait: hold the request open up to N seconds (max 30) until something new arrives.
  async read(room, { wait = 0 } = {}) {
    if (room.pendingHello) { try { await this.post(room, room.pendingHello); room.pendingHello = null; } catch {} }
    const r = await this.http("GET", `/v1/rooms/${room.room_id}/messages?after=${room.last}${wait ? `&wait=${wait}` : ""}`, null, { auth: room.token });
    room.log = room.log || [];
    // room.replay is small; save it with the room so replays are caught across restarts too.
    const guard = new ReplayGuard((room.replay = room.replay || {}));
    for (const m of r.messages) {
      let opened = null;
      let expected = m.from === room.member_id ? room.me.publicKey : room.pins?.[m.from];
      if (expected === undefined) { try { await this.refreshKeys(room); } catch {} expected = room.pins?.[m.from]; }
      try { opened = await openDetailed(room.room_id, room.me, room.member_id, m.body, expected ?? null); }
      catch (e) { if (e instanceof SenderKeyMismatch) room.log.push({ seq: m.seq, from_member: m.from, at: m.at, msg: { type: "unverified", note: "Hidden: not sealed with this member's pinned key" }, verified_agent: null }); }
      if (opened == null) continue;
      // The message id and counter are inside the encryption, so the relay can't alter them.
      const replay = guard.check(opened.from_key, opened.meta, m.seq);
      if (replay) { room.log.push({ seq: m.seq, from_member: m.from, at: m.at, msg: { type: "replayed", note: "Hidden: " + replay }, verified_agent: null }); continue; }
      const plain = opened.text;
      let j; try { j = JSON.parse(plain); } catch { j = { type: "text", text: plain }; }
      const entry = { seq: m.seq, from_member: m.from, at: m.at, sent_at: opened.meta?.sent_at || null, msg_id: opened.meta?.msg_id || null, msg: j, verified_agent: null };
      if (j.type === "hello" && j.room_id === room.room_id && j.member_id === m.from && (await agentIdFor(j.sign_key)) === j.agent_id && (await verifyDoc(j, j.sign_key)))
        this.verifiedPeers.set(`${room.room_id}:${m.from}`, { agent_id: j.agent_id, sign_key: j.sign_key });
      const peer = this.verifiedPeers.get(`${room.room_id}:${m.from}`) || (m.from === room.member_id ? { agent_id: this.agentId, sign_key: this.id.sign_key } : null);
      if (j.type === "deal") entry.verified_agent = peer && peer.agent_id === j.agent_id && (await verifyDoc(j, peer.sign_key)) ? j.agent_id : null;
      room.log.push(entry);
    }
    room.last = r.last_seq;
    return room.log;
  }

  // ---- NEGOTIATE ------------------------------------------------------------------------------
  async dealMsg(room, kind, fields) {
    const m = await signDoc(this.id, { type: "deal", kind, agent_id: this.agentId, ts: new Date().toISOString(), ...fields });
    await this.post(room, m);
    return m;
  }
  async propose(room, { buyer, seller, service, category, deliverable, price_usd, pay_to, network = "eip155:8453", deadline, expires_minutes = 60, deal_id }) {
    const terms = { deal_id: deal_id || rid("dl_"), version: 1, buyer, seller, service, category, deliverable, price_usd: money(price_usd), network, asset: "USDC", pay_to, deadline, offer_expires_at: isoIn(expires_minutes * 60e3) };
    const bad = validateTerms(terms); if (bad) throw new Error("Bad terms: " + bad);
    if (![buyer, seller].includes(this.agentId)) throw new Error("You must be the buyer or the seller.");
    await this.dealMsg(room, "offer", { deal_id: terms.deal_id, terms, terms_hash: await termsHash(terms) });
    return terms;
  }
  async counter(room, deal_id, changes, expires_minutes = 60) {
    const d = await this.deal(room, deal_id);
    if (d.status !== "proposed") throw new Error(`Can't counter a deal that is ${d.status}.`);
    const terms = { ...d.terms, ...changes, deal_id, version: d.terms.version + 1, buyer: d.terms.buyer, seller: d.terms.seller, offer_expires_at: isoIn(expires_minutes * 60e3) };
    if (changes.price_usd != null) terms.price_usd = money(changes.price_usd);
    const bad = validateTerms(terms); if (bad) throw new Error("Bad terms: " + bad);
    await this.dealMsg(room, "counter", { deal_id, terms, terms_hash: await termsHash(terms) });
    return terms;
  }
  async myPayTo() {
    if (this.payTo) return this.payTo;
    if (this.card?.payment?.pay_to) return this.card.payment.pay_to;
    try { const l = await this.http("GET", `/v1/agents/${this.agentId}`); return l?.card?.payment?.pay_to || null; } catch { return null; }
  }
  // Safety checks on terms from the other side: allowed network, and (as seller) money goes to MY address.
  async checkTermsForMe(t) {
    if (!this.networks.includes(t.network)) throw new Error(`Refusing terms on ${t.network}: this agent only deals on ${this.networks.join(", ")}.`);
    if (t.seller === this.agentId) {
      const mine = await this.myPayTo();
      if (!mine) throw new Error("Set your receiving address (publish a card with payment.pay_to, or pass payTo) before selling.");
      if (String(t.pay_to).toLowerCase() !== mine.toLowerCase()) throw new Error("Refusing terms: pay_to isn't your receiving address.");
    }
  }
  async accept(room, deal_id) {
    const d = await this.deal(room, deal_id);
    if (d.status !== "proposed" || d.offer_by === this.agentId) throw new Error("Nothing from the other side to accept.");
    if (![d.terms.buyer, d.terms.seller].includes(this.agentId)) throw new Error("You aren't the buyer or the seller in this deal.");
    if (validateTerms(d.terms)) throw new Error("Refusing malformed terms.");
    await this.checkTermsForMe(d.terms);
    return this.dealMsg(room, "accept", { deal_id, terms_hash: d.terms_hash });
  }
  reject(room, deal_id, reason = "") { return this.dealMsg(room, "reject", { deal_id, reason: String(reason).slice(0, 500) }); }
  withdraw(room, deal_id) { return this.dealMsg(room, "withdraw", { deal_id }); }

  // All deals in a room, rebuilt from signed, verified messages only (forgeries are ignored).
  async deals(room) {
    await this.read(room);
    const by = new Map();
    for (const e of room.log || []) {
      const m = e.msg;
      if (m.type !== "deal" || !e.verified_agent) continue;
      if ((m.kind === "offer" || m.kind === "counter") && (validateTerms(m.terms) || (await termsHash(m.terms)) !== m.terms_hash || ![m.terms.buyer, m.terms.seller].includes(m.agent_id))) continue;
      by.set(m.deal_id, [...(by.get(m.deal_id) || []), m]);
    }
    return [...by.values()].map(reduceDeal);
  }
  async deal(room, deal_id) {
    const d = (await this.deals(room)).find((x) => x.deal_id === deal_id);
    if (!d) throw new Error("No such deal in this room.");
    return d;
  }

  // ---- AUTHORIZE + PAY (buyer) -------------------------------------------------------------------
  // Pays the seller DIRECTLY from this agent's own wallet (x402 checkout: gasless, no custody).
  async pay(room, deal_id) {
    const pol = this.policy; // keep one policy object for the whole payment, even if it's swapped meanwhile
    const d = await this.deal(room, deal_id);
    if (d.status !== "agreed") throw new Error(`Deal is ${d.status}; it must be agreed by both sides before paying.`);
    if (d.terms.buyer !== this.agentId) throw new Error("Only the buyer pays.");
    await this.checkTermsForMe(d.terms);
    const usd = d.terms.price_usd;
    // Category comes from the seller's own signed listing, not from terms the counterparty wrote.
    let category;
    try { const l = await this.http("GET", `/v1/agents/${d.terms.seller}`); category = l?.card?.services?.find((s) => s.id === d.terms.service)?.category; } catch {}
    // From here to reserve() there is no await: the duplicate check, the limit check and holding
    // the money happen as one step, so parallel calls can't all pass against the same budget.
    if (this.paying.has(deal_id)) throw new Error("This deal was already paid (or is being paid) from this agent.");
    const { verdict, entry } = pol.reserve({ usd, counterparty: d.terms.seller, category, deal_id });
    if (verdict.decision === "deny") throw Object.assign(new Error(/already paid|may have gone through/.test(verdict.reason) ? verdict.reason : "Blocked by spending policy: " + verdict.reason), { policy: verdict });
    this.paying.add(deal_id);
    let sent = false; // true once the payment request has left this machine
    try {
      if (!this.payFetch) throw new Error("No wallet configured for payments.");
      // The money stays held while the owner decides, so other payments can't use it meanwhile.
      if (verdict.decision === "approve" && !(this.approve && (await this.approve({ usd, counterparty: d.terms.seller, deal: d.terms, reason: verdict.reason }))))
        throw Object.assign(new Error("Needs owner approval: " + verdict.reason), { policy: verdict });
      const co = await this.http("POST", "/v1/checkouts", { pay_to: d.terms.pay_to, amount_usd: usd, ref: d.terms_hash });
      if (String(co.pay_to).toLowerCase() !== d.terms.pay_to.toLowerCase() || Number(co.amount_usd) !== usd) throw new Error("Checkout doesn't match the agreed terms; not paying.");
      entry.checkout_id = co.checkout_id; pol.changed(); // saved BEFORE paying, so it can be reconciled after a crash
      sent = true;
      const r = await this.http("POST", `/v1/checkouts/${co.checkout_id}/pay`, {}, { pay: true });
      const tx = r._settlement?.transaction;
      if (!tx) { const e = new Error("The payment request went through but no settlement came back. The money stays held; call reconcilePayment() to check whether it settled before paying again."); e.uncertain = true; throw e; }
      pol.settle(entry, { tx, checkout_id: co.checkout_id });
      await this.dealMsg(room, "paid", { deal_id, terms_hash: d.terms_hash, payment: { tx, from: r._settlement?.payer, checkout_id: co.checkout_id, network: d.terms.network } });
      return { tx, checkout_id: co.checkout_id };
    } catch (e) {
      if (entry.status === "pending") {
        // A server error response means the relay refused it: a failed request is never settled
        // (PROTOCOL.md §2). No response at all (timeout, dropped connection) or a missing
        // settlement is uncertain: keep the money held until reconciled.
        if (!sent || (e.status && !e.uncertain)) pol.release(entry, e.message.slice(0, 200));
        else pol.markUncertain(entry, { error: e.message.slice(0, 200) });
      }
      throw e;
    } finally { this.paying.delete(deal_id); }
  }
  // Settle the question for a payment that may or may not have gone through, by asking the
  // checkout. Paid -> recorded (and announced in the room if given); expired or still open after
  // its expiry -> released. Otherwise it stays held.
  async reconcilePayment(deal_id, room = null) {
    const pol = this.policy;
    const entry = pol.ledger.find((e) => e.deal_id === deal_id && (e.status === "uncertain" || e.status === "pending"));
    if (!entry) return { status: pol.attemptFor(deal_id)?.status || "none" };
    if (this.paying.has(deal_id)) return { status: "in_progress" };
    if (!entry.checkout_id) { pol.release(entry, "No payment request was sent."); return { status: "released" }; }
    const co = await this.http("GET", `/v1/checkouts/${entry.checkout_id}`);
    if (co.status === "paid" && co.tx) {
      pol.settle(entry, { tx: co.tx });
      if (room) { const d = await this.deal(room, deal_id); if (d.status === "agreed") await this.dealMsg(room, "paid", { deal_id, terms_hash: d.terms_hash, payment: { tx: co.tx, from: co.payer, checkout_id: co.checkout_id, network: d.terms.network } }); }
      return { status: "settled", tx: co.tx };
    }
    if (co.status === "expired" || (co.status === "open" && Date.parse(co.expires_at) < Date.now() - 5 * 60e3)) { pol.release(entry, `Checkout ${co.status}; nothing was paid.`); return { status: "released" }; }
    return { status: entry.status, checkout: co.status };
  }
  // Report an external payment (e.g. a direct USDC transfer) by tx hash; the seller verifies it on-chain.
  // from: the wallet you paid from (the seller checks the transfer came from it).
  async markPaid(room, deal_id, tx, from) {
    if (!/^0x[0-9a-fA-F]{40}$/.test(from || "")) throw new Error("markPaid needs the paying wallet address (from).");
    const d = await this.deal(room, deal_id);
    return this.dealMsg(room, "paid", { deal_id, terms_hash: d.terms_hash, payment: { tx, from, network: d.terms.network } });
  }
  // Seller: check the buyer's payment on-chain before delivering.
  async verifyPayment(room, deal_id) {
    const d = await this.deal(room, deal_id);
    if (!d.payment?.tx) return { ok: false, error: "No payment reported yet." };
    if (!/^0x[0-9a-fA-F]{40}$/.test(d.payment.from || "")) return { ok: false, error: "The buyer didn't say which wallet paid." };
    const prior = this.usedTx.get(String(d.payment.tx).toLowerCase());
    if (prior && prior !== deal_id) return { ok: false, error: "That payment was already used for another deal." };
    const qs = new URLSearchParams({ network: d.terms.network, tx: d.payment.tx, to: d.terms.pay_to, from: d.payment.from, min_usd: String(d.terms.price_usd) });
    try { return await this.http("GET", "/v1/verify/usdc?" + qs); } catch (e) { return e.body || { ok: false, error: e.message }; }
  }

  // ---- EXCHANGE + VERIFY DELIVERY -------------------------------------------------------------
  async deliver(room, deal_id, content) {
    const d = await this.deal(room, deal_id);
    if (d.status !== "paid" || d.terms.seller !== this.agentId) throw new Error(`Only the seller can deliver a paid deal (it is ${d.status}).`);
    await this.checkTermsForMe(d.terms); // money really goes to my address, on an allowed network
    const v = await this.verifyPayment(room, deal_id);
    if (!v.ok) throw new Error("Payment not verified on-chain yet: " + v.error);
    this.usedTx.set(String(d.payment.tx).toLowerCase(), deal_id);
    const text = typeof content === "string" ? content : JSON.stringify(content);
    return this.dealMsg(room, "deliver", { deal_id, delivery: { sha256: await sha256(text), bytes: text.length, content: text } });
  }
  receiptBody(d, outcome) {
    return { v: 1, deal_id: d.deal_id, terms_hash: d.terms_hash, amount_usd: d.terms.price_usd, network: d.terms.network,
      buyer: { agent_id: d.terms.buyer, sign_key: d.terms.buyer === this.agentId ? this.id.sign_key : this.peerKey(d.terms.buyer) },
      seller: { agent_id: d.terms.seller, sign_key: d.terms.seller === this.agentId ? this.id.sign_key : this.peerKey(d.terms.seller), pay_to: d.terms.pay_to },
      payment: { tx: d.payment.tx, from: d.payment.from }, delivery_hash: d.delivery.sha256, outcome };
  }
  peerKey(agentId) { for (const p of this.verifiedPeers.values()) if (p.agent_id === agentId) return p.sign_key; throw new Error("Peer key unknown"); }
  // Buyer: check the delivered content against its hash, then sign completed (or disputed).
  async confirm(room, deal_id, { outcome = "completed", reason } = {}) {
    const d = await this.deal(room, deal_id);
    if (d.status !== "delivered" || d.terms.buyer !== this.agentId) throw new Error(`Only the buyer can confirm a delivered deal (it is ${d.status}).`);
    if ((await sha256(d.delivery.content)) !== d.delivery.sha256) outcome = "disputed";
    const body = this.receiptBody(d, outcome);
    const signed = await signDoc(this.id, body);
    await this.dealMsg(room, "confirm", { deal_id, receipt: { ...body, sigs: { buyer: signed.sig } }, reason: reason ? String(reason).slice(0, 500) : undefined });
    return { outcome };
  }
  // Seller: countersign the buyer's receipt (completed deals need both signatures).
  async countersign(room, deal_id) {
    const d = await this.deal(room, deal_id);
    if (!d.receipt || d.terms.seller !== this.agentId) throw new Error("No receipt to countersign.");
    const { sigs, ...body } = d.receipt;
    if (canonical(body) !== canonical(this.receiptBody(d, body.outcome))) throw new Error("Receipt doesn't match the deal.");
    const signed = await signDoc(this.id, body);
    await this.dealMsg(room, "countersign", { deal_id, receipt_sig: signed.sig });
    return { ...body, sigs: { ...sigs, seller: signed.sig } };
  }
  // Either party: publish the signed receipt so both agents' track records count it.
  async submitReceipt(room, deal_id) {
    const d = await this.deal(room, deal_id);
    if (!d.receipt) throw new Error("No receipt yet.");
    return this.http("POST", "/v1/receipts", { receipt: d.receipt });
  }
}
