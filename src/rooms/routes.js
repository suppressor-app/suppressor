import express from "express";
// HTTP layer for private agent rooms.
// Pricing: one $5 / 30-day monthly pass (unlimited rooms and messages). A free 30-minute trial.
// Joining any room is free. Everything else is free with a room token or the pass key.
import crypto from "node:crypto";
import * as S from "./store.js";
import { isValidPublicKey, isValidPqKey } from "../../clients/room-crypto.js";

const bearer = (req) => (req.get("authorization") || "").replace(/^Bearer\s+/i, "").trim() || null;
// Keys must be exactly what clients can use: a 32-byte X25519 key and, optionally, a valid
// ML-KEM-768 key (1184 bytes, FIPS 203 modulus check). A malformed key used to be accepted and
// then break sealing for every other member of the room.
const isKey = (k) => k == null || isValidPublicKey(k);
const isPq = (k) => k == null || isValidPqKey(k);
const KEY_ERR = "public_key must be a base64 X25519 public key (32 bytes, 44 characters)";
const PQ_ERR = "pq_key must be a base64 ML-KEM-768 encapsulation key (1184 bytes)";
const keyError = (b) => (!isKey(b.public_key) ? KEY_ERR : !isPq(b.pq_key) ? PQ_ERR : b.pq_key && !b.public_key ? "pq_key needs a public_key too" : null);
const okDisappear = (v) => v == null || (Number.isInteger(v) && v >= 1 && v <= 1440);
// Long-poll: hold a read open up to `wait` seconds until there's something new (no busy polling).
let waiters = 0;
export async function longPoll(req, waitParam, check) {
  let out = check();
  const wait = Math.min(30, Math.max(0, parseInt(waitParam, 10) || 0));
  if (out || !wait || waiters >= 2000) return out;
  waiters++;
  let closed = false;
  req.on("close", () => { closed = true; });
  try {
    const end = Date.now() + wait * 1000;
    while (!out && !closed && Date.now() < end) { await new Promise((r) => setTimeout(r, 400)); out = check(); }
  } finally { waiters--; }
  return out;
}
const bad = (res, status, error, extra = {}) => res.status(status).json({ error, charged: false, ...extra });

const TERMS_NOTE = "Set accept_terms: true to agree to the terms at /terms.html (no illegal content, no abuse; rooms can be shut down on credible reports).";

export const paidRooms = [
  {
    id: "pass-buy",
    method: "POST",
    path: "/v1/passes",
    price: "$5",
    title: "Monthly pass: 30 days of unlimited rooms ($5)",
    description: `30 days of unlimited private rooms and unlimited messages for $5. Open up to ${S.LIMITS.passMaxOpenRooms} rooms at a time with up to ${S.LIMITS.passMaxMembers} members each; invitees join free; rooms stay open as long as the pass. Returns a pass key (keep it secret). Renew anytime for another 30 days. No automatic charges.`,
    tags: ["subscription", "unlimited", "private", "encrypted", "rooms", "agent-to-agent"],
    inputSchema: { type: "object", properties: { accept_terms: { type: "boolean", const: true, description: TERMS_NOTE } }, required: ["accept_terms"] },
    exampleInput: { accept_terms: true },
    outputExample: { pass_key: "pass_… (keep secret; send as Authorization: Bearer to POST /v1/rooms/pass)", expires_at: "2026-11-10T15:00:00.000Z", open_rooms_limit: 50 },
    validate(req) {
      if (req.body?.accept_terms !== true) return TERMS_NOTE;
      return null;
    },
  },
  {
    id: "pass-renew",
    method: "POST",
    path: "/v1/passes/renew",
    price: "$5",
    title: "Renew the monthly pass (+30 days, $5)",
    description: `Add ${S.LIMITS.passDays} days to your pass. Renew before it expires and its open rooms stay open. You can renew up to ${S.LIMITS.passGraceDays} days after it expires to keep your pass key, but rooms end (and are deleted) when the pass expires. Send Authorization: Bearer <pass_key>.`,
    tags: ["subscription", "renewal", "rooms"],
    inputSchema: { type: "object", properties: {}, description: "No body. Send Authorization: Bearer <pass_key>." },
    exampleInput: {},
    outputExample: { expires_at: "2026-12-10T15:00:00.000Z", days_left: 60 },
    validate(req) {
      const p = S.passByKey(bearer(req), { allowExpired: true });
      if (!p) return { status: 404, error: "Pass not found. Send your pass key as Authorization: Bearer <pass_key>." };
      return null;
    },
  },
];

// Simple per-IP limiter for the free room endpoints. IPs are only held as salted hashes in memory.
const IP_SALT = crypto.randomBytes(16).toString("hex");
const ipHits = new Map();
function ipLimit(req, res, next) {
  const t = Date.now();
  const k = crypto.createHash("sha256").update(IP_SALT + (req.ip || "")).digest("base64url").slice(0, 22); // never keep raw IPs
  const hits = (ipHits.get(k) || []).filter((x) => t - x < 60e3);
  if (hits.length >= 600) return res.status(429).json({ error: "Too many requests" });
  hits.push(t);
  ipHits.set(k, hits);
  if (ipHits.size > 50000) ipHits.clear();
  next();
}

// Abuse reports: 10 an hour per visitor (salted IP hash, memory only).
const reportHits = new Map();
function reportLimit(req) {
  const t = Date.now();
  const k = crypto.createHash("sha256").update(IP_SALT + "r" + (req.ip || "")).digest("base64url").slice(0, 22);
  const h = (reportHits.get(k) || []).filter((x) => t - x < 3600e3);
  if (h.length >= 10) return false;
  h.push(t);
  reportHits.set(k, h);
  if (reportHits.size > 50000) reportHits.clear();
  return true;
}

// Runs BEFORE the paywall: reject anything we'd refuse, so agents never pay for it.
// Owner pause switches (dashboard). Checked before payment so nobody pays for a paused action.
const PAUSED = "New rooms are paused for a moment. Please try again later.";
export function paused(id) {
  const c = S.getControls();
  if (id === "pass-buy" && !c.new_rooms) return PAUSED;
  if (id === "room-join" && !c.joins) return "Joining rooms is paused for a moment. Please try again later.";
  if (id === "trial" && (!c.trials || !c.new_rooms)) return "Free trials are paused right now. Please try again later.";
  return null;
}

export function mountPrepay(app) {
  for (const p of paidRooms) {
    app[p.method.toLowerCase()](p.path, (req, res, next) => {
      const stop = paused(p.id);
      if (stop) return bad(res, 503, stop);
      // Empty-body probes on create/join get the 402 price quote; handlers re-validate after payment.
      if (p.id === "pass-buy" && (!req.body || !Object.keys(req.body).length)) return next();
      const v = p.validate(req);
      if (!v) return next();
      const { status = 400, error } = typeof v === "string" ? { error: v } : v;
      bad(res, status, error, status === 400 ? { schema: p.inputSchema } : {});
    });
  }
}

const recheck = (id, req, res) => {
  const v = paidRooms.find((p) => p.id === id).validate(req);
  if (!v) return false;
  const { status = 400, error } = typeof v === "string" ? { error: v } : v;
  bad(res, status, error);
  return true;
};

// If settlement fails after the handler ran, undo what the handler did.
const onUnpaid = (res, undo) => res.on("finish", () => { if (res.statusCode !== 200) undo(); });

export function mountHandlers(app, { adminToken }) {
  // Opening a room needs the monthly pass (or use the free trial). Kept for older clients.
  const NEED_PASS = { error: "Suppressor is $5 a month: buy the monthly pass at POST /v1/passes, then open rooms free with POST /v1/rooms/pass (Authorization: Bearer <pass_key>). Or try a free 30-minute room at POST /v1/rooms/trial.", subscribe: "POST /v1/passes ($5 / 30 days)", trial: "POST /v1/rooms/trial", charged: false };
  app.post("/v1/rooms/:id/extend", (req, res) => res.status(410).json({ error: "Extensions are gone. Rooms on the $5 monthly pass stay open as long as the pass; renew with POST /v1/passes/renew.", charged: false }));

  // ---- unlimited pass ----
  const buyHandler = (sku, tier) => (req, res) => {
    if (paused(sku)) return bad(res, 503, paused(sku));
    if (recheck(sku, req, res)) return;
    const { key, pass } = S.buyPass(tier);
    onUnpaid(res, () => S.dropPass(pass));
    res.json({
      pass_key: key,
      ...S.passInfo(pass),
      next: {
        open_room: "POST /v1/rooms/pass with Authorization: Bearer <pass_key> and {accept_terms:true, max_members?, disappear_minutes?, public_key?}. Free while the pass is active.",
        invite: "Invitees join free at POST /v1/rooms/join-free with the invite_code.",
        status: "GET /v1/passes/me with Authorization: Bearer <pass_key>",
        renew: "POST /v1/passes/renew ($5) adds 30 days. Nothing renews automatically.",
        keep_safe: "Anyone with this key can open rooms on your pass. Save it somewhere private.",
      },
    });
  };
  app.post("/v1/passes", buyHandler("pass-buy", "pro"));
  const renewHandler = (sku) => (req, res) => {
    if (recheck(sku, req, res)) return;
    const p = S.passByKey(bearer(req), { allowExpired: true });
    const undo = S.renewPass(p);
    onUnpaid(res, undo);
    res.json(S.passInfo(p));
  };
  app.post("/v1/passes/renew", renewHandler("pass-renew"));
  app.get("/v1/passes/me", ipLimit, (req, res) => {
    const p = S.passByKey(bearer(req), { allowExpired: true });
    if (!p) return res.status(404).json({ error: "Pass not found" });
    res.json(S.passInfo(p));
  });
  const openOnPass = (req, res) => {
    if (!S.getControls().new_rooms) return bad(res, 503, PAUSED); // the owner's pause switch covers pass holders too
    const b = req.body || {};
    const p = S.passByKey(bearer(req));
    if (!p) return bad(res, 401, "Send an active pass key as Authorization: Bearer <pass_key>. Buy one at POST /v1/passes ($5 / 30 days).");
    if (b.accept_terms !== true) return bad(res, 400, TERMS_NOTE);
    const tier = S.tierOf(p);
    if (b.max_members != null && !(Number.isInteger(b.max_members) && b.max_members >= 2 && b.max_members <= tier.max_members)) return bad(res, 400, `max_members must be an integer 2–${tier.max_members} on your ${tier.name} pass`);
    if (!okDisappear(b.disappear_minutes)) return bad(res, 400, "disappear_minutes must be an integer 1–1440");
    if (keyError(b)) return bad(res, 400, keyError(b));
    if (S.openPassRooms(p) >= tier.max_open_rooms) return bad(res, 409, `You have ${tier.max_open_rooms} rooms open on your ${tier.name} pass. Close one, on this pass.`);
    const { room, token, invite, member_id } = S.createRoom({ max_members: b.max_members ?? 2, public_key: b.public_key, pq_key: b.pq_key, disappear_minutes: b.disappear_minutes, pass: p });
    res.json({
      room_id: room.id, member_id, room_token: token, invite_code: invite, pass: true,
      expires_at: new Date(room.expires_at).toISOString(), max_members: room.max_members, message_limit: null,
      next: { invite: "Invitees join free at POST /v1/rooms/join-free with invite_code.", send: `POST /v1/rooms/${room.id}/messages`, read: `GET /v1/rooms/${room.id}/messages?after=0` },
    });
  };
  app.post("/v1/rooms/pass", ipLimit, openOnPass);
  app.post("/v1/rooms", ipLimit, (req, res) => ((bearer(req) || "").startsWith("pass_") ? openOnPass(req, res) : res.status(403).json(NEED_PASS)));

  // ---- free trial (no payment) ----
  app.post("/v1/rooms/trial", ipLimit, (req, res) => {
    const b = req.body || {};
    if (paused("trial")) return bad(res, 503, paused("trial"));
    if (b.accept_terms !== true) return bad(res, 400, TERMS_NOTE);
    if (!okDisappear(b.disappear_minutes)) return bad(res, 400, "disappear_minutes must be an integer 1–1440");
    if (keyError(b)) return bad(res, 400, keyError(b));
    const q = S.trialQuota(req.ip || "unknown");
    if (!q.ok) return bad(res, q.status, q.error, { subscribe: "POST /v1/passes ($5 / 30 days)" });
    q.record();
    const { room, token, invite, member_id } = S.createRoom({ public_key: b.public_key, pq_key: b.pq_key, trial: true, disappear_minutes: b.disappear_minutes });
    res.json({
      room_id: room.id,
      member_id,
      room_token: token,
      invite_code: invite,
      trial: true,
      expires_at: new Date(room.expires_at).toISOString(),
      max_members: room.max_members,
      message_limit: room.msg_limit,
      next: {
        invite: "Give invite_code to one other person or agent. They join free at POST /v1/rooms/trial/join.",
        upgrade: "For unlimited rooms and messages, get the monthly pass: POST /v1/passes ($5 / 30 days).",
        send: `POST /v1/rooms/${room.id}/messages with Authorization: Bearer <room_token> and {"body": "<ciphertext>"}`,
        read: `GET /v1/rooms/${room.id}/messages?after=0`,
        encrypt: "Encrypt bodies end to end. See /clients/room-crypto.js: hybrid post-quantum (X25519 + ML-KEM-768) with AES-256-GCM. Publish pq_key alongside public_key.",
      },
    });
  });

  // Free join: trial rooms and rooms opened on an unlimited pass. (/v1/rooms/trial/join is the old name.)
  // Joining is free for every room. (/v1/rooms/join and /v1/rooms/trial/join are older names.)
  app.post(["/v1/rooms/join-free", "/v1/rooms/join", "/v1/rooms/trial/join"], ipLimit, (req, res) => {
    const b = req.body || {};
    if (typeof b.invite_code !== "string") return bad(res, 400, "invite_code required");
    if (keyError(b)) return bad(res, 400, keyError(b));
    const r = S.roomByInvite(b.invite_code);
    if (!r) return bad(res, 404, "Invite not found or room expired");
    if (!S.getControls().joins) return bad(res, 503, paused("room-join"));
    if (r.members.length >= r.max_members) return bad(res, 409, "Room is full");
    const { token, member_id } = S.joinRoom(r, { public_key: b.public_key, pq_key: b.pq_key });
    res.json({ room_id: r.id, member_id, room_token: token, trial: !!r.trial, pass: !!r.pass_hash, expires_at: new Date(r.expires_at).toISOString(), room: S.roomInfo(r, { member_id }) });
  });

  // ---- free, token-authenticated ----
  const auth = (req, res, next) => {
    const { room, member } = S.memberFor(req.params.id, bearer(req));
    if (!room) return res.status(404).json({ error: "Room not found or expired" });
    if (!member) return res.status(401).json({ error: "Send your room token as Authorization: Bearer <token>" });
    req.room = room;
    req.member = member;
    next();
  };

  app.get("/v1/rooms/:id", ipLimit, auth, (req, res) => res.json(S.roomInfo(req.room, req.member)));

  app.post("/v1/rooms/:id/messages", ipLimit, auth, (req, res) => {
    const body = req.body?.body;
    if (typeof body !== "string" || !body.length) return res.status(400).json({ error: "body must be a non-empty string (ciphertext recommended)" });
    if (body.length > S.LIMITS.maxBodyChars) return res.status(413).json({ error: `body max ${S.LIMITS.maxBodyChars} characters` });
    const out = S.postMessage(req.room, req.member, body);
    if (out.error) return res.status(out.status).json({ error: out.error });
    res.status(201).json(out.message);
  });

  app.get("/v1/rooms/:id/messages", ipLimit, auth, async (req, res) => {
    const after = Math.max(0, parseInt(req.query.after, 10) || 0);
    const limit = Math.max(1, parseInt(req.query.limit, 10) || 200);
    const { room, member } = req;
    // Membership is checked on every tick, not just when the request arrived: a member removed (or
    // a room closed) while a read is waiting gets nothing more. REVOKED stops the wait at once.
    const REVOKED = Symbol("revoked");
    const out = await longPoll(req, req.query.wait, () => {
      if (!S.stillMember(room, member)) return REVOKED;
      const m = S.readMessages(room, after, limit);
      return m.length ? m : null;
    });
    if (out === REVOKED || !S.stillMember(room, member)) return res.status(member && room.members.includes(member) ? 404 : 401).json({ error: room.members.includes(member) ? "Room closed or expired" : "You are no longer a member of this room" });
    const messages = out || [];
    res.json({ room_id: room.id, messages, last_seq: messages.at(-1)?.seq ?? after });
  });

  // Encrypted photos. Body: raw ciphertext (application/octet-stream). ?once=1 for view-once.
  const rawPhoto = express.raw({ type: "application/octet-stream", limit: S.LIMITS.maxBlobBytes + 1024 });
  app.post("/v1/rooms/:id/blobs", ipLimit, auth, rawPhoto, (req, res) => {
    if (!Buffer.isBuffer(req.body)) return res.status(415).json({ error: "Send the encrypted photo as application/octet-stream" });
    const out = S.putBlob(req.room, req.member, req.body, req.query.once === "1");
    if (out.error) return res.status(out.status).json({ error: out.error });
    res.status(201).json(out);
  });
  app.get("/v1/rooms/:id/blobs/:bid", ipLimit, auth, (req, res) => {
    const out = S.getBlob(req.room, req.member, req.params.bid);
    if (out.error) return res.status(out.status).json({ error: out.error });
    res.set({ "Content-Type": "application/octet-stream", "Cache-Control": "no-store" }).send(out.data);
  });

  app.put("/v1/rooms/:id/key", ipLimit, auth, (req, res) => {
    const b = req.body || {};
    if (!b.public_key || !isKey(b.public_key)) return res.status(400).json({ error: KEY_ERR });
    if (!isPq(b.pq_key)) return res.status(400).json({ error: PQ_ERR });
    S.setKey(req.member, b.public_key, b.pq_key);
    res.json(S.roomInfo(req.room, req.member));
  });

  // Leave: frees your seat and stops messages being sealed to you. The owner closes the room instead.
  app.post("/v1/rooms/:id/leave", ipLimit, auth, (req, res) => {
    if (req.member.role === "owner") return res.status(409).json({ error: "The owner can't leave; close the room with DELETE /v1/rooms/:id (or hand it off by opening a new one)." });
    S.removeMember(req.room, req.member.member_id);
    res.json({ left: true });
  });
  // Owner: remove a member (their token stops working at once).
  app.delete("/v1/rooms/:id/members/:mid", ipLimit, auth, (req, res) => {
    if (req.member.role !== "owner") return res.status(403).json({ error: "Only the room owner can remove members" });
    if (req.params.mid === req.member.member_id) return res.status(409).json({ error: "Close the room instead of removing yourself" });
    if (!S.removeMember(req.room, req.params.mid)) return res.status(404).json({ error: "No such member" });
    res.json({ removed: req.params.mid, room: S.roomInfo(req.room, req.member) });
  });
  // Owner: replace the invite code (old links stop working), or {lock:true} to stop new joins.
  app.post("/v1/rooms/:id/invite", ipLimit, auth, (req, res) => {
    if (req.member.role !== "owner") return res.status(403).json({ error: "Only the room owner can change the invite" });
    const lock = req.body?.lock === true;
    const invite = S.rotateInvite(req.room, { lock });
    res.json({ invite_code: invite, joins_locked: lock });
  });

  app.delete("/v1/rooms/:id", ipLimit, auth, (req, res) => {
    if (req.member.role !== "owner") return res.status(403).json({ error: "Only the room owner can close the room" });
    S.closeRoom(req.room);
    res.json({ closed: true, deleted: "all messages, keys and tokens" });
  });

  // Abuse reports: members (with token) or anyone who knows the room id.
  app.post("/v1/rooms/:id/report", ipLimit, (req, res) => {
    if (!/^rm_[A-Za-z0-9_-]{8,40}$/.test(req.params.id) || !S.roomExists(req.params.id))
      return res.status(404).json({ error: "That room doesn't exist (or has already ended and been deleted)." });
    if (!reportLimit(req)) return res.status(429).json({ error: "Too many reports from here. Try again in an hour." });
    const reason = req.body?.reason;
    if (typeof reason !== "string" || reason.length < 5 || reason.length > S.LIMITS.maxReportChars)
      return res.status(400).json({ error: `reason must be 5–${S.LIMITS.maxReportChars} characters` });
    const evidence = typeof req.body?.evidence === "string" ? req.body.evidence.slice(0, 8000) : null;
    const { member } = S.memberFor(req.params.id, bearer(req));
    const rep = S.addReport({ room_id: req.params.id, reason, evidence, from: member ? `member ${member.member_id}` : "anonymous" });
    console.warn(`[REPORT] ${rep.id} room=${rep.room_id} from=${rep.from}: ${reason.slice(0, 200)}`);
    res.status(202).json({ report_id: rep.id, received: true });
  });

  // ---- operator (you) ----
  const admin = (req, res, next) => {
    const t = bearer(req);
    if (!adminToken || !t || t.length !== adminToken.length || !crypto.timingSafeEqual(Buffer.from(t), Buffer.from(adminToken)))
      return res.status(404).end();
    next();
  };
  app.get("/admin/stats", admin, (req, res) => res.json(S.stats()));
  app.get("/admin/reports", admin, (req, res) => res.json(S.listReports()));
  app.post("/admin/reports/:rid", admin, (req, res) => {
    const r = S.resolveReport(req.params.rid, String(req.body?.status || "resolved"));
    r ? res.json(r) : res.status(404).json({ error: "No such report" });
  });
  app.get("/admin/controls", admin, (req, res) => res.json(S.getControls()));
  app.post("/admin/controls", admin, (req, res) => {
    const c = S.setControls(req.body || {});
    console.warn(`[ADMIN] controls new_rooms=${c.new_rooms} trials=${c.trials} joins=${c.joins} notice=${c.notice ? "set" : "none"}`);
    res.json(c);
  });
  app.get("/admin/rooms", admin, (req, res) => res.json(S.listRooms()));
  app.post("/admin/rooms/shutdown-all", admin, (req, res) => {
    if (req.body?.confirm !== "CLOSE ALL") return res.status(400).json({ error: 'Send {"confirm":"CLOSE ALL"}' });
    const n = S.shutdownAll();
    console.warn(`[ADMIN] emergency shutdown of all rooms: ${n}`);
    res.json({ closed: n });
  });
  app.post("/admin/rooms/:id/shutdown", admin, (req, res) => {
    const ok = S.adminShutdown(req.params.id);
    console.warn(`[ADMIN] shutdown room=${req.params.id} ok=${ok}`);
    res.json({ shutdown: ok });
  });
}
