import assert from "node:assert/strict";

let n = 0;
const t = (name, fn) => { fn(); n++; console.log("ok", name); };

// Offline checks of Suppressor: rooms, encryption, privacy, pass, photos, agent commerce. Run: npm test
const S = await import("../src/rooms/store.js");

t("rooms: tokens stored only as hashes; join, full, auth", () => {
  const { room, token, invite } = S.createRoom({ max_members: 2 });
  assert.ok(!JSON.stringify(room).includes(token));
  assert.ok(!JSON.stringify(room).includes(invite));
  assert.equal(S.roomByInvite(invite).id, room.id);
  const j = S.joinRoom(room, {});
  assert.equal(room.members.length, 2);
  assert.ok(S.memberFor(room.id, j.token).member);
  assert.equal(S.memberFor(room.id, "tok_wrong").member, null);
  S.closeRoom(room);
  assert.equal(S.roomByInvite(invite), null);
});

t("rooms: message limit and per-member rate limit", () => {
  const { room, token } = S.createRoom({});
  const me = S.memberFor(room.id, token).member;
  room.msg_limit = 3;
  for (let i = 0; i < 3; i++) assert.ok(S.postMessage(room, me, "x").message);
  assert.equal(S.postMessage(room, me, "x").status, 409);
  room.msg_limit = 1000;
  let limited = false;
  for (let i = 0; i < 130; i++) if (S.postMessage(room, me, "x").status === 429) limited = true;
  assert.ok(limited);
  assert.equal(S.readMessages(room, 2, 1)[0].seq, 3);
  S.closeRoom(room);
});

t("rooms: extend respects lifetime cap; expiry deletes everything", () => {
  const { room, token } = S.createRoom({});
  const before = room.expires_at;
  S.extendRoom(room);
  assert.ok(room.expires_at > before && room.msg_limit === 2000);
  for (let i = 0; i < 40; i++) S.extendRoom(room);
  assert.ok(room.expires_at <= room.created_at + 30 * 86400e3);
  assert.equal(S.canExtend(room), false);
  room.expires_at = Date.now() - 1;
  S.sweep();
  assert.equal(S.memberFor(room.id, token).room, null);
});

t("rooms: free trial limits, quota, and paid upgrade", () => {
  const { room, invite } = S.createRoom({ trial: true, max_members: 8 });
  assert.equal(room.trial, true);
  assert.ok(invite.startsWith("trial_"));
  assert.equal(room.max_members, S.LIMITS.trialMembers);
  assert.equal(room.msg_limit, S.LIMITS.trialMessages);
  assert.ok(room.expires_at - Date.now() <= S.LIMITS.trialMinutes * 60e3 + 1000);
  S.extendRoom(room);
  assert.equal(room.trial, false);
  assert.ok(room.msg_limit > S.LIMITS.trialMessages);
  S.closeRoom(room);
  const ip = "203.0.113." + Math.floor(Math.random() * 200);
  for (let i = 0; i < S.LIMITS.trialPerIpPerDay; i++) { const q = S.trialQuota(ip); assert.ok(q.ok); q.record(); }
  assert.equal(S.trialQuota(ip).status, 429);
  assert.ok(S.trialQuota(ip + "9").ok);
});

t("rooms: end-to-end encryption round trip", async () => {});
{
  const C = await import("../clients/room-crypto.js");
  const a = await C.generateIdentity(), b = await C.generateIdentity(), eve = await C.generateIdentity();
  const members = [{ member_id: "A", public_key: a.publicKey }, { member_id: "B", public_key: b.publicKey }];
  const sealed = await C.seal("rm_1", a, members, "secret price 68");
  assert.ok(!sealed.includes("secret"));
  assert.equal(await C.open("rm_1", b, "B", sealed), "secret price 68");
  assert.equal(await C.open("rm_1", a, "A", sealed), "secret price 68"); // sender reads own history
  await assert.rejects(C.seal("rm_1", a, [members[0]], "alone")); // nobody else to send to
  await assert.rejects(C.open("rm_1", eve, "B", sealed)); // wrong key can't decrypt
  await assert.rejects(C.open("rm_2", b, "B", sealed)); // bound to the room id
  // length hiding: short and medium messages produce the same envelope size
  const s1 = await C.seal("rm_1", a, members, "ok"), s2 = await C.seal("rm_1", a, members, "x".repeat(200));
  assert.equal(s1.length, s2.length);
  assert.equal(await C.open("rm_1", b, "B", s2), "x".repeat(200));
  assert.equal(C.padBucket(10), 256); assert.equal(C.padBucket(300), 1024); assert.equal(C.padBucket(5000), 8192);
  console.log("ok privacy: padding hides message length");
  n++;
}

t("privacy: no labels stored, minute timestamps, disappearing messages", () => {
  const { room } = S.createRoom({ max_members: 2, public_key: "k", disappear_minutes: 5, label: "secret name" });
  assert.ok(!JSON.stringify(room).includes("secret name"));
  assert.equal(S.roomInfo(room).disappear_minutes, 5);
  const m = room.members[0];
  const r = S.postMessage(room, m, "sealed");
  assert.equal(new Date(r.message.at).getSeconds(), 0);
  room.messages[0].posted -= 6 * 60e3; // pretend it was sent 6 minutes ago
  assert.equal(S.readMessages(room).length, 0);
  const plain = S.createRoom({ max_members: 2 }).room;
  assert.equal(S.roomInfo(plain).disappear_minutes, null);
});

t("photos: memory-only, view once deletes after every recipient opens", () => {
  const { room } = S.createRoom({ max_members: 3, public_key: "k1" });
  const owner = room.members[0];
  S.joinRoom(room, { public_key: "k2" }); S.joinRoom(room, { public_key: "k3" });
  const [, b, c] = room.members;
  const up = S.putBlob(room, owner, Buffer.alloc(1000, 7), true);
  assert.ok(up.blob_id);
  assert.equal(S.getBlob(room, owner, up.blob_id).status, 403); // sender can't reopen
  assert.ok(S.getBlob(room, b, up.blob_id).data);
  assert.equal(S.getBlob(room, b, up.blob_id).status, 410); // once only
  assert.ok(S.getBlob(room, c, up.blob_id).data);
  assert.equal(S.blobStats().photos_held, 0); // gone after everyone opened
  const keep = S.putBlob(room, owner, Buffer.alloc(10, 1), false);
  assert.ok(S.getBlob(room, b, keep.blob_id).data && S.getBlob(room, b, keep.blob_id).data);
  assert.equal(S.putBlob(room, owner, Buffer.alloc(S.LIMITS.maxBlobBytes + 1)).status, 413);
  S.closeRoom(room);
  assert.equal(S.blobStats().photos_held, 0); // closing the room deletes its photos
});

t("unlimited pass: free rooms, 25 members, rolling storage, renew carries rooms", () => {
  const { key, pass } = S.buyPass();
  assert.ok(key.startsWith("pass_") && !JSON.stringify(pass).includes(key)); // only the hash is kept
  assert.equal(S.passByKey(key).hash, pass.hash);
  assert.equal(S.passByKey("pass_wrong"), null);
  const { room, invite } = S.createRoom({ max_members: 25, public_key: "k", pass });
  assert.ok(invite.startsWith("free_") && S.isFreeJoin(room) && !S.canExtend(room));
  assert.equal(room.expires_at, pass.expires_at);
  assert.equal(S.openPassRooms(pass), 1);
  const m = room.members[0];
  const big = "x".repeat(600000);
  for (let i = 0; i < 100; i++) assert.ok(!S.postMessage(room, m, big).error); // 60 MB through a 50 MB room
  assert.ok(room.bytes <= S.LIMITS.passRoomBytes); // oldest rolled off; never "full"
  const before = pass.expires_at;
  const undo = S.renewPass(pass);
  assert.ok(pass.expires_at >= before + 29 * 86400e3 && room.expires_at === pass.expires_at);
  undo();
  assert.equal(pass.expires_at, before);
  assert.equal(room.expires_at, before);
  S.closeRoom(room);
});

t("pay-per-room rooms cap at 7 days", () => {
  const { room } = S.createRoom({ max_members: 2 });
  let n = 0; while (S.canExtend(room) && n < 50) { S.extendRoom(room); n++; }
  assert.ok(room.expires_at - room.created_at <= 7 * 86400e3 + 1000 && n <= 7);
  S.closeRoom(room);
});

{
  const I = await import("../clients/agent-identity.js");
  const SDK = await import("../clients/suppressor-sdk.js");
  const AS = await import("../src/agents/store.js");
  const a = await I.generateAgentIdentity(), b = await I.generateAgentIdentity();
  // identity + signed docs
  const doc = await I.signDoc(a, { hello: "world", n: 1 }, "hello");
  assert.ok(await I.verifyDoc(doc, a.sign_key, "hello"));
  assert.ok(!(await I.verifyDoc({ ...doc, n: 2 }, a.sign_key, "hello")), "tampered doc must fail");
  assert.ok(!(await I.verifyDoc(doc, b.sign_key, "hello")), "wrong key must fail");
  assert.equal(await I.agentIdFor(a.sign_key), a.agent_id);
  // signed requests: bound to method+path+body; nonce can't be reused; stale time refused
  const h = I.parseAgentHeader(await I.signRequest(a, "GET", "/v1/agents/x/inbox", ""));
  assert.ok(await I.verifyRequest(h, a.sign_key, "GET", "/v1/agents/x/inbox", ""));
  assert.ok(!(await I.verifyRequest(h, a.sign_key, "GET", "/v1/agents/y/inbox", "")));
  assert.equal(AS.useNonce(h.nonce, h.ts), null);
  assert.match(AS.useNonce(h.nonce, h.ts), /Replayed/);
  assert.match(AS.useNonce("freshnonce123", Date.now() - 10 * 60e3), /time/);
  // sealed knocks: only the addressed agent can open
  const sealed = await I.sealTo(a.box_key, a.agent_id, "secret invite");
  assert.equal(await I.openSealed(a, sealed), "secret invite");
  await assert.rejects(I.openSealed(b, sealed));
  console.log("ok agents: signatures, request replay protection, sealed knocks"); n++;

  // directory: valid card accepted; forged agent_id or bad signature caught; search filters
  const agentA = await SDK.SuppressorAgent.create({ baseUrl: "http://x", identity: a });
  const card = await agentA.makeCard({ name: "Research A", services: [{ id: "brief", title: "Market brief", category: "research", price: { model: "fixed", usd: 2 } }], payment: { network: "eip155:8453", asset: "USDC", pay_to: "0x" + "1".repeat(40) } });
  assert.equal(AS.validateCard(card), null);
  assert.ok(await I.verifyDoc(card, card.sign_key, "card"));
  const forged = { ...card, agent_id: b.agent_id };
  assert.notEqual(await I.agentIdFor(forged.sign_key), forged.agent_id, "agent_id can't be claimed with someone else's key");
  assert.ok(!(await SDK.SuppressorAgent.verifyListing({ agent_id: card.agent_id, card: { ...card, name: "Evil" } })));
  assert.match(AS.validateCard({ ...card, services: [{ id: "x", title: "t", price: { model: "fixed", usd: -1 } }] }), /price/);
  assert.match(AS.validateCard({ ...card, endpoints: { http: "javascript:alert(1)" } }), /https/);
  AS.putCard(card);
  assert.equal(AS.search({ q: "market brief" }).length >= 1, true);
  assert.equal(AS.search({ q: "market", max_usd: 1 }).filter((l) => l.agent_id === a.agent_id).length, 0);
  assert.equal(AS.putCard(card).status, 409, "same card can't be replayed");
  AS.addKnock(a.agent_id, "k1"); assert.equal(AS.takeKnocks(a.agent_id).length, 1); assert.equal(AS.takeKnocks(a.agent_id).length, 0, "knocks are read once");
  AS.removeCard(a.agent_id);
  console.log("ok agents: directory validation, anti-forgery, search filters, read-once inbox"); n++;

  // negotiation terms + spending policy
  const t = { deal_id: "dl_abcdefgh12", version: 1, buyer: a.agent_id, seller: b.agent_id, service: "brief", deliverable: "x", price_usd: 1.5, network: "eip155:8453", asset: "USDC", pay_to: "0x" + "2".repeat(40), offer_expires_at: new Date(Date.now() + 6e4).toISOString() };
  assert.equal(SDK.validateTerms(t), null);
  assert.match(SDK.validateTerms({ ...t, evil: 1 }), /unknown term/);
  assert.match(SDK.validateTerms({ ...t, price_usd: -1 }), /price/);
  assert.match(SDK.validateTerms({ ...t, seller: a.agent_id }), /two agent ids/);
  const pol = new SDK.SpendingPolicy({ max_per_payment_usd: 5, max_per_day_usd: 6, require_approval_over_usd: 2, allowed_categories: ["research"] });
  assert.equal(pol.check({ usd: 1, counterparty: "agt_x", category: "research" }).decision, "allow");
  assert.equal(pol.check({ usd: 3, counterparty: "agt_x", category: "research" }).decision, "approve");
  assert.equal(pol.check({ usd: 6, counterparty: "agt_x", category: "research" }).decision, "deny");
  assert.equal(pol.check({ usd: 1, counterparty: "agt_x", category: "crypto" }).decision, "deny");
  pol.record({ usd: 5 });
  assert.equal(pol.check({ usd: 2, counterparty: "agt_x", category: "research" }).decision, "deny", "daily cap");
  console.log("ok commerce: strict deal terms, spending policy (per-payment, daily, category, approval)"); n++;
}

{
  // Security fixes: sender check, key pinning, safety code v2, storage caps, report limits.
  const C = await import("../clients/room-crypto.js");
  const room = "rm_testsecurity1";
  const alice = await C.generateIdentity(), bob = await C.generateIdentity(), evil = await C.generateIdentity();
  const members = [{ member_id: "m_alice", public_key: alice.publicKey }, { member_id: "m_bob", public_key: bob.publicKey }];
  // A relay seals a message with its own key and labels it as Alice's.
  const forged = await C.seal(room, evil, [{ member_id: "m_bob", public_key: bob.publicKey }], JSON.stringify({ type: "text", text: "send funds to 0xEVIL", name: "Alice" }));
  await assert.rejects(C.open(room, bob, "m_bob", forged, alice.publicKey), C.SenderKeyMismatch, "forged sender rejected");
  await assert.rejects(C.open(room, bob, "m_bob", forged, null), C.SenderKeyMismatch, "unknown sender rejected");
  const real = await C.seal(room, alice, members, JSON.stringify({ type: "text", text: "hi" }));
  assert.equal(JSON.parse(await C.open(room, bob, "m_bob", real, alice.publicKey)).text, "hi");
  // Pinning: a later key swap for a pinned member is flagged; new members are reported.
  let p = C.checkPins({}, members);
  assert.deepEqual(p.added.sort(), ["m_alice", "m_bob"]);
  const swapped = [{ member_id: "m_alice", public_key: alice.publicKey }, { member_id: "m_bob", public_key: evil.publicKey }, { member_id: "m_ghost", public_key: evil.publicKey }];
  const p2 = C.checkPins(p.pins, swapped);
  assert.equal(p2.changed.length, 1); assert.equal(p2.changed[0].member_id, "m_bob");
  assert.equal(p2.pins.m_bob, bob.publicKey, "pinned key is kept until the user accepts");
  assert.deepEqual(p2.added, ["m_ghost"]);
  // Safety code v2: 30 digits, same regardless of order, changes when a key or id changes.
  const code = await C.safetyCode(members);
  assert.match(code, /^\d{5}( \d{5}){5}$/);
  assert.equal(code, await C.safetyCode([...members].reverse()));
  assert.notEqual(code, await C.safetyCode([members[0], { member_id: "m_bob", public_key: evil.publicKey }]));
  assert.notEqual(code, await C.safetyCode([{ member_id: "m_bob", public_key: alice.publicKey }, { member_id: "m_alice", public_key: bob.publicKey }]), "relabeling keys changes the code");

  // Storage: whole-server cap and per-pass cap.
  const save = { ...S.LIMITS };
  S.LIMITS.maxTotalMessageBytes = S.storedBytes() + 5000;
  const { room: r1, token: t1 } = S.createRoom({});
  const me1 = S.memberFor(r1.id, t1).member;
  assert.ok(S.postMessage(r1, me1, "x".repeat(3000)).message);
  assert.equal(S.postMessage(r1, me1, "x".repeat(3000)).status, 503, "server-wide cap");
  S.closeRoom(r1); S.sweep();
  S.LIMITS.maxTotalMessageBytes = save.maxTotalMessageBytes;
  const { pass } = S.buyPass();
  S.LIMITS.passTotalBytes = 4000; S.LIMITS.passRoomBytes = 3000;
  const a = S.createRoom({ pass }), b = S.createRoom({ pass });
  const ma = S.memberFor(a.room.id, a.token).member, mb = S.memberFor(b.room.id, b.token).member;
  assert.ok(S.postMessage(a.room, ma, "y".repeat(2500)).message);
  assert.ok(S.postMessage(a.room, ma, "y".repeat(2500)).message, "per-room roll-off keeps pass rooms usable");
  assert.equal(S.postMessage(b.room, mb, "z".repeat(2000)).status, 409, "per-pass cap across rooms");
  Object.assign(S.LIMITS, save);
  S.closeRoom(a.room); S.closeRoom(b.room); S.sweep();

  // Reports: bounded per room and overall.
  const { room: r2 } = S.createRoom({});
  assert.equal(S.roomExists(r2.id), true); assert.equal(S.roomExists("rm_nope"), false);
  const before = S.listReports().length;
  for (let i = 0; i < 50; i++) S.addReport({ room_id: r2.id, reason: "spam report " + i });
  assert.equal(S.listReports().length - before, S.LIMITS.maxOpenReportsPerRoom, "open reports per room capped");
  S.closeRoom(r2);
  console.log("ok security: forged sender rejected, key swaps flagged, 30-digit code, storage and report caps"); n++;
}

{
  // Agent deal safety (SDK): seller refuses wrong pay_to / network, one payment can't pay two deals, no double pay.
  const { SuppressorAgent, SpendingPolicy } = await import("../clients/suppressor-sdk.js");
  const seller = await SuppressorAgent.create({ baseUrl: "http://localhost:1", payTo: "0x" + "aa".repeat(20) });
  const terms = { deal_id: "dl_abcdefgh", version: 1, buyer: "agt_B", seller: seller.agentId, service: "s", deliverable: "d", price_usd: 1, network: "eip155:8453", asset: "USDC", pay_to: "0x" + "aa".repeat(20), offer_expires_at: new Date(Date.now() + 3600e3).toISOString() };
  await seller.checkTermsForMe(terms);
  await assert.rejects(seller.checkTermsForMe({ ...terms, pay_to: "0x" + "bb".repeat(20) }), /pay_to/, "seller refuses buyer-chosen pay_to");
  await assert.rejects(seller.checkTermsForMe({ ...terms, network: "eip155:84532" }), /only deals on/, "seller refuses testnet terms");
  // one payment tx can't be accepted for two deals
  seller.usedTx.set("0x" + "cc".repeat(32), "dl_other");
  seller.deal = async () => ({ deal_id: "dl_abcdefgh", terms, payment: { tx: "0x" + "cc".repeat(32), from: "0x" + "dd".repeat(20) } });
  const v = await seller.verifyPayment({}, "dl_abcdefgh");
  assert.equal(v.ok, false); assert.match(v.error, /another deal/);
  seller.deal = async () => ({ deal_id: "dl_abcdefgh", terms, payment: { tx: "0x" + "ee".repeat(32) } });
  assert.match((await seller.verifyPayment({}, "dl_abcdefgh")).error, /which wallet/, "payer required");
  await assert.rejects(seller.markPaid({}, "dl_abcdefgh", "0x" + "ee".repeat(32)), /paying wallet/);
  // buyer: paying the same deal twice is refused
  const buyer = await SuppressorAgent.create({ baseUrl: "http://localhost:1", policy: new SpendingPolicy({}, [{ at: new Date().toISOString(), usd: 1, to_agent: "agt_S", deal_id: "dl_abcdefgh" }]) });
  buyer.deal = async () => ({ deal_id: "dl_abcdefgh", status: "agreed", terms: { ...terms, buyer: buyer.agentId } });
  await assert.rejects(buyer.pay({}, "dl_abcdefgh"), /already paid/);
  console.log("ok agent deals: seller checks pay_to and network, payer bound, no payment reuse, no double pay"); n++;
}

{
  // Abuse cases (negotiation): three agents in one in-memory relay room. Each attack is a validly
  // signed message the SDK must refuse to count. The relay stores ciphertext, like the real one.
  const { SuppressorAgent } = await import("../clients/suppressor-sdk.js");
  const { signDoc, roomIdentity } = await import("../clients/agent-identity.js");
  const relay = { members: [], msgs: [] };
  const relayHttp = (member_id) => async (method, path, body) => {
    if (method === "GET" && /^\/v1\/rooms\/[^/]+$/.test(path)) return { members: relay.members };
    if (method === "POST" && path.endsWith("/messages")) { relay.msgs.push({ seq: relay.msgs.length + 1, from: member_id, at: new Date().toISOString(), body: body.body }); return {}; }
    if (method === "GET" && path.includes("/messages")) { const after = Number(/after=(\d+)/.exec(path)[1]); return { messages: relay.msgs.filter((m) => m.seq > after), last_seq: relay.msgs.length }; }
    throw Object.assign(new Error("not found"), { status: 404 });
  };
  const PAY_TO = "0x" + "ab".repeat(20);
  const join = async (member_id, opts = {}) => {
    const ag = await SuppressorAgent.create({ baseUrl: "http://relay", ...opts });
    ag.http = relayHttp(member_id);
    const room = { room_id: "rm_abuse", member_id, token: member_id, last: 0, me: roomIdentity(ag.id) };
    relay.members.push({ member_id, public_key: room.me.publicKey });
    return { ag, room };
  };
  const B = await join("m_buyer"), Sl = await join("m_seller", { payTo: PAY_TO }), M = await join("m_mallory");
  for (const x of [B, Sl, M]) await x.ag.hello(x.room);
  const offer = (extra = {}) => B.ag.propose(B.room, { buyer: B.ag.agentId, seller: Sl.ag.agentId, service: "brief", deliverable: "1-page brief", price_usd: 1, pay_to: PAY_TO, ...extra });
  const status = async (id) => (await B.ag.deal(B.room, id)).status;

  // a stranger in the room can't accept, and can't speak for the seller
  const t1 = await offer();
  await M.ag.dealMsg(M.room, "accept", { deal_id: t1.deal_id, terms_hash: (await B.ag.deal(B.room, t1.deal_id)).terms_hash });
  await M.ag.post(M.room, await signDoc(M.ag.id, { type: "deal", kind: "accept", agent_id: Sl.ag.agentId, ts: new Date().toISOString(), deal_id: t1.deal_id, terms_hash: (await B.ag.deal(B.room, t1.deal_id)).terms_hash }, "deal"));
  assert.equal(await status(t1.deal_id), "proposed", "accept from a non-party or an impostor doesn't count");
  // an accept of stale terms doesn't count
  const stale = (await B.ag.deal(B.room, t1.deal_id)).terms_hash;
  await Sl.ag.counter(Sl.room, t1.deal_id, { price_usd: 2 });
  await Sl.ag.dealMsg(Sl.room, "accept", { deal_id: t1.deal_id, terms_hash: stale });
  await B.ag.dealMsg(B.room, "accept", { deal_id: t1.deal_id, terms_hash: stale });
  assert.equal(await status(t1.deal_id), "proposed", "accepting superseded terms doesn't agree the deal");
  // once agreed, terms are locked: a later counter can't raise the price
  await B.ag.accept(B.room, t1.deal_id);
  assert.equal(await status(t1.deal_id), "agreed");
  await Sl.ag.dealMsg(Sl.room, "counter", { deal_id: t1.deal_id, terms: { ...t1, version: 9, price_usd: 50 }, terms_hash: "x" });
  await Sl.ag.counter(Sl.room, t1.deal_id, { price_usd: 50 }).catch(() => {});
  const d1 = await B.ag.deal(B.room, t1.deal_id);
  assert.equal(d1.status, "agreed"); assert.equal(d1.terms.price_usd, 2, "agreed price can't be changed by one side");
  // only the buyer can report payment
  await Sl.ag.dealMsg(Sl.room, "paid", { deal_id: t1.deal_id, terms_hash: d1.terms_hash, payment: { tx: "0x" + "11".repeat(32), from: "0x" + "22".repeat(20), network: "eip155:8453" } });
  assert.equal(await status(t1.deal_id), "agreed", "a payment reported by the seller doesn't count");
  // an offer whose terms_hash doesn't match its terms is dropped
  await B.ag.dealMsg(B.room, "offer", { deal_id: "dl_tampered01", terms: { ...t1, deal_id: "dl_tampered01" }, terms_hash: stale });
  assert.equal((await B.ag.deals(B.room)).some((d) => d.deal_id === "dl_tampered01"), false, "tampered offer ignored");
  // an accept after the offer expired doesn't count
  const t2 = await offer({ expires_minutes: 0.0005 });
  await new Promise((r) => setTimeout(r, 80));
  await Sl.ag.dealMsg(Sl.room, "accept", { deal_id: t2.deal_id, terms_hash: (await B.ag.deal(B.room, t2.deal_id)).terms_hash });
  assert.equal(await status(t2.deal_id), "expired", "late accept doesn't agree an expired offer");
  // a relay that tampers with ciphertext gets the message hidden, not believed
  const last = relay.msgs[relay.msgs.length - 1];
  relay.msgs.push({ ...last, seq: relay.msgs.length + 1, from: "m_seller", body: last.body.slice(0, -8) + "AAAAAAAA" });
  assert.equal(await status(t2.deal_id), "expired", "tampered ciphertext is dropped, not believed");
  console.log("ok abuse cases: impostor and non-party accepts, stale accepts, locked terms, seller-reported payment, tampered and late messages"); n++;

  // Owner mandates: signed by an owner key, checked by the seller, enforced on the buyer's payments.
  const { createMandate, checkMandate } = await import("../clients/suppressor-sdk.js");
  const I2 = await import("../clients/agent-identity.js");
  const owner = await I2.generateOwnerKey(), stranger = await I2.generateOwnerKey();
  const mandate = await createMandate(owner, { agent_id: B.ag.agentId, max_per_deal_usd: 1.5, max_total_usd: 2, allowed_sellers: [Sl.ag.agentId] });
  const covered = { ...t1, price_usd: 1 };
  assert.equal(mandate.sig_v, 2, "mandates are always signed labeled");
  assert.equal(await checkMandate(mandate, { agent_id: B.ag.agentId, terms: covered }), null);
  assert.match(await checkMandate({ ...mandate, max_per_deal_usd: 1.9 }, { terms: covered }), /signature/, "raised limit breaks the owner signature");
  assert.match(await checkMandate({ ...mandate, owner_id: stranger.owner_id }, {}), /owner_sign_key/);
  assert.match(await checkMandate(mandate, { agent_id: M.ag.agentId }), /different agent/, "another agent can't reuse it");
  assert.match(await checkMandate(mandate, { terms: { ...covered, price_usd: 2 } }), /per deal/);
  assert.match(await checkMandate(mandate, { terms: { ...covered, seller: M.ag.agentId } }), /seller/);
  assert.match(await checkMandate(mandate, { now: Date.now() + 31 * 86400e3 }), /valid now/, "expired");
  assert.match(await checkMandate(mandate, { trustedOwners: [stranger.owner_id] }), /don't trust/);
  const { sig: _s, sig_v: _v, ...plainBody } = mandate;
  const plainSig = await I2.signBytes(owner, new TextEncoder().encode(I2.canonical(plainBody)));
  assert.match(await checkMandate({ ...plainBody, sig: plainSig }, {}), /signature/, "an unlabeled mandate signature is refused");
  await assert.rejects(createMandate(owner, { agent_id: B.ag.agentId, max_per_deal_usd: 5, max_total_usd: 1 }), /over max_total/);
  // seller requires a mandate: none → refused; a covering one → accepted; buyer can't offer past its own mandate
  Sl.ag.requireMandate = true;
  const t3 = await offer();
  await assert.rejects(Sl.ag.accept(Sl.room, t3.deal_id), /hasn't shown an owner mandate/);
  B.ag.mandate = mandate;
  const t4 = await offer();
  assert.equal((await Sl.ag.deal(Sl.room, t4.deal_id)).mandate.mandate_id, mandate.mandate_id);
  await Sl.ag.accept(Sl.room, t4.deal_id);
  assert.equal(await status(t4.deal_id), "agreed");
  await assert.rejects(offer({ price_usd: 3 }), /mandate doesn't cover/);
  const mt = { ...t4, deal_id: "dl_mallorymdt1", buyer: M.ag.agentId, version: 1 };
  await M.ag.dealMsg(M.room, "offer", { deal_id: mt.deal_id, terms: mt, terms_hash: await (await import("../clients/suppressor-sdk.js")).termsHash(mt), mandate });
  await assert.rejects(Sl.ag.accept(Sl.room, "dl_mallorymdt1"), /different agent/, "a copied mandate doesn't work for another agent");
  Sl.ag.trustedOwners = [stranger.owner_id];
  await assert.rejects(Sl.ag.checkBuyerMandate(await Sl.ag.deal(Sl.room, t4.deal_id)), /don't trust/, "seller can limit which owner keys it accepts");
  Sl.ag.trustedOwners = []; Sl.ag.requireMandate = false;
  // buyer: the mandate's total is enforced against what was already paid under it
  B.ag.policy.ledger.push({ at: new Date().toISOString(), usd: 1.5, to_agent: Sl.ag.agentId, deal_id: "dl_earlier1", mandate_id: mandate.mandate_id });
  await assert.rejects(B.ag.pay(B.room, t4.deal_id), /\$2 total/);
  B.ag.mandate = null; B.ag.policy.ledger.length = 0;
  console.log("ok mandates: owner-signed, labeled, tamper-proof, bound to agent, seller, price and time; seller can require one; buyer total enforced"); n++;

  // Signature labels: a signature made for one kind of document doesn't verify as another.
  // Unlabeled (old) signatures still verify during the transition, unless turned off.
  const ia = await I2.generateAgentIdentity();
  I2.signatureSettings.signLabeled = true;
  const lab = await I2.signDoc(ia, { type: "deal", kind: "offer", n: 1 }, "deal");
  assert.equal(lab.sig_v, 2);
  assert.ok(await I2.verifyDoc(lab, ia.sign_key, "deal"));
  assert.ok(!(await I2.verifyDoc(lab, ia.sign_key, "card")), "a deal signature can't pass as a card");
  assert.ok(!(await I2.verifyDoc(lab, ia.sign_key, "receipt")), "or as a receipt");
  const { sig_v: _sv, ...stripped } = lab;
  assert.ok(!(await I2.verifyDoc(stripped, ia.sign_key, "deal")), "removing the label breaks the signature");
  assert.ok(!(await I2.verifyDoc(lab, ia.sign_key)), "verifying needs a purpose");
  I2.signatureSettings.signLabeled = false;
  const old = await I2.signDoc(ia, { type: "deal", kind: "offer", n: 1 }, "deal");
  assert.equal(old.sig_v, undefined, "phase 1 still signs the old way, so older agents can read it");
  assert.ok(await I2.verifyDoc(old, ia.sign_key, "deal"));
  I2.signatureSettings.acceptUnlabeled = false;
  assert.ok(!(await I2.verifyDoc(old, ia.sign_key, "deal")), "phase 3 refuses old signatures");
  I2.signatureSettings.acceptUnlabeled = true;
  // receipts: a labeled buyer and an unlabeled seller still produce one receipt both signatures verify on
  const AS0 = await import("../src/agents/store.js");
  const verifyOk = (http) => async (method, path, body) => (path.startsWith("/v1/verify/usdc") ? { ok: true } : http(method, path, body));
  Sl.ag.http = verifyOk(relayHttp("m_seller"));
  for (const labeledBuyer of [false, true]) {
    const tr = await offer();
    await Sl.ag.accept(Sl.room, tr.deal_id);
    await B.ag.markPaid(B.room, tr.deal_id, "0x" + (labeledBuyer ? "a1" : "b2").repeat(32), "0x" + "cd".repeat(20));
    await Sl.ag.deliver(Sl.room, tr.deal_id, "the brief");
    I2.signatureSettings.signLabeled = labeledBuyer;
    await B.ag.confirm(B.room, tr.deal_id);
    I2.signatureSettings.signLabeled = false;
    const rcpt = await Sl.ag.countersign(Sl.room, tr.deal_id);
    assert.equal(rcpt.sig_v, labeledBuyer ? 2 : undefined);
    assert.equal(AS0.receiptShapeError(rcpt), null);
    const { sigs, ...rb } = rcpt;
    assert.ok(await I2.verifyDoc({ ...rb, sig: sigs.buyer }, B.ag.id.sign_key, "receipt"), "buyer signature verifies as the server checks it");
    assert.ok(await I2.verifyDoc({ ...rb, sig: sigs.seller }, Sl.ag.id.sign_key, "receipt"), "seller countersigned the same form");
  }
  console.log("ok signature labels: bound to document kind, label can't be stripped, old form accepted until turned off, mixed-version receipts"); n++;

  // Abuse cases (owner control and receipts): no model tool can change the owner's limits, and
  // the server refuses receipts carrying fields it doesn't expect.
  const fs = await import("node:fs");
  const mcp = fs.readFileSync(new URL("../mcp/server.js", import.meta.url), "utf8");
  const tools = [...mcp.matchAll(/registerTool\("([a-z_]+)"/g)].map((m) => m[1]);
  assert.ok(tools.length > 20);
  assert.deepEqual(tools.filter((x) => /polic|limit|admin|approv|setting/.test(x)), [], "no tool edits policy, limits or admin settings");
  assert.ok(!/writeFileSync\([^)]*(POLICY|MANDATE)/.test(mcp), "the MCP server never writes the policy or mandate file");
  const AS = await import("../src/agents/store.js");
  const rc = { v: 1, deal_id: "dl_abcdefgh", terms_hash: "h", amount_usd: 1, network: "eip155:8453", buyer: { agent_id: "agt_a", sign_key: "k" }, seller: { agent_id: "agt_b", sign_key: "k", pay_to: PAY_TO }, payment: { tx: "0x1", from: PAY_TO }, delivery_hash: "d", outcome: "completed", sigs: { buyer: "s", seller: "s" } };
  assert.equal(AS.receiptShapeError(rc), null);
  assert.match(AS.receiptShapeError({ ...rc, type: "deal" }), /unexpected field type/);
  assert.match(AS.receiptShapeError({ ...rc, seller: { ...rc.seller, note: "x" } }), /seller\.note/);
  assert.match(AS.receiptShapeError({ ...rc, payment: null }), /payment must be an object/);
  console.log("ok abuse cases: no tool can change owner limits, receipts with unexpected fields refused"); n++;
}

console.log(`\n${n} checks passed`);
