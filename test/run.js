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
  const doc = await I.signDoc(a, { hello: "world", n: 1 });
  assert.ok(await I.verifyDoc(doc, a.sign_key));
  assert.ok(!(await I.verifyDoc({ ...doc, n: 2 }, a.sign_key)), "tampered doc must fail");
  assert.ok(!(await I.verifyDoc(doc, b.sign_key)), "wrong key must fail");
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
  assert.ok(await I.verifyDoc(card, card.sign_key));
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
  // escrow routing: $100+ deals, flagged counterparties and low-track-record sellers need escrow; small deals go direct
  const ep = new SpendingPolicy({ escrow_below_verified_deals: 3, escrow_counterparties: ["agt_shady"] });
  assert.equal(ep.needsEscrow({ usd: 99.99, counterparty: "agt_x", verified_deals: 5 }).required, false);
  assert.equal(ep.needsEscrow({ usd: 100, counterparty: "agt_x", verified_deals: 5 }).required, true, "threshold is inclusive");
  assert.equal(ep.needsEscrow({ usd: 5, counterparty: "agt_shady", verified_deals: 50 }).required, true);
  assert.equal(ep.needsEscrow({ usd: 5, counterparty: "agt_x", verified_deals: 1 }).required, true);
  assert.equal(ep.needsEscrow({ usd: 5, counterparty: "agt_x", verified_deals: null }).required, true, "unknown track record counts as too few");
  assert.equal(new SpendingPolicy().needsEscrow({ usd: 5, counterparty: "agt_x" }).required, false, "default: only $100+ needs escrow");
  const { validateTerms } = await import("../clients/suppressor-sdk.js");
  assert.equal(validateTerms({ ...terms, settlement: "escrow" }), null);
  assert.match(validateTerms({ ...terms, settlement: "trust-me" }), /settlement/);
  const big = await SuppressorAgent.create({ baseUrl: "http://localhost:1", payFetch: async () => { throw new Error("must not pay"); }, policy: new SpendingPolicy({ max_per_payment_usd: 500, max_per_day_usd: 500, max_total_usd: 500, require_approval_over_usd: 500 }) });
  const bigTerms = { ...terms, buyer: big.agentId, price_usd: 150 };
  big.deal = async () => ({ deal_id: "dl_abcdefgh", status: "agreed", terms: bigTerms });
  await assert.rejects(big.pay({}, "dl_abcdefgh"), /Escrow required/, "a $150 deal can't be paid direct");
  await assert.rejects(big.requireEscrowIfNeeded(bigTerms), /Escrow required/);
  await big.requireEscrowIfNeeded({ ...bigTerms, settlement: "escrow" });
  big.deal = async () => ({ deal_id: "dl_abcdefgh", status: "agreed", terms: { ...bigTerms, settlement: "escrow" } });
  await assert.rejects(big.pay({}, "dl_abcdefgh"), /settles through escrow/, "escrow deals never fall back to a direct payment");
  seller.deal = async () => ({ deal_id: "dl_abcdefgh", status: "paid", terms: { ...terms, settlement: "escrow" }, payment: { tx: "0x" + "ee".repeat(32), from: "0x" + "dd".repeat(20) } });
  await assert.rejects(seller.deliver({}, "dl_abcdefgh", "x"), /settles through escrow/, "seller won't deliver an escrow deal against a direct payment");
  console.log("ok escrow routing: $100+ / flagged / low-track-record deals need escrow; no direct fallback"); n++;
}

console.log(`\n${n} checks passed`);
