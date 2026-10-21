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
  assert.equal(C.pinKey(p2.pins.m_bob), bob.publicKey, "pinned key is kept until the user accepts");
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
  // Post-quantum hybrid encryption (X25519 + ML-KEM-768).
  const C = await import("../clients/room-crypto.js");
  const room = "rm_pqtest00001";
  const a = await C.generateIdentity(), b = await C.generateIdentity(), eve = await C.generateIdentity();
  assert.ok(C.isValidPublicKey(a.publicKey) && C.isValidPqKey(a.pqPublicKey));
  const mem = (id, x, pq = true) => ({ member_id: id, public_key: x.publicKey, pq_key: pq ? x.pqPublicKey : null });
  const both = [mem("A", a), mem("B", b)];
  const d = await C.sealDetailed(room, a, both, "quantum-proof hello");
  const env = JSON.parse(d.body);
  assert.equal(env.v, 2); assert.ok(d.post_quantum);
  assert.equal(Buffer.from(env.to.B.kem, "base64").length, 1088, "ML-KEM-768 ciphertext per recipient");
  const got = await C.openDetailed(room, b, "B", d.body, a.publicKey);
  assert.equal(got.text, "quantum-proof hello"); assert.equal(got.post_quantum, true);
  assert.equal(await C.open(room, a, "A", d.body, a.publicKey), "quantum-proof hello", "sender reads own hybrid history");
  // Bindings: another room, a relabeled box, or the wrong ML-KEM secret all fail.
  await assert.rejects(C.open("rm_other000001", b, "B", d.body));
  const relabel = JSON.parse(d.body); relabel.to = { A: env.to.B }; // B's box handed to A
  await assert.rejects(C.open(room, a, "A", JSON.stringify(relabel)));
  await assert.rejects(C.open(room, { ...b, pqSeed: eve.pqSeed }, "B", d.body), "ML-KEM half required");
  await assert.rejects(C.open(room, { ...b, privateKeyPkcs8: eve.privateKeyPkcs8 }, "B", d.body), "X25519 half required");
  // Mixed room: an old (classical) member still gets a v1 box an old client can read.
  const mixed = await C.sealDetailed(room, a, [mem("A", a), mem("B", b), mem("OLD", eve, false)], "hi all");
  const menv = JSON.parse(mixed.body);
  assert.ok(menv.to.B.kem && !menv.to.OLD.kem); assert.equal(mixed.post_quantum, false);
  assert.equal(await C.open(room, { publicKey: eve.publicKey, privateKeyPkcs8: eve.privateKeyPkcs8 }, "OLD", mixed.body, a.publicKey), "hi all");
  // Old identities can be upgraded in place; X25519 key unchanged.
  const legacy = { publicKey: eve.publicKey, privateKeyPkcs8: eve.privateKeyPkcs8 };
  assert.equal(await C.upgradeIdentity(legacy), true); assert.equal(legacy.publicKey, eve.publicKey); assert.ok(C.isValidPqKey(legacy.pqPublicKey));
  assert.equal(await C.upgradeIdentity(legacy), false);
  // Pins: adding a PQ key is an automatic upgrade; removing or swapping it is flagged (downgrade).
  let p = C.checkPins({}, [mem("A", a), mem("B", b, false)]);
  p = C.checkPins(p.pins, both); assert.deepEqual(p.upgraded, ["B"]); assert.equal(p.changed.length, 0);
  const stripped = C.checkPins(p.pins, [mem("A", a), mem("B", b, false)]);
  assert.equal(stripped.changed.length, 1); assert.equal(stripped.changed[0].downgrade, true);
  const swappedPq = C.checkPins(p.pins, [mem("A", a), { ...mem("B", b), pq_key: eve.pqPublicKey }]);
  assert.equal(swappedPq.changed.length, 1); assert.equal(swappedPq.changed[0].downgrade, false);
  assert.deepEqual(C.checkPins(p.pins, [mem("A", a)]).gone, ["B"]);
  assert.equal(C.checkPins({ B: b.publicKey }, both).upgraded[0], "B", "legacy string pins still work");
  // seal() with pins refuses a stripped PQ key instead of quietly sending classical.
  await assert.rejects(C.seal(room, a, [mem("A", a), mem("B", b, false)], "x", { pins: p.pins }), C.KeyPinMismatch);
  // Safety code v3 covers ML-KEM keys; v2 (old clients) when anyone lacks one.
  const code = await C.safetyCode(both);
  assert.notEqual(code, await C.safetyCode([mem("A", a), { ...mem("B", b), pq_key: eve.pqPublicKey }]), "PQ key swap changes the code");
  assert.equal(await C.safetyCode([mem("A", a, false), mem("B", b, false)]), await C.safetyCode([{ member_id: "A", public_key: a.publicKey }, { member_id: "B", public_key: b.publicKey }]), "v2 unchanged for old clients");
  assert.deepEqual(C.roomPqStatus(both), { post_quantum: true, missing: [] });
  assert.deepEqual(C.roomPqStatus([mem("A", a), mem("B", b, false)]).missing, ["B"]);
  console.log("ok post-quantum: hybrid X25519+ML-KEM-768, bindings, mixed rooms, upgrade, downgrade flagged, safety v3"); n++;
}

{
  // One bad key can't stop a room: malformed keys are rejected by the relay and skipped by clients.
  const C = await import("../clients/room-crypto.js");
  const a = await C.generateIdentity(), b = await C.generateIdentity();
  const zeros = Buffer.alloc(32).toString("base64"); // low-order point
  for (const badKey of ["AAAAAAAAAAAAAAAA", "not base64 at all!!", zeros.slice(0, 40)]) assert.equal(C.isValidPublicKey(badKey), false);
  assert.equal(C.isValidPqKey(Buffer.alloc(1184, 255).toString("base64")), false, "FIPS 203 modulus check");
  const members = [{ member_id: "A", public_key: a.publicKey, pq_key: a.pqPublicKey }, { member_id: "B", public_key: b.publicKey, pq_key: b.pqPublicKey },
    { member_id: "X1", public_key: "AAAAAAAAAAAAAAAA" }, { member_id: "X2", public_key: zeros }, { member_id: "X3", public_key: b.publicKey.replace(/^./, "C"), pq_key: Buffer.alloc(1184, 255).toString("base64") }];
  const d = await C.sealDetailed("rm_badkeys0001", a, members, "still works");
  assert.ok(d.skipped.includes("X1") && d.skipped.includes("X3"), "bad keys skipped, not fatal");
  assert.ok(!JSON.parse(d.body).to.X3, "invalid PQ key is skipped, never downgraded to classical");
  assert.equal(await C.open("rm_badkeys0001", b, "B", d.body, a.publicKey), "still works");
  console.log("ok hardening: malformed and low-order keys skipped, room keeps working"); n++;
}

t("hardening: leave frees the seat, owner remove, invite rotate and lock, view-once cleanup", () => {
  const { room, token, invite } = S.createRoom({ max_members: 3 });
  const j1 = S.joinRoom(room, {}), j2 = S.joinRoom(room, {});
  assert.equal(room.members.length, 3);
  const owner = S.memberFor(room.id, token).member;
  // view-once photo to both members; one opens it, the other leaves -> it's deleted.
  const ph = S.putBlob(room, owner, Buffer.from("cipher"), true);
  assert.ok(S.getBlob(room, S.memberFor(room.id, j1.token).member, ph.blob_id).data);
  assert.ok(S.removeMember(room, j2.member_id));
  assert.equal(S.getBlob(room, owner, ph.blob_id).status, 410, "view-once photo dropped once everyone remaining opened it");
  assert.equal(S.memberFor(room.id, j2.token).member, null, "left member's token is dead");
  assert.equal(room.members.length, 2, "seat is free again");
  assert.ok(S.roomByInvite(invite));
  const fresh = S.rotateInvite(room);
  assert.equal(S.roomByInvite(invite), null, "old invite stops working"); assert.equal(S.roomByInvite(fresh).id, room.id);
  assert.equal(S.rotateInvite(room, { lock: true }), null);
  assert.equal(S.roomByInvite(fresh), null); assert.equal(S.roomInfo(room, owner).joins_locked, true);
  S.closeRoom(room);
});

t("hardening: PQ keys stored, key replacement semantics, disappearing clock rounded, rate map pruned", () => {
  const { room, token } = S.createRoom({ max_members: 2, public_key: "x".repeat(44), pq_key: "p", disappear_minutes: 5 });
  const m = S.memberFor(room.id, token).member;
  assert.equal(S.roomInfo(room, m).members[0].pq_key, "p");
  S.setKey(m, "x".repeat(44), "q"); assert.equal(m.pq_key, "q", "pq-only update");
  S.setKey(m, "x".repeat(44)); assert.equal(m.pq_key, "q", "same key, pq kept");
  S.setKey(m, "y".repeat(44)); assert.equal(m.pq_key, null, "new identity clears the old ML-KEM key");
  S.postMessage(room, m, "sealed");
  assert.equal(room.messages[0].posted % 60e3, 0, "no millisecond timestamps, even for disappearing messages");
  assert.ok(room.messages[0].posted >= Date.now() - 1000);
  S.closeRoom(room);
});

{
  // HTTP: the relay rejects bad keys before doing anything, and the new endpoints work end to end.
  const express = (await import("express")).default;
  const R = await import("../src/rooms/routes.js");
  const C = await import("../clients/room-crypto.js");
  const app = express(); app.use(express.json({ limit: "2mb" }));
  R.mountHandlers(app, { adminToken: null });
  const srv = app.listen(0); const base = `http://127.0.0.1:${srv.address().port}`;
  const call = async (method, path, body, tok) => { const r = await fetch(base + path, { method, headers: { "content-type": "application/json", ...(tok ? { authorization: `Bearer ${tok}` } : {}) }, body: body ? JSON.stringify(body) : undefined }); return { status: r.status, j: await r.json().catch(() => ({})) }; };
  const a = await C.generateIdentity(), b = await C.generateIdentity(), c = await C.generateIdentity();
  assert.equal((await call("POST", "/v1/rooms/trial", { accept_terms: true, public_key: "AAAAAAAAAAAAAAAA" })).status, 400);
  assert.equal((await call("POST", "/v1/rooms/trial", { accept_terms: true, public_key: a.publicKey, pq_key: "short" })).status, 400);
  const { pass } = S.buyPass();
  const opened = S.createRoom({ max_members: 3, public_key: a.publicKey, pq_key: a.pqPublicKey, pass });
  const rid = opened.room.id;
  const jb = await call("POST", "/v1/rooms/join-free", { invite_code: opened.invite, public_key: b.publicKey, pq_key: b.pqPublicKey });
  assert.equal(jb.status, 200); assert.equal(jb.j.room.members.find((m) => m.member_id === jb.j.member_id).pq_key, b.pqPublicKey);
  // hybrid message through the relay
  const info = (await call("GET", `/v1/rooms/${rid}`, null, opened.token)).j;
  const sealed = await C.sealDetailed(rid, a, info.members, "over the wire");
  assert.ok(sealed.post_quantum);
  assert.equal((await call("POST", `/v1/rooms/${rid}/messages`, { body: sealed.body }, opened.token)).status, 201);
  const read = (await call("GET", `/v1/rooms/${rid}/messages?after=0`, null, jb.j.room_token)).j;
  assert.equal(await C.open(rid, b, jb.j.member_id, read.messages[0].body, a.publicKey), "over the wire");
  // PUT key: bad keys refused
  assert.equal((await call("PUT", `/v1/rooms/${rid}/key`, { public_key: b.publicKey, pq_key: Buffer.alloc(1184, 255).toString("base64") }, jb.j.room_token)).status, 400);
  // invite rotate + lock (owner only)
  assert.equal((await call("POST", `/v1/rooms/${rid}/invite`, {}, jb.j.room_token)).status, 403);
  const rot = (await call("POST", `/v1/rooms/${rid}/invite`, {}, opened.token)).j;
  assert.equal((await call("POST", "/v1/rooms/join-free", { invite_code: opened.invite, public_key: c.publicKey })).status, 404, "old invite dead");
  assert.equal((await call("POST", `/v1/rooms/${rid}/invite`, { lock: true }, opened.token)).j.joins_locked, true);
  assert.equal((await call("POST", "/v1/rooms/join-free", { invite_code: rot.invite_code, public_key: c.publicKey })).status, 404, "locked");
  // leave / remove
  assert.equal((await call("POST", `/v1/rooms/${rid}/leave`, {}, opened.token)).status, 409, "owner closes instead");
  assert.equal((await call("DELETE", `/v1/rooms/${rid}/members/${jb.j.member_id}`, null, jb.j.room_token)).status, 403);
  assert.equal((await call("POST", `/v1/rooms/${rid}/leave`, {}, jb.j.room_token)).j.left, true);
  assert.equal((await call("GET", `/v1/rooms/${rid}`, null, jb.j.room_token)).status, 401, "token dead after leaving");
  assert.equal((await call("GET", `/v1/rooms/${rid}`, null, opened.token)).j.members.length, 1);
  srv.close(); S.closeRoom(opened.room);
  console.log("ok relay HTTP: strict key validation, PQ keys, hybrid over the wire, invite rotate/lock, leave/remove"); n++;
}

{
  // SDK end to end through a real relay: agents get hybrid PQ rooms, joins are announced, lock and leave work.
  const express = (await import("express")).default;
  const R = await import("../src/rooms/routes.js");
  const { SuppressorAgent } = await import("../clients/suppressor-sdk.js");
  const AI = await import("../clients/agent-identity.js");
  const app = express(); app.use(express.json({ limit: "2mb" }));
  R.mountHandlers(app, { adminToken: null });
  const srv = app.listen(0); const baseUrl = `http://127.0.0.1:${srv.address().port}`;
  const { key: passKey } = S.buyPass();
  const A = await SuppressorAgent.create({ baseUrl, passKey }), B = await SuppressorAgent.create({ baseUrl }), Cg = await SuppressorAgent.create({ baseUrl }), D = await SuppressorAgent.create({ baseUrl });
  assert.ok(A.id.box_pq_seed, "new agent identities carry an ML-KEM seed");
  const ra = await A.openRoom({ maxMembers: 3 });
  await A.refreshKeys(ra); // seen with only the owner present
  const rb = await B.joinRoom(ra.invite_code);
  const sent = await A.post(ra, { type: "text", text: "pq hello" });
  assert.equal(sent.post_quantum, true, "every agent has an ML-KEM key, so boxes are hybrid");
  const logB = await B.read(rb);
  assert.ok(logB.some((e) => e.msg.type === "text" && e.msg.text === "pq hello"));
  assert.ok(ra.log.some((e) => e.msg.type === "member_joined" && e.msg.member_id === rb.member_id), "B's join announced to A");
  const rc = await Cg.joinRoom(ra.invite_code);
  await A.refreshKeys(ra);
  assert.ok(ra.log.some((e) => e.msg.type === "member_joined" && e.msg.member_id === rc.member_id), "third member announced");
  await A.lockJoins(ra);
  await assert.rejects(D.joinRoom(ra.invite_code), /not found/i, "locked room refuses joins");
  await Cg.leave(rc);
  await A.refreshKeys(ra);
  assert.ok(ra.log.some((e) => e.msg.type === "member_left" && e.msg.member_id === rc.member_id));
  // A legacy agent (no ML-KEM seed) still talks classically, and upgrading adds PQ without a key-swap alarm.
  const legacy = await AI.generateAgentIdentity(); delete legacy.box_pq_seed;
  const L = new SuppressorAgent({ baseUrl, identity: legacy });
  const rb2 = await B.openRoom({ mode: "trial" });
  await B.refreshKeys(rb2);
  const rl = await L.joinRoom(rb2.invite_code);
  assert.equal((await B.post(rb2, { type: "text", text: "classical" })).post_quantum, false);
  assert.ok((await L.read(rl)).some((e) => e.msg.text === "classical"));
  assert.equal(AI.ensureRoomPq(legacy), true);
  rl.me = AI.roomIdentity(legacy);
  await L.refreshKeys(rl); // publishes the new ML-KEM key
  await B.refreshKeys(rb2);
  assert.equal(rb2.keyAlert, null, "adding a PQ key is an upgrade, not a key swap");
  assert.equal((await B.post(rb2, { type: "text", text: "now hybrid" })).post_quantum, true);
  assert.ok((await L.read(rl)).some((e) => e.msg.text === "now hybrid"));
  srv.close();
  console.log("ok SDK end to end: hybrid PQ agent rooms, joins/leaves announced, lock, legacy agents upgrade cleanly"); n++;
}

console.log(`\n${n} checks passed`);
