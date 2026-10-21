// End-to-end encryption helper for private rooms (open protocol, see PROTOCOL.md).
// Works in Node 20+ and modern browsers (WebCrypto X25519 + HKDF + AES-256-GCM, plus ML-KEM-768).
// Photos: encryptBlob / decryptBlob (random per-photo key, sent inside a sealed message).
// The server only ever sees the sealed JSON string; it can't read it.
// Messages are padded to fixed size buckets so the relay can't infer message length.
//
// Post-quantum (v1.2): every identity also has an ML-KEM-768 key (FIPS 203). When a recipient has
// published one, their box is "hybrid": the AES key comes from BOTH an X25519 secret and an
// ML-KEM secret, so recording traffic today and breaking X25519 with a future quantum computer
// isn't enough to read it. Members without an ML-KEM key get classical v1 boxes, so old clients
// keep working.
//
//   const me = await generateIdentity();            // keep me.privateKeyPkcs8 and me.pqSeed secret
//   // publish me.publicKey + me.pqPublicKey (public_key, pq_key) when creating/joining or via PUT /key
//   const body = await seal(roomId, me, room.members, "hello");   // POST as {body}
//   const text = await open(roomId, me, myMemberId, body, pinnedSenderKey);

import { ml_kem768 } from "./vendor/ml-kem.js";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (buf) => {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  return btoa(s);
};
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const sha256 = async (bytes) => new Uint8Array(await subtle.digest("SHA-256", bytes));
const concat = (...parts) => { const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0)); let o = 0; for (const p of parts) { out.set(p, o); o += p.length; } return out; };

export const X25519_KEY_BYTES = 32;
export const PQ_KEY_BYTES = 1184; // ML-KEM-768 encapsulation key
const PQ_SEED_BYTES = 64;

// ---- key validation (used by clients AND the relay) ----------------------------------------
const decodes = (s, n) => { if (typeof s !== "string" || s.length !== Math.ceil(n / 3) * 4 || !/^[A-Za-z0-9+/]+={0,2}$/.test(s)) return false; try { return unb64(s).length === n; } catch { return false; } };
export const isValidPublicKey = (s) => decodes(s, X25519_KEY_BYTES);
export function isValidPqKey(s) {
  if (!decodes(s, PQ_KEY_BYTES)) return false;
  try { ml_kem768.encapsulate(unb64(s)); return true; } catch { return false; } // FIPS 203 modulus check
}

// ---- identities ----------------------------------------------------------------------------
const pqCache = new Map(); // seed -> { publicKey, secretKey }
function pqKeys(seedB64) {
  let k = pqCache.get(seedB64);
  if (!k) { k = ml_kem768.keygen(unb64(seedB64)); pqCache.set(seedB64, k); if (pqCache.size > 64) pqCache.delete(pqCache.keys().next().value); }
  return k;
}
export async function generateIdentity() {
  const kp = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const pqSeed = b64(globalThis.crypto.getRandomValues(new Uint8Array(PQ_SEED_BYTES)));
  return {
    publicKey: b64(await subtle.exportKey("raw", kp.publicKey)),
    privateKeyPkcs8: b64(await subtle.exportKey("pkcs8", kp.privateKey)),
    pqPublicKey: b64(pqKeys(pqSeed).publicKey),
    pqSeed,
  };
}
export const newPqSeed = () => b64(globalThis.crypto.getRandomValues(new Uint8Array(PQ_SEED_BYTES)));
export const pqPublicKeyFor = (seedB64) => b64(pqKeys(seedB64).publicKey);
// Add an ML-KEM key to an identity saved by an older client. Returns true if it changed, in
// which case publish the new pq_key with PUT /v1/rooms/:id/key (public_key stays the same).
export async function upgradeIdentity(me) {
  if (me.pqSeed && me.pqPublicKey) return false;
  me.pqSeed = b64(globalThis.crypto.getRandomValues(new Uint8Array(PQ_SEED_BYTES)));
  me.pqPublicKey = b64(pqKeys(me.pqSeed).publicKey);
  return true;
}

// ---- key derivation --------------------------------------------------------------------------
async function x25519Bits(myPrivatePkcs8, theirPublicB64) {
  const priv = await subtle.importKey("pkcs8", unb64(myPrivatePkcs8), { name: "X25519" }, false, ["deriveBits"]);
  const pub = await subtle.importKey("raw", unb64(theirPublicB64), { name: "X25519" }, false, []);
  return new Uint8Array(await subtle.deriveBits({ name: "X25519", public: pub }, priv, 256));
}
async function hkdfKey(ikm, roomId, info) {
  const hk = await subtle.importKey("raw", ikm, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: enc.encode(roomId), info: enc.encode(info) }, hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
// v1 (classical): X25519 only.
const classicalKey = async (roomId, myPrivatePkcs8, theirPublicB64) => hkdfKey(await x25519Bits(myPrivatePkcs8, theirPublicB64), roomId, "suppressor-room-v1");
// v2 (hybrid): HKDF over X25519 || ML-KEM secrets, bound to both parties' keys, the recipient's
// seat and the KEM ciphertext. X25519 authenticates the sender; ML-KEM adds quantum resistance.
async function hybridKey(roomId, x25519Shared, kemShared, { fromKey, toMember, toKey, toPqKeyBytes, kemCt }) {
  const info = ["suppressor-room-v2", fromKey, toMember, toKey, b64(await sha256(toPqKeyBytes)), b64(await sha256(kemCt))].join("\n");
  return hkdfKey(concat(x25519Shared, kemShared), roomId, info);
}
const hybridAad = (roomId, toMember) => enc.encode(`suppressor-v2\n${roomId}\n${toMember}`);

// Length-hiding padding: [4-byte big-endian length][UTF-8 text][random bytes] up to a bucket
// of 256, 1024, 4096, 8192, 16384… bytes (doubling from 4096 on).
export function padBucket(n) { let b = 256; while (b < n) b *= b < 4096 ? 4 : 2; return b; }
function pad(text) {
  const t = enc.encode(text);
  const out = new Uint8Array(padBucket(t.length + 4));
  globalThis.crypto.getRandomValues(out);
  new DataView(out.buffer).setUint32(0, t.length);
  out.set(t, 4);
  return out;
}
function unpad(bytes) {
  const n = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength).getUint32(0);
  if (n > bytes.length - 4) throw new Error("bad padding");
  return dec.decode(bytes.subarray(4, 4 + n));
}

// ---- seal / open -------------------------------------------------------------------------------
export class KeyPinMismatch extends Error {}
// Encrypt once per recipient: every member with a valid public key, including yourself (so you can
// read your own history back). Needs at least one OTHER member's key.
// - Members whose keys are malformed are SKIPPED (listed in `skipped`), so one bad key can't stop
//   everyone else from talking.
// - Pass opts.pins (from checkPins) to refuse sealing to any key that differs from the pinned one,
//   including a post-quantum key that has been stripped (a downgrade).
export async function sealDetailed(roomId, me, members, plaintext, opts = {}) {
  const others = members.filter((m) => m.public_key && m.public_key !== me.publicKey && m.member_id !== opts.myMemberId);
  if (!others.length) throw new Error("No other member has published a public key yet.");
  const to = {}, skipped = [];
  const padded = pad(plaintext);
  let hybrid = false;
  for (const m of members) {
    if (!m.public_key) continue;
    if (opts.pins) {
      const pin = normPin(opts.pins[m.member_id]);
      if (pin && (pin.k !== m.public_key || (pin.pq && pin.pq !== m.pq_key)))
        throw new KeyPinMismatch(`The relay is showing a different key for ${m.member_id} than the one you pinned. Compare safety codes before sending.`);
    }
    if (!isValidPublicKey(m.public_key)) { skipped.push(m.member_id); continue; }
    const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
    try {
      const xs = await x25519Bits(me.privateKeyPkcs8, m.public_key);
      if (m.pq_key) {
        // An invalid PQ key is skipped (caught below), never silently downgraded to classical.
        if (!decodes(m.pq_key, PQ_KEY_BYTES)) throw new Error("bad pq key");
        const pqBytes = unb64(m.pq_key);
        const { cipherText, sharedSecret } = ml_kem768.encapsulate(pqBytes); // throws on a bad modulus
        const key = await hybridKey(roomId, xs, sharedSecret, { fromKey: me.publicKey, toMember: m.member_id, toKey: m.public_key, toPqKeyBytes: pqBytes, kemCt: cipherText });
        sharedSecret.fill(0);
        const ct = await subtle.encrypt({ name: "AES-GCM", iv, additionalData: hybridAad(roomId, m.member_id) }, key, padded);
        to[m.member_id] = { iv: b64(iv), ct: b64(ct), kem: b64(cipherText) };
        hybrid = true;
      } else {
        const key = await hkdfKey(xs, roomId, "suppressor-room-v1");
        const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, padded);
        to[m.member_id] = { iv: b64(iv), ct: b64(ct) };
      }
      xs.fill(0);
    } catch {
      skipped.push(m.member_id); // e.g. a low-order X25519 point the platform refuses
    }
  }
  padded.fill(0);
  if (!Object.keys(to).some((id) => others.some((m) => m.member_id === id))) throw new Error("No other member has a usable public key.");
  const body = JSON.stringify(hybrid
    ? { v: 2, alg: "X25519+MLKEM768-HKDF-AES256GCM", pad: 1, from_key: me.publicKey, to }
    : { v: 1, alg: "X25519-HKDF-AES256GCM", pad: 1, from_key: me.publicKey, to });
  return { body, skipped, post_quantum: hybrid && Object.values(to).every((b) => b.kem) };
}
export async function seal(roomId, me, members, plaintext, opts) {
  return (await sealDetailed(roomId, me, members, plaintext, opts)).body;
}

// expectedFromKey: the sender's public key as you know it (pinned when they joined), or the pin
// itself from checkPins. Pass it whenever you can: without it, a dishonest relay could seal a
// message with its own key and label it as coming from another member. A mismatch throws.
export class SenderKeyMismatch extends Error {}
export async function openDetailed(roomId, me, myMemberId, body, expectedFromKey) {
  const env = JSON.parse(body);
  const box = env.to?.[myMemberId];
  if (!box) return null; // not addressed to me
  const expected = expectedFromKey && typeof expectedFromKey === "object" ? expectedFromKey.k : expectedFromKey;
  if (expected !== undefined && env.from_key !== expected) throw new SenderKeyMismatch("The message's sender key doesn't match that member's key");
  if (!isValidPublicKey(env.from_key)) throw new SenderKeyMismatch("Malformed sender key");
  let pt;
  if (box.kem) {
    if (!me.pqSeed) throw new Error("This message uses post-quantum encryption, but this identity has no ML-KEM key.");
    const { publicKey: myPq, secretKey } = pqKeys(me.pqSeed);
    const kemCt = unb64(box.kem);
    const kemShared = ml_kem768.decapsulate(kemCt, secretKey);
    const xs = await x25519Bits(me.privateKeyPkcs8, env.from_key);
    const key = await hybridKey(roomId, xs, kemShared, { fromKey: env.from_key, toMember: myMemberId, toKey: me.publicKey, toPqKeyBytes: myPq, kemCt });
    kemShared.fill(0); xs.fill(0);
    pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(box.iv), additionalData: hybridAad(roomId, myMemberId) }, key, unb64(box.ct)));
  } else {
    const key = await classicalKey(roomId, me.privateKeyPkcs8, env.from_key);
    pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(box.iv) }, key, unb64(box.ct)));
  }
  const text = env.pad ? unpad(pt) : dec.decode(pt); // unpadded = older clients
  pt.fill(0);
  return { text, post_quantum: !!box.kem };
}
export async function open(roomId, me, myMemberId, body, expectedFromKey) {
  const r = await openDetailed(roomId, me, myMemberId, body, expectedFromKey);
  return r ? r.text : null;
}

// ---- photos / files (v1.1) ----------------------------------------------------------
// A photo is encrypted ONCE with a fresh random AES-256-GCM key. Only that small key travels
// inside a normal sealed message, so each member gets it through their own end-to-end box
// (hybrid post-quantum when every member has an ML-KEM key; AES-256 itself is quantum-safe).
// Size is padded up to a multiple of 64 KB so the relay learns only a rough size.
const BLOB_STEP = 64 * 1024;
export async function encryptBlob(bytes) {
  const raw = new Uint8Array(bytes);
  const size = Math.ceil((raw.length + 4) / BLOB_STEP) * BLOB_STEP;
  const padded = new Uint8Array(size);
  for (let i = 0; i < size; i += 65536) globalThis.crypto.getRandomValues(padded.subarray(i, Math.min(size, i + 65536)));
  new DataView(padded.buffer).setUint32(0, raw.length);
  padded.set(raw, 4);
  const keyBytes = globalThis.crypto.getRandomValues(new Uint8Array(32));
  const iv = globalThis.crypto.getRandomValues(new Uint8Array(12));
  const key = await subtle.importKey("raw", keyBytes, "AES-GCM", false, ["encrypt"]);
  const data = new Uint8Array(await subtle.encrypt({ name: "AES-GCM", iv }, key, padded));
  padded.fill(0);
  const out = { data, key: b64(keyBytes), iv: b64(iv) };
  keyBytes.fill(0);
  return out;
}
export async function decryptBlob(data, keyB64, ivB64) {
  const key = await subtle.importKey("raw", unb64(keyB64), "AES-GCM", false, ["decrypt"]);
  const pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64(ivB64) }, key, data));
  const n = new DataView(pt.buffer).getUint32(0);
  if (n > pt.length - 4) throw new Error("bad padding");
  const out = pt.slice(4, 4 + n);
  pt.fill(0);
  return out;
}

// ---- verification: key pinning + safety code (PROTOCOL.md §4) -------------------------------------
// A pin is { k: X25519 key, pq: ML-KEM key or null }. Older clients stored plain strings; both work.
export const normPin = (p) => (p == null ? null : typeof p === "string" ? { k: p, pq: null } : p);
export const pinKey = (p) => normPin(p)?.k;
// Pin each member's keys the first time you see them. If the relay later shows a different key
// for someone already pinned — or drops a post-quantum key they had (a downgrade) — that's a
// possible interception: stop and re-compare the safety code.
// Returns the updated pins and: added (new members), changed (key swapped or PQ key removed),
// upgraded (a pinned member added a PQ key for the first time; pinned automatically, since a
// hybrid key can only add protection, never remove the X25519 layer), gone (pinned members no
// longer listed, e.g. they left).
export function checkPins(pins = {}, members = []) {
  const next = {}, added = [], changed = [], upgraded = [];
  for (const [id, p] of Object.entries(pins)) next[id] = normPin(p);
  for (const m of members) {
    if (!m.public_key) continue;
    const shown = { k: m.public_key, pq: m.pq_key || null };
    const pin = next[m.member_id];
    if (!pin) { next[m.member_id] = shown; added.push(m.member_id); }
    else if (pin.k !== shown.k || (pin.pq && pin.pq !== shown.pq)) changed.push({ member_id: m.member_id, pinned: pin, shown, downgrade: pin.k === shown.k && !shown.pq });
    else if (!pin.pq && shown.pq) { next[m.member_id] = shown; upgraded.push(m.member_id); }
  }
  const listed = new Set(members.map((m) => m.member_id));
  const gone = Object.keys(next).filter((id) => !listed.has(id));
  return { pins: next, added, changed, upgraded, gone };
}

// Post-quantum status of a room: protected only when every member with a key has an ML-KEM key.
export function roomPqStatus(members = []) {
  const keyed = members.filter((m) => m.public_key);
  const missing = keyed.filter((m) => !m.pq_key).map((m) => m.member_id);
  return { post_quantum: keyed.length > 0 && missing.length === 0, missing };
}

// Safety code: about 100 bits, shown as 30 digits (6 groups of 5). Covers every member's id and
// key(s), so the relay can't swap or relabel a key without the codes differing.
// v3 (every member has an ML-KEM key) also covers the ML-KEM keys; otherwise v2, as older clients compute.
export async function safetyCode(members) {
  const keyed = members.filter((m) => m.public_key);
  const v3 = keyed.length > 0 && keyed.every((m) => m.pq_key);
  const entries = keyed.map((m) => (v3 ? `${m.member_id}:${m.public_key}:${m.pq_key}` : `${m.member_id}:${m.public_key}`)).sort().join("\n");
  const h = new Uint8Array(await subtle.digest("SHA-256", enc.encode((v3 ? "suppressor-safety-v3\n" : "suppressor-safety-v2\n") + entries)));
  let n = 0n;
  for (let i = 0; i < 16; i++) n = (n << 8n) | BigInt(h[i]);
  return (n % 10n ** 30n).toString().padStart(30, "0").match(/.{5}/g).join(" ");
}
