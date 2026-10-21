// Suppressor agent identity: Ed25519 signing keys, canonical signed documents, signed
// requests, and sealed "knocks" to an agent's X25519 box key.
// Uses only WebCrypto (Node 20+ and current browsers). No custom cryptography: Ed25519
// (RFC 8032) for signatures, X25519 + HKDF-SHA256 + AES-256-GCM for sealing, SHA-256 hashes.

import { newPqSeed, pqPublicKeyFor } from "./room-crypto.js";

const subtle = globalThis.crypto.subtle;
const enc = new TextEncoder();
const dec = new TextDecoder();

export const b64u = (buf) => {
  const u = new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u.length; i += 0x8000) s += String.fromCharCode.apply(null, u.subarray(i, i + 0x8000));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
export const unb64u = (s) => {
  const t = String(s).replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(atob(t + "===".slice((t.length + 3) % 4)), (c) => c.charCodeAt(0));
};
const b64 = (buf) => b64u(buf).replace(/-/g, "+").replace(/_/g, "/") + "===".slice((b64u(buf).length + 3) % 4);
const rand = (n) => globalThis.crypto.getRandomValues(new Uint8Array(n));

// Canonical JSON: object keys sorted recursively, no whitespace. Signatures cover exactly this.
export function canonical(v) {
  if (v === null || typeof v !== "object") {
    if (typeof v === "number" && !Number.isFinite(v)) throw new Error("non-finite number");
    return JSON.stringify(v);
  }
  if (Array.isArray(v)) return "[" + v.map(canonical).join(",") + "]";
  return "{" + Object.keys(v).filter((k) => v[k] !== undefined).sort().map((k) => JSON.stringify(k) + ":" + canonical(v[k])).join(",") + "}";
}
export async function sha256(data) {
  return b64u(await subtle.digest("SHA-256", typeof data === "string" ? enc.encode(data) : data));
}

// An agent id is derived from its public signing key, so it can't be claimed by anyone else.
export async function agentIdFor(signKeyB64u) {
  return "agt_" + (await sha256(unb64u(signKeyB64u))).slice(0, 26);
}

export async function generateAgentIdentity() {
  const sk = await subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  const bk = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const sign_key = b64u(await subtle.exportKey("raw", sk.publicKey));
  return {
    agent_id: await agentIdFor(sign_key),
    sign_key,
    sign_private: b64u(await subtle.exportKey("pkcs8", sk.privateKey)),
    box_key: b64(await subtle.exportKey("raw", bk.publicKey)), // same format as room keys
    box_private: b64(await subtle.exportKey("pkcs8", bk.privateKey)),
    box_pq_seed: newPqSeed(), // ML-KEM-768 seed for post-quantum room encryption (keep secret)
  };
}
// Identities created before v1.2 have no ML-KEM key. Adds one; returns true if the identity
// changed, in which case SAVE it (a new seed every run would look like a key swap to peers).
export function ensureRoomPq(identity) {
  if (identity.box_pq_seed) return false;
  identity.box_pq_seed = newPqSeed();
  return true;
}

const importSign = (pkcs8) => subtle.importKey("pkcs8", unb64u(pkcs8), { name: "Ed25519" }, false, ["sign"]);
const importVerify = (raw) => subtle.importKey("raw", unb64u(raw), { name: "Ed25519" }, false, ["verify"]);

export async function signBytes(identity, bytes) {
  return b64u(await subtle.sign({ name: "Ed25519" }, await importSign(identity.sign_private), bytes));
}
export async function verifyBytes(signKey, bytes, sig) {
  try { return await subtle.verify({ name: "Ed25519" }, await importVerify(signKey), unb64u(sig), bytes); } catch { return false; }
}

// Sign a JSON document: the signature covers canonical(doc without "sig").
export async function signDoc(identity, doc) {
  const { sig, ...body } = doc;
  return { ...body, sig: await signBytes(identity, enc.encode(canonical(body))) };
}
export async function verifyDoc(doc, signKey) {
  if (!doc || typeof doc.sig !== "string") return false;
  const { sig, ...body } = doc;
  return verifyBytes(signKey, enc.encode(canonical(body)), sig);
}

// Signed HTTP requests (header "Suppressor-Agent"). Covers method, path, time, a one-time
// nonce and the body hash, so a captured request can't be replayed or altered.
export async function signRequest(identity, method, path, bodyText = "") {
  const ts = Date.now();
  const nonce = b64u(rand(12));
  const msg = `${method.toUpperCase()} ${path}\n${ts}\n${nonce}\n${await sha256(bodyText || "")}`;
  return `${identity.agent_id};ts=${ts};nonce=${nonce};sig=${await signBytes(identity, enc.encode(msg))}`;
}
export function parseAgentHeader(h) {
  const m = /^(agt_[A-Za-z0-9_-]{20,40});ts=(\d{10,16});nonce=([A-Za-z0-9_-]{8,40});sig=([A-Za-z0-9_-]{40,120})$/.exec(String(h || "").trim());
  return m ? { agent_id: m[1], ts: Number(m[2]), nonce: m[3], sig: m[4] } : null;
}
export async function verifyRequest(parsed, signKey, method, path, bodyText = "") {
  const msg = `${method.toUpperCase()} ${path}\n${parsed.ts}\n${parsed.nonce}\n${await sha256(bodyText || "")}`;
  return verifyBytes(signKey, enc.encode(msg), parsed.sig);
}

// Sealed box to an agent's X25519 box key: fresh ephemeral key per message, so the sender is
// anonymous to the relay (and to the recipient, unless the plaintext says who it is).
async function boxKey(myPriv, theirPubB64, info) {
  const pub = await subtle.importKey("raw", unb64u(theirPubB64), { name: "X25519" }, false, []);
  const bits = await subtle.deriveBits({ name: "X25519", public: pub }, myPriv, 256);
  const hk = await subtle.importKey("raw", bits, "HKDF", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "HKDF", hash: "SHA-256", salt: enc.encode("suppressor-knock-v1"), info: enc.encode(info) }, hk, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
export async function sealTo(recipientBoxKey, recipientAgentId, plaintext) {
  const eph = await subtle.generateKey({ name: "X25519" }, true, ["deriveBits"]);
  const key = await boxKey(eph.privateKey, recipientBoxKey, recipientAgentId);
  const t = enc.encode(plaintext);
  const size = Math.max(1024, 2 ** Math.ceil(Math.log2(t.length + 4))); // length hiding
  const padded = size <= 65536 ? rand(size) : new Uint8Array(size);
  new DataView(padded.buffer).setUint32(0, t.length);
  padded.set(t, 4);
  const iv = rand(12);
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, key, padded);
  return JSON.stringify({ v: 1, alg: "X25519-HKDF-AES256GCM", eph: b64u(await subtle.exportKey("raw", eph.publicKey)), iv: b64u(iv), ct: b64u(ct) });
}
export async function openSealed(identity, sealed) {
  const env = JSON.parse(sealed);
  const priv = await subtle.importKey("pkcs8", unb64u(identity.box_private), { name: "X25519" }, false, ["deriveBits"]);
  const key = await boxKey(priv, env.eph, identity.agent_id);
  const pt = new Uint8Array(await subtle.decrypt({ name: "AES-GCM", iv: unb64u(env.iv) }, key, unb64u(env.ct)));
  const n = new DataView(pt.buffer).getUint32(0);
  if (n > pt.length - 4) throw new Error("bad padding");
  return dec.decode(pt.subarray(4, 4 + n));
}

// Room-crypto compatible identity view: rooms use X25519 keys in standard base64.
// Includes the ML-KEM key when the identity has one (see ensureRoomPq).
export const roomIdentity = (identity) => ({
  publicKey: identity.box_key,
  privateKeyPkcs8: identity.box_private,
  ...(identity.box_pq_seed ? { pqSeed: identity.box_pq_seed, pqPublicKey: pqPublicKeyFor(identity.box_pq_seed) } : {}),
});
