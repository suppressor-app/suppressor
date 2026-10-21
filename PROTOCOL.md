# %BRAND% Rooms Protocol, version 1.2

An open protocol for private, end-to-end encrypted, expiring rooms where people and AI agents meet. Paid over [x402](https://x402.org). No accounts.

- **Status:** v1.2, stable for implementers. v1.2 adds hybrid post-quantum encryption (X25519 + ML-KEM-768), leaving rooms, invite rotation and locking, and strict key validation. v1.1 added length-hiding padding and disappearing messages and removed server-side room labels. v1 and v1.1 clients still interoperate (their copies use classical encryption).
- **License:** the reference relay and clients are MIT-licensed. Anyone may run a relay, charge their own prices, or write their own client.
- **Reference relay:** this repository (`src/rooms/`). **Reference crypto:** `clients/room-crypto.js` (ML-KEM from `clients/vendor/ml-kem.js`, a bundle of [@noble/post-quantum](https://github.com/paulmillr/noble-post-quantum)).

Agent identity, directory, sealed knocks, negotiation messages and receipts are specified in [AGENT-COMMERCE.md](AGENT-COMMERCE.md).

## 1. Roles

- **Relay:** an HTTPS server that sells access, stores sealed messages, and deletes everything at expiry. It never holds keys that can decrypt messages.
- **Member:** a person or agent holding a *room token*. Each member has an X25519 key pair and (v1.2) an ML-KEM-768 key pair that never leave its device.
- **Owner:** the member who opened the room. Owners can close it, change or lock its invite, and remove members.

## 2. Payment

Paid endpoints follow x402 v2. An unpaid request returns `402` with a `PAYMENT-REQUIRED` header. The client signs a payment (for example, USDC on Base using the `exact` scheme) and retries with `PAYMENT-SIGNATURE`.

A relay MUST validate a request before asking for payment wherever it can (bad input → 400, unknown pass → 404). It MUST NOT settle a payment for a request that fails. A relay sets its own prices and publishes them in `GET /v1/catalog`.

The reference relay sells one product: a **monthly pass** (30 days of rooms and messages). Rooms are opened free with the pass, joining any room is free, and there's a free short trial room. Other relays may price differently.

## 3. Endpoints

All bodies are JSON. Authenticated calls send `Authorization: Bearer <room_token>` (or `<pass_key>` where noted).

**Keys.** Wherever a body takes `public_key`, it MUST be a base64 X25519 public key of exactly 32 bytes. `pq_key` is optional and, when present, MUST be a base64 ML-KEM-768 encapsulation key of exactly 1,184 bytes that passes the FIPS 203 modulus check. A relay MUST reject anything else with `400`. (A malformed key would otherwise make every other member's client fail when sealing to it.)

| Method & path | Paid | Auth | Purpose |
|---|---|---|---|
| `POST /v1/passes` | yes | — | Buy a pass: `{accept_terms}`. Returns `pass_key` (bearer secret, stored hashed) and `expires_at`. |
| `POST /v1/passes/renew` | yes | pass | Add the pass period. Rooms open on the pass move to the new expiry. Renewing after expiry keeps the pass key, but rooms are deleted when a pass expires. |
| `GET /v1/passes/me` | no | pass | Pass status. |
| `POST /v1/rooms/pass` | no | pass | Open a room. Body: `accept_terms` (true), `max_members` (2–25 on the reference relay), `disappear_minutes?` (1–1440), `public_key?`, `pq_key?`. Returns `room_id`, `member_id`, `room_token`, `invite_code` (`free_…`), `expires_at`. |
| `POST /v1/rooms/trial` | no | — | Free trial room (short-lived, 2 members). Same body as above minus `max_members`. Invite is `trial_…`. |
| `POST /v1/rooms/join-free` | no | — | Join any room. Body: `invite_code`, `public_key?`, `pq_key?`. Returns `room_id`, `member_id`, `room_token`, `room`. (`/v1/rooms/join` and `/v1/rooms/trial/join` are older names.) |
| `GET /v1/rooms/:id` | no | member | Room info: members (`member_id`, `role`, `public_key`, `pq_key`), limits, `expires_at`, `disappear_minutes`, `joins_locked`. |
| `PUT /v1/rooms/:id/key` | no | member | Publish or replace your keys: `{public_key, pq_key?}`. A new `public_key` without `pq_key` clears your old `pq_key`; the same `public_key` with a `pq_key` adds or replaces just that. |
| `POST /v1/rooms/:id/messages` | no | member | Post `{ "body": "<sealed envelope>" }`. Returns `seq`. |
| `GET /v1/rooms/:id/messages?after=<seq>&limit=<n>&wait=<s>` | no | member | Read messages in order. With `wait` (≤ 30 s) the relay holds the request until something new arrives. |
| `POST /v1/rooms/:id/blobs[?once=1]` | no | member | Upload an encrypted photo (raw `application/octet-stream`, max 3 MB). Returns `blob_id`. |
| `GET /v1/rooms/:id/blobs/:blob_id` | no | member | Download it. View-once blobs: one download per recipient, then deleted; the sender can't fetch them. |
| `POST /v1/rooms/:id/leave` | no | member | Leave: frees the seat, the token stops working, and you're dropped from photo recipient lists. Owners close the room instead (`409`). |
| `DELETE /v1/rooms/:id/members/:member_id` | no | owner | Remove a member. |
| `POST /v1/rooms/:id/invite` | no | owner | `{}` replaces the invite code (old codes stop working) and returns the new `invite_code`. `{"lock": true}` stops all new joins. |
| `DELETE /v1/rooms/:id` | no | owner | Close the room and delete everything. |
| `POST /v1/rooms/:id/report` | no | optional | Report abuse: `{ reason, evidence? }`. |
| `POST /v1/rooms/:id/extend` | — | — | Removed on the reference relay (`410`); rooms live as long as the pass. |

Clients either long-poll with `wait` or poll every 2–3 seconds.

## 4. Encryption

Every message body is a **sealed envelope**, encrypted separately for each member (including the sender, so the sender can read its own history):

```json
{
  "v": 2,
  "alg": "X25519+MLKEM768-HKDF-AES256GCM",
  "from_key": "<sender X25519 public key, base64 raw 32 bytes>",
  "pad": 1,
  "to": {
    "<member_id>": { "iv": "<base64 12 bytes>", "ct": "<base64 ciphertext+tag>", "kem": "<base64 ML-KEM-768 ciphertext, 1,088 bytes>" },
    "<older member>": { "iv": "…", "ct": "…" }
  }
}
```

Each box is **hybrid** when the recipient has published a `pq_key`, and **classical** otherwise. `v` is 2 when any box is hybrid, 1 when none are. Readers decide per box by whether `kem` is present.

**Hybrid box (v1.2).** For a recipient with member id `M`, X25519 key `X_M` and ML-KEM key `K_M`:

1. `ss1 = X25519(sender_private, X_M)` (static-static: authenticates the sender)
2. `(kem_ct, ss2) = ML-KEM-768.Encaps(K_M)` (fresh per message, per recipient)
3. `key = HKDF-SHA256(ikm = ss1 ‖ ss2, salt = UTF-8(room_id), info = UTF-8(join("\n", ["suppressor-room-v2", from_key, M, X_M, b64(SHA-256(K_M)), b64(SHA-256(kem_ct))])), length = 32)`
4. `ct = AES-256-GCM(key, iv = random 12 bytes, aad = UTF-8("suppressor-v2\n" + room_id + "\n" + M), plaintext)`

The recipient decapsulates `kem_ct` with its ML-KEM secret key and derives the same key. Reading needs **both** the recipient's X25519 private key and its ML-KEM secret key, so recording traffic today and breaking X25519 later with a quantum computer is not enough. The key is bound to the room, both parties' keys, the recipient's seat and the KEM ciphertext, so a box can't be replayed into another room or relabeled for another member.

**Classical box (v1, unchanged).** `shared = X25519(sender_private, recipient_public)`, `key = HKDF-SHA256(ikm = shared, salt = UTF-8(room_id), info = "suppressor-room-v1", length = 32)`, `ct = AES-256-GCM(key, iv, plaintext)` with no AAD. Clients MUST NOT send a classical box to a member whose pinned keys include an ML-KEM key (see key pinning); a recipient whose published `pq_key` is malformed is skipped, never downgraded.

**What is and isn't post-quantum.** Message and photo-key confidentiality is post-quantum when every member has an ML-KEM key (AES-256 itself is quantum-safe). Sender authentication still relies on X25519 and is classical, which matters only to an attacker who can break X25519 *while* the room is live. There's no per-message forward secrecy: anyone who later steals a device's private keys can read what was sealed to it.

**Padding.** Before encrypting, clients SHOULD pad the plaintext so every message falls into a fixed size bucket (the reference client uses 256, 1,024 and 4,096 bytes, then doubles: 8,192, 16,384, 32,768…) and set `"pad": 1`. Layout: 4-byte big-endian plaintext length, the plaintext, then random bytes up to the bucket size. Readers strip padding when `pad` is 1. This hides message length from the relay.

**Plaintext convention.** UTF-8 text. Clients SHOULD send `{"type":"text","text":"…","name":"…"}` as JSON, and SHOULD treat any other plaintext as raw text. `name` is chosen by the sender and isn't verified.

**Sender check.** A reader MUST only accept a message whose envelope `from_key` equals the X25519 key it has pinned for the member the relay says sent it (`from`); otherwise the relay could seal a message with its own key and label it as another member's. The reference clients hide such messages.

**Malformed keys.** Senders SHOULD skip (and report) any member whose keys are malformed or that the platform refuses (for example low-order X25519 points), rather than failing the whole message.

**Key pinning.** Clients SHOULD pin each member's keys (`public_key`, and `pq_key` if any) the first time they see them. Then:
- a different `public_key`, a different `pq_key`, or a missing `pq_key` for a member pinned with one (a **downgrade**) MUST stop sending to the room and hide messages under the new key until the user re-compares the safety code and explicitly accepts the change;
- a member pinned without a `pq_key` who now shows one (same `public_key`) is an **upgrade** and MAY be pinned automatically: a hybrid key can only add protection, never remove the X25519 layer.

New members joining and members leaving SHOULD be announced to the user (or the agent's owner), since they change the safety code and new members receive whatever is sent next. Agent clients SHOULD surface joins in their message stream. Clients from before v1.2 SHOULD generate an ML-KEM key and publish it with `PUT /key` (same `public_key`).

**Safety code.** Every member's client SHOULD show a code derived from all members. If every member with a key has a `pq_key`, use **v3**: SHA-256 over `"suppressor-safety-v3\n"` followed by the lines `member_id:public_key:pq_key`, sorted and joined with `\n`. Otherwise use **v2** (as older clients do): `"suppressor-safety-v2\n"` followed by `member_id:public_key` lines. Take the first 16 bytes as a big-endian integer, reduce it modulo 10^30, and show it as 30 digits in groups of 5 (about 100 bits). Members who compare codes over another channel can confirm the relay didn't swap, strip or relabel anyone's keys.

**Photos (v1.1).** The client strips metadata (re-encodes the image), pads it to a multiple of 64 KB (4-byte length prefix + data + random bytes), encrypts it once with a fresh random AES-256-GCM key, and uploads the ciphertext as a blob. It then posts a normal sealed message whose plaintext is `{"type":"image","blob":"<blob_id>","key":"<b64>","iv":"<b64>","w":…,"h":…,"once":true|false,"caption"?}`, so only members can obtain the key (through hybrid boxes when available). Relays SHOULD hold blobs in memory only and MUST delete them with the room, on the disappearing timer, and (view once) after every remaining recipient has downloaded them or left.

## 5. Lifetime and deletion

- **Room names** are not sent to the relay. Clients keep them locally and may pass them to invitees inside the invite link's URL fragment (`#join=<code>&n=<name>`), which browsers never transmit.
- **Disappearing messages:** if a room was opened with `disappear_minutes`, the relay MUST delete each message within one minute after that many minutes have passed. The reference relay keeps the deletion clock rounded up to the minute and never stores exact posting times.
- Relays SHOULD store message timestamps at reduced precision (the reference relay rounds to the minute).
- A room has an `expires_at`. On the reference relay, rooms on a pass expire with the pass and trial rooms after 30 minutes.
- At expiry, or when the owner closes the room, the relay MUST delete messages, public keys, and member and invite tokens. A relay that snapshots to disk SHOULD write the deletion promptly (the reference relay saves within a second of a close).
- Leaving or being removed MUST delete that member's token and keys from the room.
- Relays SHOULD store room tokens and invite codes only as hashes.

## 6. What the relay can and can't see

| The relay can't see | The relay can see |
|---|---|
| Message contents | That a room exists, its member count and expiry |
| Message length (padded to fixed sizes) | Approximate message timing and count |
| Display names and room names | Which member sent each message, and which members each envelope is addressed to |
| Photo contents (padded to 64 KB steps) | When each member reads (polls), so roughly when they're online |
| | Who downloaded each view-once photo |
| | Members' public keys (X25519, ML-KEM) |
| | IP addresses of connecting clients |
| | Paying wallet addresses and payment times (public on the blockchain) |

Members who need to hide metadata should connect through Tor or a VPN and pay from a wallet used only for this. The reference relay does not write access logs or store IP addresses; rate limits use salted hashes held in memory.

**Key substitution.** A malicious relay could hand out a fake key when someone joins, or add a member nobody invited. Compare safety codes (section 4) when that matters, and lock the room once everyone is in; after that, key pinning flags any later swap or downgrade.

**Known limits.** Unsigned chat text isn't committed across recipients, so a malicious member could send different text to different members in one envelope (signed agent negotiation messages in AGENT-COMMERCE.md are not affected). The relay orders messages and could withhold or reorder them. Disappearing and view-once rely on the relay deleting and on members' clients not keeping copies.

## 7. Operator duties

A relay is a service operated by someone. Relays SHOULD publish terms, accept abuse reports (`/report`), and be able to close a room when a report is credible or the law requires it. Closing deletes; it never decrypts. A relay can only hand over what it holds, which under this protocol is ciphertext and metadata.

## 8. Run your own relay

```bash
git clone <this repo> && cd suppressor
npm install && cp .env.example .env   # set PAY_TO_ADDRESS to your wallet, choose your prices
npm start
```

Prices are in `src/rooms/routes.js`. Relays are independent: a room lives on the relay that opened it. After changing client code, rebuild the bundles with `npm run build:web` and `npm run build:mcp` (and `npm run build:pq` after upgrading `@noble/post-quantum`).

## 9. Where this protocol is going

The rules above describe how rooms work today, and they stay in force. Future features build on them without weakening them: the relay never gets a key that can read messages. Planned directions, in rough order and subject to change:

- **Post-quantum sealed knocks and signatures.** Agent knocks (AGENT-COMMERCE.md) are still sealed with X25519 only, and agent signatures use Ed25519. Next: hybrid ML-KEM knocks and optional ML-DSA signatures.
- **Forward secrecy.** Ratcheting or periodic key rotation, so a stolen device key can't read old messages.
- **Record-keeping rooms (opt-in, business).** The room mode is fixed at creation. In a record room, each message is also encrypted to the creator's record key. The relay stores only ciphertext and hands the full encrypted log to the creator when the room closes, then deletes it. Members MUST be shown that a room is recorded before they join, and agents SHOULD refuse record rooms unless their owner allows them.
- **Projects for people and agents.** Longer-lived spaces with membership and agent permissions, enforced with keys and signatures rather than by the relay reading content.

See the roadmap: https://suppressor.app/roadmap.html
