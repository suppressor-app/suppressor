// Private rooms: browser client for people.
// Bundled to sites/rooms/rooms/app.js with `npm run build:web`.
// Keys and room tokens stay in this browser (localStorage). The server only sees ciphertext.
import { wrapFetchWithPaymentFromConfig } from "@x402/fetch";
import { ExactEvmScheme } from "@x402/evm";
import { createWalletClient, custom } from "viem";
import { generateIdentity, seal, open, encryptBlob, decryptBlob, checkPins, safetyCode, SenderKeyMismatch } from "../clients/room-crypto.js";

const $ = (s) => document.querySelector(s);
// The page's language comes from the server; translated UI strings ride along in the page.
const LOCALE = document.documentElement.lang || "en";
const STRINGS = (() => { try { return JSON.parse(document.getElementById("i18n-strings")?.textContent || "{}"); } catch { return {}; } })();
const t = (s, v = {}) => (STRINGS[s] || s).replace(/\{(\w+)\}/g, (m, k) => (k in v ? v[k] : m));
const show = (id) => document.querySelectorAll("[data-view]").forEach((el) => (el.hidden = el.dataset.view !== id));
const store = {
  get(k) { try { return JSON.parse(localStorage.getItem(k)); } catch { return null; } },
  set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch {} },
  del(k) { try { localStorage.removeItem(k); } catch {} },
};
const roomKey = (id) => `sup.room.${id}`;
const myRooms = () => store.get("sup.rooms") || [];
const remember = (creds) => {
  store.set(roomKey(creds.room_id), creds);
  store.set("sup.rooms", [creds.room_id, ...myRooms().filter((x) => x !== creds.room_id)].slice(0, 30));
};
const forget = (id) => { store.del(roomKey(id)); store.set("sup.rooms", myRooms().filter((x) => x !== id)); };
const forgetAll = () => { for (const id of myRooms()) store.del(roomKey(id)); store.del("sup.rooms"); };
const MAX_TEXT = 4000;
// The room's label never goes to the server: it travels inside the invite link's #fragment,
// which browsers don't send in requests.
const inviteLink = (c) => `${location.origin}/rooms/#join=${c.invite}${c.label ? "&n=" + encodeURIComponent(c.label) : ""}`;
const disappearChoice = () => Number($("#disappear").value) || undefined;
const freeInvite = (code) => /^(trial|free)_/.test(code || "");

// ---- unlimited pass (key kept only in this browser) ----------------------------------
const getPass = () => store.get("sup.pass");
// Renewal reminders. Passes never renew on their own (crypto wallets can't be charged automatically),
// and rooms on a pass close, and their messages are deleted, when it ends. So warn early and plainly.
const RENEW_WARN_DAYS = 5;
const passDaysLeft = (p) => Math.max(0, Math.ceil((new Date(p.expires_at) - Date.now()) / 86400e3));
const endDate = (iso) => new Date(iso).toLocaleDateString(LOCALE, { weekday: "short", month: "short", day: "numeric" });
function renewWarning(p) {
  if (!p || !p.expires_at) return null;
  if (new Date(p.expires_at) <= new Date()) return t("Your pass has ended. Renew within 30 days to keep using the same pass key.");
  const d = passDaysLeft(p);
  if (d > RENEW_WARN_DAYS) return null;
  const date = endDate(p.expires_at);
  return d === 1
    ? t("Your pass ends in 1 day ({date}). When it ends, rooms on it close and their messages are deleted. Renewing now keeps your days left and adds 30 more.", { date })
    : t("Your pass ends in {n} days ({date}). When it ends, rooms on it close and their messages are deleted. Renewing now keeps your days left and adds 30 more.", { n: d, date });
}
// A calendar reminder made on this device: Suppressor never learns your email or calendar.
function downloadReminder() {
  const p = getPass();
  if (!p || !p.expires_at) return;
  const end = new Date(p.expires_at);
  const at = new Date(Math.max(Date.now() + 3600e3, end.getTime() - 3 * 86400e3));
  const f = (d) => d.toISOString().replace(/[-:]/g, "").replace(/\.\d{3}/, "");
  const url = `${location.origin}/rooms/`;
  const ics = [
    "BEGIN:VCALENDAR", "VERSION:2.0", "PRODID:-//Suppressor//Pass reminder//EN", "BEGIN:VEVENT",
    `UID:pass-${end.getTime()}@${location.host}`, `DTSTAMP:${f(new Date())}`, `DTSTART:${f(at)}`, `DTEND:${f(new Date(at.getTime() + 15 * 60e3))}`,
    `SUMMARY:Renew your ${health?.name || "Suppressor"} pass ($5)`,
    `DESCRIPTION:Your pass ends ${end.toUTCString()}. Rooms on it close and their messages are deleted when it ends. Renew at ${url}`,
    `URL:${url}`, "BEGIN:VALARM", "ACTION:DISPLAY", "TRIGGER:PT0M", "DESCRIPTION:Renew your pass", "END:VALARM", "END:VEVENT", "END:VCALENDAR",
  ].join("\r\n");
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([ics], { type: "text/calendar" }));
  a.download = "renew-pass-reminder.ics";
  document.body.append(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 5000);
  status(t("Reminder saved for {date}. Open the file to add it to your calendar.", { date: endDate(at.toISOString()) }), "ok");
}
const passActive = () => { const p = getPass(); return !!(p && p.key && new Date(p.expires_at) > new Date()); };
function renderPass() {
  const p = getPass(), on = passActive();
  $("#pass-none").hidden = !!p;
  $("#pass-active").hidden = !p;
  const st = $("#pass-state");
  if (!p) { st.textContent = t("No pass on this device"); st.className = "pill"; }
  else if (on) { const d = passDaysLeft(p); st.textContent = d === 1 ? t("Active · 1 day left") : t("Active · {n} days left", { n: d }); st.className = d <= RENEW_WARN_DAYS ? "pill soon" : "pill on"; }
  else { st.textContent = t("Expired: renew to keep using it"); st.className = "pill soon"; }
  const w = renewWarning(p);
  $("#renew-warn").hidden = !w;
  if (w) $("#renew-warn-text").textContent = w;
  const pro = on;
  document.querySelectorAll("#size option[data-pass]").forEach((o) => { o.disabled = !pro; o.hidden = !pro; });
  if (!pro && Number($("#size").value) > 8) $("#size").value = "2";
  if (p) $("#renew-price").textContent = (health?.room_prices || {})["pass-renew"] || "$5";
  $("#open-btn").textContent = on ? t("Open a room") : t("Get unlimited ({price}/month) and open a room", { price: (health?.room_prices || {})["pass-buy"] || "$5" });
}
async function refreshPass() {
  const p = getPass();
  if (!p) return renderPass();
  try {
    const r = await fetch("/v1/passes/me", { headers: { authorization: `Bearer ${p.key}` } });
    if (r.status === 404) { store.del("sup.pass"); status(t("The saved pass key wasn't found, so it was removed from this browser."), "err"); }
    else if (r.ok) { const j = await r.json(); store.set("sup.pass", { key: p.key, expires_at: j.expires_at, tier: j.tier }); }
  } catch {}
  renderPass();
}
function showKey(editable) {
  $("#pass-key-box").hidden = false;
  $("#pass-key-note").hidden = false;
  const k = $("#pass-key");
  k.readOnly = !editable;
  k.value = editable ? "" : getPass()?.key || "";
  $("#pass-key-save").textContent = editable ? t("Use this key") : t("Copy");
  $("#pass-key-save").dataset.mode = editable ? "save" : "copy";
  if (editable) k.focus(); else k.select();
}
async function buyPass(tier) {
  if (!$("#terms").checked) return status(t("Tick the box agreeing to the terms first."), "err");
  const btn = $("#pass-buy");
  const sku = "pass-buy";
  btn.disabled = true;
  try {
    const pay = await getPayer();
    status(health.payments ? t("Approve the {price} USDC payment in your wallet…", { price: health.room_prices[sku] }) : t("Getting your pass…"));
    const r = await api(pay, "POST", "/v1/passes", { accept_terms: true });
    store.set("sup.pass", { key: r.pass_key, expires_at: r.expires_at, tier: r.tier });
    renderPass();
    showKey(false);
    status(t("Your pass is active. Save your pass key below, and tap \"Add renewal reminder to my calendar\" so it doesn't lapse."), "ok");
  } catch (err) {
    status(err.message, "err");
  } finally {
    btn.disabled = false;
  }
}
async function renewPass() {
  const p = getPass();
  if (!p) return;
  try {
    const pay = await getPayer();
    status(health.payments ? t("Approve the {price} USDC payment in your wallet…", { price: health.room_prices["pass-renew"] }) : t("Renewing…"));
    const r = await api(pay, "POST", "/v1/passes/renew", null, p.key);
    store.set("sup.pass", { key: p.key, expires_at: r.expires_at, tier: r.tier });
    renderPass();
    status(t("Renewed. Your pass now runs to {date}.", { date: new Date(r.expires_at).toLocaleDateString(LOCALE) }), "ok");
  } catch (err) {
    status(err.message, "err");
  }
}
async function savePassKey() {
  const btn = $("#pass-key-save");
  if (btn.dataset.mode === "copy") {
    try { await navigator.clipboard.writeText($("#pass-key").value); status(t("Pass key copied."), "ok"); } catch { $("#pass-key").select(); }
    return;
  }
  const key = $("#pass-key").value.trim();
  try {
    const r = await fetch("/v1/passes/me", { headers: { authorization: `Bearer ${key}` } });
    if (!r.ok) throw new Error(t("That pass key wasn't found."));
    const j = await r.json();
    store.set("sup.pass", { key, expires_at: j.expires_at, tier: j.tier });
    $("#pass-key-box").hidden = true;
    renderPass();
    status(t("Pass added to this browser."), "ok");
  } catch (err) {
    status(err.message, "err");
  }
}

let health = null;
let payFetch = null;

function status(msg, kind = "") {
  const el = $("#status");
  el.textContent = msg || "";
  el.className = "status " + kind;
}

async function api(f, method, path, body, token) {
  const res = await f(path, {
    method,
    headers: { "content-type": "application/json", ...(token ? { authorization: `Bearer ${token}` } : {}) },
    body: body ? JSON.stringify(body) : undefined,
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(json.error || (res.status === 402 ? t("Payment didn't go through. Check you have enough USDC on {network}.", { network: health?.mainnet ? "Base" : "Base Sepolia" }) : t("Request failed ({code})", { code: res.status })));
    err.status = res.status;
    throw err;
  }
  return json;
}

// ---- wallet + x402 ----------------------------------------------------------
const CHAINS = {
  8453: { chainId: "0x2105", chainName: "Base", rpcUrls: ["https://mainnet.base.org"], blockExplorerUrls: ["https://basescan.org"], nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
  84532: { chainId: "0x14a34", chainName: "Base Sepolia", rpcUrls: ["https://sepolia.base.org"], blockExplorerUrls: ["https://sepolia.basescan.org"], nativeCurrency: { name: "Ether", symbol: "ETH", decimals: 18 } },
};

async function getPayer() {
  if (!health.payments) return fetch; // local dev mode
  if (payFetch) return payFetch;
  const eth = window.ethereum;
  if (!eth) throw new Error(t("No wallet found. Install Coinbase Wallet or MetaMask, or open this page inside your wallet app's browser."));
  status(t("Connect your wallet…"));
  const [address] = await eth.request({ method: "eth_requestAccounts" });
  const chain = CHAINS[Number(health.network.split(":")[1])];
  try {
    await eth.request({ method: "wallet_switchEthereumChain", params: [{ chainId: chain.chainId }] });
  } catch (e) {
    if (e.code === 4902) await eth.request({ method: "wallet_addEthereumChain", params: [chain] });
    else throw e;
  }
  const wallet = createWalletClient({ account: address, transport: custom(eth) });
  const signer = { address, signTypedData: (m) => wallet.signTypedData({ account: address, ...m }) };
  // The x402 client caps each payment at $1 by default; the monthly pass is $5.
  // The wallet still asks the person to approve every payment.
  payFetch = wrapFetchWithPaymentFromConfig(fetch, { schemes: [{ network: "eip155:*", client: new ExactEvmScheme(signer) }], spendControls: { maxAmountPerPayment: "$10" } });
  $("#wallet").textContent = address.slice(0, 6) + "…" + address.slice(-4);
  return payFetch;
}

// ---- open / join --------------------------------------------------------------
async function openRoom(e) {
  e.preventDefault();
  if (!$("#terms").checked) return status(t("Please agree to the terms first."), "err");
  const btn = $("#open-btn");
  btn.disabled = true;
  try {
    // Rooms come with the $5 monthly pass. No pass yet? Buy it first, then open the room.
    if (!passActive()) { btn.disabled = false; await buyPass("pro"); if (!passActive()) return; }
    const me = await generateIdentity();
    status(t("Opening your room…"));
    const r = await api(fetch, "POST", "/v1/rooms/pass", {
      accept_terms: true,
      max_members: Number($("#size").value),
      disappear_minutes: disappearChoice(),
      public_key: me.publicKey,
    }, getPass().key);
    remember({ room_id: r.room_id, member_id: r.member_id, token: r.room_token, invite: r.invite_code, owner: true, me, name: $("#name").value.trim(), label: $("#label").value.trim() });
    status("");
    location.hash = `room=${r.room_id}`;
  } catch (err) {
    status(err.message, "err");
  } finally {
    btn.disabled = false;
  }
}

async function openTrial() {
  if (!$("#terms").checked) return status(t("Please agree to the terms first (tick the box above)."), "err");
  const btn = $("#trial-btn");
  btn.disabled = true;
  try {
    const me = await generateIdentity();
    status(t("Opening your free room…"));
    const r = await api(fetch, "POST", "/v1/rooms/trial", {
      accept_terms: true,
      disappear_minutes: disappearChoice(),
      public_key: me.publicKey,
    });
    remember({ room_id: r.room_id, member_id: r.member_id, token: r.room_token, invite: r.invite_code, owner: true, me, name: $("#name").value.trim(), label: $("#label").value.trim() });
    status("");
    location.hash = `room=${r.room_id}`;
  } catch (err) {
    status(err.message, "err");
  } finally {
    btn.disabled = false;
  }
}

async function joinRoom(e) {
  e.preventDefault();
  if (!$("#jterms").checked) return status(t("Please agree to the terms first."), "err");
  const hp = new URLSearchParams(location.hash.slice(1));
  const invite = hp.get("join");
  const label = (hp.get("n") || "").slice(0, 80);
  const btn = $("#join-btn");
  btn.disabled = true;
  try {
    const me = await generateIdentity();
    status(t("Joining…"));
    const r = await api(fetch, "POST", "/v1/rooms/join-free", { invite_code: invite, public_key: me.publicKey });
    remember({ room_id: r.room_id, member_id: r.member_id, token: r.room_token, owner: false, me, name: $("#jname").value.trim(), label });
    status("");
    location.hash = `room=${r.room_id}`;
  } catch (err) {
    status(err.message, "err");
  } finally {
    btn.disabled = false;
  }
}

// ---- room view ----------------------------------------------------------------
let current = null; // { creds, info, last, timer }

function stop() {
  if (current?.timer) clearInterval(current.timer);
  current = null;
  closeViewer();
  if (pending) discardPhoto();
  if (rec) rec.stop();
}

async function enterRoom(id) {
  stop();
  const creds = store.get(roomKey(id));
  if (!creds) {
    show("missing");
    return;
  }
  current = { creds, info: null, last: 0, members: new Map() };
  $("#messages").replaceChildren();
  $("#room-title").textContent = creds.label || t("Private room");
  $("#invite-row").hidden = !creds.owner;
  $("#close-btn").hidden = !creds.owner;
  if (creds.owner) $("#invite-link").value = inviteLink(creds);
  show("room");
  await refreshInfo();
  await poll();
  let tick = 0;
  current.timer = setInterval(async () => {
    await poll();
    if (++tick % 4 === 0) await refreshInfo();
  }, 2500);
  $("#msg").focus();
}

async function refreshInfo() {
  if (!current) return;
  try {
    const info = await api(fetch, "GET", `/v1/rooms/${current.creds.room_id}`, null, current.creds.token);
    current.info = info;
    info.members.forEach((m, i) => current.members.set(m.member_id, i));
    const others = info.members.length - 1;
    $("#trial-note").hidden = !info.trial;
    const meta = [];
    if (info.trial) meta.push(t("Free trial")); else if (info.pass) meta.push(t("Monthly pass"));
    if (info.disappear_minutes) meta.push(info.disappear_minutes >= 60 ? t("messages vanish after {n} h", { n: info.disappear_minutes / 60 }) : t("messages vanish after {n} min", { n: info.disappear_minutes }));
    meta.push(t("{n} of {max} members", { n: info.members.length, max: info.max_members }));
    meta.push(info.pass ? t("{n} messages", { n: info.messages_used }) : t("{n}/{max} messages", { n: info.messages_used, max: info.message_limit }));
    meta.push(t("expires {date}", { date: new Date(info.expires_at).toLocaleString(LOCALE) }));
    $("#room-meta").textContent = meta.join(" · ");
    $("#waiting").hidden = others > 0;
    roomRenewWarning(info);
    verifyKeys(info);
    $("#safety").textContent = await safetyCode(info.members);
    $("#invite-row").hidden = !current.creds.owner || info.members.length >= info.max_members;
  } catch (err) {
    gone(err);
  }
}

// Inside a room on a pass: warn before the pass (and so the room) ends. Only the pass holder can renew.
function roomRenewWarning(info) {
  const box = $("#room-renew-warn");
  const ends = info.pass && info.expires_at ? new Date(info.expires_at) : null;
  const d = ends ? Math.max(0, Math.ceil((ends - Date.now()) / 86400e3)) : Infinity;
  if (!ends || d > RENEW_WARN_DAYS) { box.hidden = true; return; }
  const mine = !!current?.creds?.owner && !!getPass();
  const date = endDate(info.expires_at);
  $("#room-renew-text").textContent = !mine
    ? t("This room closes on {date}, when the host's pass ends, and its messages will be deleted.", { date })
    : d === 1
      ? t("This room closes when your pass ends in 1 day ({date}), and its messages are deleted. Renew to keep it open.", { date })
      : t("This room closes when your pass ends in {n} days ({date}), and its messages are deleted. Renew to keep it open.", { n: d, date });
  $("#room-renew-row").hidden = !mine;
  box.hidden = false;
}

// ---- key pinning (PROTOCOL.md §4) -------------------------------------------------------
// Each member's key is remembered the first time this device sees it. If the server later shows
// a different key for someone, sending stops and their new-key messages stay hidden until you
// re-check the safety code and accept. New members joining are announced in the chat.
const who = (id) => (id === current?.creds.member_id ? t("you") : t("Member {id}", { id: id.slice(2, 6) }));
function notice(text) {
  const li = document.createElement("li");
  li.className = "msg sys";
  li.style.cssText = "align-self:center;max-width:92%;text-align:center";
  const b = document.createElement("div");
  b.className = "body";
  b.style.cssText = "background:transparent;border:1px dashed var(--rule);color:var(--muted);font-size:.85rem";
  b.textContent = text;
  li.append(b);
  $("#messages").append(li);
  li.scrollIntoView({ block: "end" });
}
function verifyKeys(info) {
  const c = current, creds = c.creds;
  const seeded = !!creds.pins;
  if (!creds.pins) creds.pins = { [creds.member_id]: creds.me.publicKey };
  const res = checkPins(creds.pins, info.members);
  creds.pins = res.pins;
  remember(creds);
  if (seeded) for (const id of res.added) notice(t("{who} joined. The safety code changed, so compare it again.", { who: who(id) }));
  c.keyAlert = res.changed.length ? res.changed : null;
  showKeyAlert();
}
function showKeyAlert() {
  const c = current;
  let el = document.getElementById("key-alert");
  if (!c?.keyAlert) { if (el) el.hidden = true; return; }
  if (!el) {
    el = document.createElement("div");
    el.id = "key-alert";
    el.className = "waiting";
    el.setAttribute("role", "alert");
    el.style.cssText = "border:1px solid var(--err);background:rgba(251,113,133,.12)";
    $("#waiting").after(el); // inside the header block, so the message list keeps its space
  }
  const self = c.keyAlert.some((x) => x.member_id === c.creds.member_id);
  el.replaceChildren();
  const warnText = document.createElement("p");
  warnText.style.margin = "0 0 8px";
  warnText.textContent = self
    ? t("Security warning: the server is showing a different key for you than the one on this device. Don't use this room. Close it and open a new one.")
    : t("Security warning: the server is now showing a different key for {who}. Sending is paused and their messages under the new key are hidden. Call them and compare the safety code. Only if it matches, trust the new key.", { who: c.keyAlert.map((x) => who(x.member_id)).join(", ") });
  el.append(warnText);
  if (!self) {
    const btn = document.createElement("button");
    btn.className = "btn line small";
    btn.type = "button";
    btn.textContent = t("The codes match: trust the new key");
    btn.addEventListener("click", () => {
      if (!confirm(t("Only do this after comparing the safety code with them over a call or in person. Trust the new key?"))) return;
      for (const x of c.keyAlert) c.creds.pins[x.member_id] = x.shown;
      remember(c.creds);
      notice(t("New key accepted for {who}.", { who: c.keyAlert.map((x) => who(x.member_id)).join(", ") }));
      c.keyAlert = null;
      showKeyAlert();
      c.last = 0; $("#messages").replaceChildren(); poll(); // show their messages again
    });
    el.append(btn);
  }
  el.hidden = false;
}

function gone(err) {
  if (err.status === 404 || err.status === 401) {
    const id = current?.creds.room_id;
    stop();
    if (id) forget(id);
    show("closed");
  } else status(err.message, "err");
}

async function poll() {
  if (!current) return;
  const c = current;
  try {
    const r = await api(fetch, "GET", `/v1/rooms/${c.creds.room_id}/messages?after=${c.last}`, null, c.creds.token);
    for (const m of r.messages) await render(m);
    c.last = r.last_seq;
  } catch (err) {
    gone(err);
  }
}

async function render(m) {
  const c = current;
  let text, name, photo = null, unverified = false;
  try {
    // Only accept a message sealed with the key we have pinned for its sender.
    let expected = m.from === c.creds.member_id ? c.creds.me.publicKey : c.creds.pins?.[m.from];
    if (expected === undefined) { await refreshInfo(); expected = c.creds.pins?.[m.from]; }
    const plain = await open(c.creds.room_id, c.creds.me, c.creds.member_id, m.body, expected ?? null);
    if (plain == null) text = null;
    else {
      try {
        const j = JSON.parse(plain);
        if (j && j.type === "image" && typeof j.blob === "string") { photo = j; name = j.name; text = j.caption || ""; }
        else if (j && typeof j.text === "string") ({ text, name } = j);
        else text = plain;
      } catch {
        text = plain;
      }
    }
  } catch (err) {
    text = undefined;
    unverified = err instanceof SenderKeyMismatch;
  }
  const mine = m.from === c.creds.member_id;
  const li = document.createElement("li");
  li.className = "msg" + (mine ? " mine" : "");
  const who = document.createElement("div");
  who.className = "who";
  who.textContent = `${mine ? t("You") : name || t("Member {id}", { id: m.from.slice(2, 6) })} · ${new Date(m.at).toLocaleTimeString(LOCALE, { hour: "numeric", minute: "2-digit" })}`;
  const body = document.createElement("div");
  body.className = "body";
  if (text === null) { body.textContent = t("Sent before you joined, or not addressed to you."); li.classList.add("dim"); }
  else if (unverified) { body.textContent = t("Hidden: this message wasn't sealed with this member's verified key."); li.classList.add("dim"); }
  else if (text === undefined) { body.textContent = t("Couldn't decrypt this message."); li.classList.add("dim"); }
  else if (photo) body.append(photoCard(photo, mine));
  else body.textContent = text;
  if (photo && text) { const cap = document.createElement("div"); cap.textContent = text; cap.style.marginTop = "6px"; body.append(cap); }
  li.append(who, body);
  $("#messages").append(li);
  li.scrollIntoView({ block: "end" });
}

async function send(e) {
  e.preventDefault();
  const input = $("#msg");
  const text = input.value.trim();
  if (pending && current) return sendPhoto(text);
  if (!text || !current) return;
  if (text.length > MAX_TEXT) return status(t("Messages can be up to {n} characters. Split it into parts.", { n: MAX_TEXT }), "err");
  try {
    await refreshInfo();
    if (current.keyAlert) return status(t("Sending is paused until the key warning above is resolved."), "err");
    const sealed = await seal(current.creds.room_id, current.creds.me, current.info.members, JSON.stringify({ type: "text", text, name: current.creds.name || undefined }));
    await api(fetch, "POST", `/v1/rooms/${current.creds.room_id}/messages`, { body: sealed }, current.creds.token);
    input.value = "";
    await poll();
  } catch (err) {
    status(err.message.includes("public key") ? t("Nobody else is in the room yet. Share the invite link first.") : err.message, "err");
  }
}


async function closeRoom() {
  if (!confirm(t("Close the room for everyone and delete all messages? This can't be undone."))) return;
  try {
    await api(fetch, "DELETE", `/v1/rooms/${current.creds.room_id}`, null, current.creds.token);
  } catch {}
  const id = current.creds.room_id;
  stop();
  forget(id);
  location.hash = "";
}

function forgetHere() {
  if (!confirm(t("Remove this room's keys from this device? You won't be able to read or rejoin it here. The room stays open for the others."))) return;
  const id = current.creds.room_id;
  stop();
  forget(id);
  location.hash = "";
}

async function report() {
  const reason = prompt(t("What's wrong in this room? (5–2000 characters)"));
  if (!reason || reason.length < 5) return;
  try {
    await api(fetch, "POST", `/v1/rooms/${current.creds.room_id}/report`, { reason }, current.creds.token);
    status(t("Report sent. Thank you."), "ok");
  } catch (err) {
    status(err.message, "err");
  }
}

// ---- photos: encrypted on device, view once, never saved -------------------------------
let pending = null; // { bytes, w, h }
const MAX_SIDE = 1600;

async function preparePhoto(file) {
  if (!file || !/^image\//.test(file.type)) return status(t("Pick a photo (JPG, PNG, HEIC, WebP…)."), "err");
  try {
    status(t("Preparing photo…"));
    const bmp = await createImageBitmap(file, { imageOrientation: "from-image" });
    const k = Math.min(1, MAX_SIDE / Math.max(bmp.width, bmp.height));
    const w = Math.round(bmp.width * k), h = Math.round(bmp.height * k);
    const cv = document.createElement("canvas");
    cv.width = w; cv.height = h;
    cv.getContext("2d").drawImage(bmp, 0, 0, w, h);
    // Re-encoding through a canvas drops ALL hidden data: GPS location, camera, date, etc.
    const blob = await new Promise((res) => cv.toBlob(res, "image/jpeg", 0.82));
    const bytes = new Uint8Array(await blob.arrayBuffer());
    const thumb = $("#attach-thumb"), tk = 64 / h;
    thumb.width = Math.max(1, Math.round(w * tk)); thumb.height = 64;
    thumb.getContext("2d").drawImage(bmp, 0, 0, thumb.width, thumb.height);
    bmp.close();
    cv.width = cv.height = 0;
    if (bytes.length > 2.9 * 1024 * 1024) return status(t("That photo is too large even after shrinking. Try another."), "err");
    discardPhoto();
    pending = { bytes, w, h };
    $("#attach").hidden = false;
    status("");
    $("#msg").placeholder = t("Add a caption (optional), then Send");
  } catch {
    status(t("Couldn't read that photo. Try a JPG or PNG."), "err");
  }
}
function discardPhoto() {
  if (pending) pending.bytes.fill(0);
  pending = null;
  $("#attach").hidden = true;
  const thumb = $("#attach-thumb"); thumb.width = thumb.height = 1;
  $("#msg").placeholder = t("Message (Enter to send)");
}

async function sendPhoto(caption) {
  const c = current, p = pending;
  if (caption.length > 500) return status(t("Captions can be up to 500 characters."), "err");
  try {
    await refreshInfo();
    if (c.keyAlert) throw new Error(t("Sending is paused until the key warning above is resolved."));
    if (!c.info.members.some((m) => m.public_key && m.member_id !== c.creds.member_id)) throw new Error(t("Nobody else is in the room yet. Share the invite link first."));
    status(t("Encrypting photo…"));
    const once = $("#once").checked;
    const enc = await encryptBlob(p.bytes);
    const r = await fetch(`/v1/rooms/${c.creds.room_id}/blobs${once ? "?once=1" : ""}`, { method: "POST", headers: { "content-type": "application/octet-stream", authorization: `Bearer ${c.creds.token}` }, body: enc.data });
    const j = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(j.error || t("Upload failed ({code})", { code: r.status }));
    const msg = { type: "image", blob: j.blob_id, key: enc.key, iv: enc.iv, w: p.w, h: p.h, once, caption: caption || undefined, name: c.creds.name || undefined };
    const sealed = await seal(c.creds.room_id, c.creds.me, c.info.members, JSON.stringify(msg));
    await api(fetch, "POST", `/v1/rooms/${c.creds.room_id}/messages`, { body: sealed }, c.creds.token);
    enc.data.fill(0);
    discardPhoto();
    $("#msg").value = "";
    status("");
    await poll();
  } catch (err) {
    status(err.message, "err");
  }
}

const openedSet = () => new Set(current?.creds.opened || []);
function markOpened(blobId) {
  const c = current;
  if (!c) return;
  c.creds.opened = [...openedSet(), blobId].slice(-500);
  store.set(roomKey(c.creds.room_id), c.creds);
}

function photoCard(p, mine) {
  const b = document.createElement("button");
  b.type = "button";
  b.className = "photo-card";
  const ico = document.createElement("span"); ico.className = "ico"; ico.textContent = "📷";
  const label = document.createElement("span");
  b.append(ico, label);
  const set = (txt, disabled) => { label.textContent = txt; b.disabled = !!disabled; };
  if (p.once && mine) set(t("Photo sent · view once"), true);
  else if (p.once && openedSet().has(p.blob)) set(t("Photo · opened"), true);
  else set(p.once ? t("Tap to view photo · view once") : t("Tap to view photo"));
  b.addEventListener("click", () => viewPhoto(p, set));
  return b;
}

let viewing = null;
async function viewPhoto(p, setCard) {
  const c = current;
  if (!c || viewing) return;
  let bytes = null, bmp = null;
  try {
    status(t("Opening photo…"));
    const r = await fetch(`/v1/rooms/${c.creds.room_id}/blobs/${encodeURIComponent(p.blob)}`, { headers: { authorization: `Bearer ${c.creds.token}` }, cache: "no-store" });
    if (p.once) markOpened(p.blob); // one chance, even if this view fails
    if (!r.ok) {
      const j = await r.json().catch(() => ({}));
      setCard(r.status === 410 ? t("Photo · gone") : t("Photo unavailable"), true);
      return status(j.error || t("This photo is gone."), "err");
    }
    const data = new Uint8Array(await r.arrayBuffer());
    bytes = await decryptBlob(data, p.key, p.iv);
    data.fill(0);
    bmp = await createImageBitmap(new Blob([bytes], { type: "image/jpeg" }));
    bytes.fill(0);
    status("");
  } catch {
    if (bytes) bytes.fill(0);
    if (p.once) setCard(t("Photo · opened"), true);
    return status(t("Couldn't decrypt this photo."), "err");
  }
  const cv = $("#viewer-canvas");
  cv.width = bmp.width; cv.height = bmp.height;
  cv.getContext("2d").drawImage(bmp, 0, 0);
  bmp.close();
  $("#viewer").hidden = false;
  let left = 10;
  const info = () => { $("#viewer-info").innerHTML = ""; const s1 = document.createElement("span"); s1.textContent = p.once ? t("View once · closes in ") : t("Photo · not saved anywhere"); $("#viewer-info").append(s1); if (p.once) { const n = document.createElement("span"); n.className = "count"; n.textContent = left + "s"; $("#viewer-info").append(n); } };
  info();
  viewing = { once: p.once, timer: p.once ? setInterval(() => { left--; if (left <= 0) closeViewer(); else info(); }, 1000) : null };
  if (p.once) setCard(t("Photo · opened"), true);
}
function closeViewer() {
  if (!viewing) return;
  clearInterval(viewing.timer);
  const cv = $("#viewer-canvas");
  const ctx = cv.getContext("2d");
  ctx.clearRect(0, 0, cv.width, cv.height);
  cv.width = cv.height = 1; // releases the pixels
  $("#viewer").hidden = true;
  viewing = null;
}

// ---- voice typing: on-device speech-to-text --------------------------------------------
let voiceWorker = null, rec = null, recTimer = null, voiceSeq = 0;
const voiceWaiting = new Map();
const vstatus = (msg) => { $("#voice-status").textContent = msg || ""; };

function startWorker() {
  if (voiceWorker) return voiceWorker;
  voiceWorker = new Worker("/voice/worker.js", { type: "module" });
  voiceWorker.onmessage = (e) => {
    const m = e.data;
    if (m.type === "progress") vstatus(t("Downloading voice model (one time): {pct}%", { pct: m.pct }));
    else if (m.type === "ready") { if (!rec) vstatus(""); try { localStorage.setItem("sup.voice.ready", "1"); } catch {} }
    else if (m.type === "text" || m.type === "error") { const cb = voiceWaiting.get(m.id); voiceWaiting.delete(m.id); cb?.(m); }
  };
  voiceWorker.onerror = () => vstatus(t("Voice typing isn't available in this browser."));
  voiceWorker.postMessage({ type: "load" });
  return voiceWorker;
}

async function toggleMic() {
  if (rec) { rec.stop(); return; }
  let ok = false;
  try { ok = localStorage.getItem("sup.voice.ok") === "1"; } catch {}
  if (!ok) {
    if (!confirm(t("Voice typing turns speech into text right here on your device. Your voice is never uploaded.\n\nThe first time, it downloads a speech model (about 65 MB) from our server. After that it works instantly.\n\nTurn it on?"))) return;
    try { localStorage.setItem("sup.voice.ok", "1"); } catch {}
  }
  startWorker();
  let stream;
  try {
    stream = await navigator.mediaDevices.getUserMedia({ audio: { channelCount: 1, echoCancellation: true, noiseSuppression: true } });
  } catch {
    return vstatus(t("Microphone blocked. Allow it in your browser's site settings."));
  }
  const chunks = [];
  rec = new MediaRecorder(stream);
  rec.ondataavailable = (e) => e.data.size && chunks.push(e.data);
  rec.onstop = async () => {
    stream.getTracks().forEach((tr) => tr.stop());
    clearInterval(recTimer);
    rec = null;
    $("#mic-btn").classList.remove("rec");
    $("#mic-btn").setAttribute("aria-label", t("Voice typing"));
    vstatus(t("Turning speech into text on this device…"));
    try {
      const buf = await new Blob(chunks, { type: chunks[0]?.type }).arrayBuffer();
      chunks.length = 0;
      const ac = new AudioContext({ sampleRate: 16000 });
      const audio = (await ac.decodeAudioData(buf)).getChannelData(0).slice();
      ac.close();
      const id = ++voiceSeq;
      const res = await new Promise((resolve) => { voiceWaiting.set(id, resolve); voiceWorker.postMessage({ type: "transcribe", id, audio }, [audio.buffer]); });
      if (res.type === "error") throw new Error(res.error);
      const words = res.text.replace(/\s*\[(BLANK_AUDIO|MUSIC|NOISE)\]\s*/gi, " ").trim();
      if (!words) return vstatus(t("Didn't catch that. Try again a little closer to the mic."));
      const box = $("#msg");
      box.value = (box.value.trim() ? box.value.trim() + " " : "") + words;
      box.focus();
      vstatus(t("Check the text, then press Send."));
      setTimeout(() => vstatus(""), 4000);
    } catch {
      vstatus(t("Couldn't turn that into text. Try again."));
    }
  };
  rec.start();
  const t0 = Date.now();
  $("#mic-btn").classList.add("rec");
  $("#mic-btn").setAttribute("aria-label", t("Stop recording"));
  const tick = () => { const s2 = Math.floor((Date.now() - t0) / 1000); vstatus(t("Listening… {time} · tap the mic again to finish", { time: `${Math.floor(s2 / 60)}:${String(s2 % 60).padStart(2, "0")}` })); if (s2 >= 60) rec?.stop(); };
  tick();
  recTimer = setInterval(tick, 500);
}

async function voiceAvailable() {
  if (!(window.Worker && window.MediaRecorder && navigator.mediaDevices?.getUserMedia && window.WebAssembly && window.AudioContext)) return false;
  try { return (await fetch("/voice/lib/transformers.min.js", { method: "HEAD" })).ok; } catch { return false; }
}

// ---- landing -------------------------------------------------------------------
function renderMyRooms() {
  const list = $("#my-rooms");
  list.replaceChildren();
  const ids = myRooms().filter((id) => store.get(roomKey(id)));
  $("#my-rooms-wrap").hidden = !ids.length;
  for (const id of ids) {
    const c = store.get(roomKey(id));
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = `#room=${id}`;
    a.textContent = c.label || t("Private room");
    const s = document.createElement("span");
    s.textContent = c.owner ? t("owner") : t("member");
    li.append(a, s);
    list.append(li);
  }
}

function route() {
  status("");
  const h = new URLSearchParams(location.hash.slice(1));
  if (h.get("room")) return enterRoom(h.get("room"));
  stop();
  if (h.get("join")) {
    return show("join");
  }
  renderMyRooms();
  show("home");
}

async function main() {
  health = await (await fetch("/health")).json();
  if (!health.rooms) { show("off"); return; }
  document.querySelectorAll("[data-price]").forEach((el) => (el.textContent = health.room_prices[el.dataset.price] || ""));
  if (health.notice) { $("#site-notice").textContent = health.notice; $("#site-notice").hidden = false; }
  const open = health.open || {};
  if (open.new_rooms === false) { $("#pass-buy").disabled = true; $("#open-btn").disabled = true; $("#open-btn").title = t("New rooms are paused for a moment"); }
  if (open.trials === false || open.new_rooms === false) { $("#trial-btn").disabled = true; $("#trial-btn").title = t("Free trials are paused for a moment"); }
  if (open.joins === false) { $("#join-btn").disabled = true; $("#join-btn").title = t("Joining is paused for a moment"); }
  $("#net").textContent = health.payments ? (health.mainnet ? t("USDC on Base") : t("Test USDC on Base Sepolia")) : t("Local test mode: payments off");
  if (!globalThis.crypto?.subtle) { status(t("This browser can't do the encryption this needs. Use a current Chrome, Edge, Firefox or Safari over https."), "err"); return; }
  try { await generateIdentity(); } catch { status(t("This browser doesn't support X25519 encryption yet. Update it, or use current Chrome, Edge, Firefox or Safari."), "err"); return; }
  $("#open-form").addEventListener("submit", openRoom);
  $("#trial-btn").addEventListener("click", openTrial);
  $("#join-form").addEventListener("submit", joinRoom);
  $("#send-form").addEventListener("submit", send);
  $("#close-btn").addEventListener("click", closeRoom);
  $("#report-btn").addEventListener("click", report);
  $("#forget-btn").addEventListener("click", forgetHere);
  $("#pass-buy").addEventListener("click", () => buyPass("pro"));
  $("#pass-renew").addEventListener("click", renewPass);
  $("#pass-show").addEventListener("click", () => showKey(false));
  $("#pass-cal").addEventListener("click", downloadReminder);
  $("#renew-warn-btn").addEventListener("click", renewPass);
  $("#room-renew-btn").addEventListener("click", async () => { await renewPass(); refreshInfo(); });
  $("#pass-add").addEventListener("click", () => showKey(true));
  $("#pass-key-save").addEventListener("click", savePassKey);
  $("#pass-remove").addEventListener("click", () => {
    if (!confirm(t("Remove the pass key from this browser? Your pass keeps working anywhere you add the key again. Without a saved copy of the key, you can't get it back."))) return;
    store.del("sup.pass"); $("#pass-key-box").hidden = true; $("#pass-key-note").hidden = true; renderPass();
  });
  refreshPass();
  $("#photo-btn").addEventListener("click", () => $("#photo-input").click());
  $("#photo-input").addEventListener("change", (e) => { const f = e.target.files[0]; e.target.value = ""; preparePhoto(f); });
  $("#attach-cancel").addEventListener("click", discardPhoto);
  $("#viewer-close").addEventListener("click", closeViewer);
  $("#viewer").addEventListener("contextmenu", (e) => e.preventDefault());
  // A view-once photo closes the moment you leave the page or switch apps.
  document.addEventListener("visibilitychange", () => { if (document.hidden && viewing?.once) closeViewer(); });
  window.addEventListener("blur", () => { if (viewing?.once) closeViewer(); });
  document.addEventListener("keydown", (e) => { if (e.key === "Escape") closeViewer(); });
  $("#mic-btn").addEventListener("click", toggleMic);
  voiceAvailable().then((ok) => { $("#mic-btn").hidden = !ok; });
  $("#forget-all").addEventListener("click", () => {
    if (!confirm(t("Erase every room key stored in this browser? Rooms stay open for other members, but you lose access to them here."))) return;
    forgetAll();
    renderMyRooms();
    status(t("All room keys erased from this browser."), "ok");
  });
  $("#copy-invite").addEventListener("click", async () => {
    const v = $("#invite-link").value;
    try { await navigator.clipboard.writeText(v); status(t("Invite link copied."), "ok"); } catch { $("#invite-link").select(); status(t("Select and copy the link."), ""); }
  });
  $("#msg").addEventListener("keydown", (e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); $("#send-form").requestSubmit(); } });
  window.addEventListener("hashchange", route);
  route();
}

main().catch((e) => status(t("Couldn't reach the server: {error}", { error: e.message }), "err"));
