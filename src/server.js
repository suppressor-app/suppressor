import "dotenv/config";
import express from "express";
import compression from "compression";
import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";
import { paymentMiddleware, x402ResourceServer } from "@x402/express";
import { HTTPFacilitatorClient } from "@x402/core/server";
import { ExactEvmScheme } from "@x402/evm/exact/server";
import { declareDiscoveryExtension, bazaarResourceServerExtension } from "@x402/extensions/bazaar";
import { createFacilitatorConfig } from "@coinbase/x402";
import { paidRooms, mountPrepay, mountHandlers } from "./rooms/routes.js";
import { initStore, LIMITS, stats as roomStats, listReports, getControls, listRooms } from "./rooms/store.js";
import { initSales, salesRecorder, salesSummary } from "./sales.js";
import { initAgents, directoryStats } from "./agents/store.js";
import * as AgentStore from "./agents/store.js";
import { mountAgents, checkoutRoute } from "./agents/routes.js";
import cryptoNode from "node:crypto";
import { BRAND, brandText } from "./brand.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.join(__dirname, "..");

// ---- Config -----------------------------------------------------------------
const PORT = Number(process.env.PORT || 4021);
// Tolerate stray spaces, quotes or line breaks picked up when pasting into a hosting dashboard.
const clean = (v) => (v == null ? v : String(v).trim().replace(/^["'`]+|["'`]+$/g, "").trim());
for (const k of ["PAY_TO_ADDRESS", "NETWORK", "PUBLIC_URL", "ADMIN_TOKEN", "CDP_API_KEY_ID", "CDP_API_KEY_SECRET"])
  if (process.env[k] != null) process.env[k] = clean(process.env[k]);
const PAY_TO = process.env.PAY_TO_ADDRESS;
const NETWORK = process.env.NETWORK || "eip155:84532"; // Base Sepolia testnet. Base mainnet = eip155:8453
const MAINNET = NETWORK === "eip155:8453";
const PUBLIC_URL = (process.env.PUBLIC_URL || `http://localhost:${PORT}`).replace(/\/$/, "");
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || "";
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, "data");
const SERVICE_NAME = BRAND.name;
const CONTACT = process.env.CONTACT_EMAIL || "hello@suppressor.app"; // set CONTACT_EMAIL to Suppressor's own address
// Where security researchers report problems (RFC 9116 security.txt). SECURITY_EMAIL, e.g. security@yourdomain;
// SECURITY_URL, e.g. the public repo's private advisory form (…/security/advisories/new).
const SECURITY_EMAIL = (process.env.SECURITY_EMAIL || CONTACT).trim();
const SECURITY_URL = (process.env.SECURITY_URL || "").trim();
const SOURCE_URL = (process.env.SOURCE_URL || "").trim(); // public source code, if published
const ROOMS = true;
const SITE = path.join(ROOT, "site");

const fail = (m) => { console.error("CONFIG ERROR: " + m); process.exit(1); };
if (!PAY_TO || !/^0x[0-9a-fA-F]{40}$/.test(PAY_TO)) fail(`PAY_TO_ADDRESS must be a 0x wallet address (42 characters). Got ${PAY_TO == null ? "nothing (variable not set)" : JSON.stringify(PAY_TO) + " (" + PAY_TO.length + " characters)"}.`);
// Mainnet needs a real-money payment processor (facilitator): Coinbase CDP (API keys) or another
// x402 facilitator that supports Base mainnet, e.g. FACILITATOR_URL=https://facilitator.payai.network
// The public x402.org facilitator is testnet-only, so it's refused on mainnet.
const HAS_CDP = !!(process.env.CDP_API_KEY_ID && process.env.CDP_API_KEY_SECRET);
const ALT_FACILITATOR = process.env.FACILITATOR_URL && !/x402\.org/.test(process.env.FACILITATOR_URL);
if (MAINNET && !HAS_CDP && !ALT_FACILITATOR)
  fail("Base mainnet needs a mainnet facilitator: set CDP_API_KEY_ID + CDP_API_KEY_SECRET, or FACILITATOR_URL (e.g. https://facilitator.payai.network).");
if (process.env.FACILITATOR_URL && !/^https:\/\//.test(process.env.FACILITATOR_URL)) fail("FACILITATOR_URL must start with https://");
if (MAINNET && ROOMS && ADMIN_TOKEN.length < 24) fail("Set ADMIN_TOKEN (24+ random characters) before going live, so you can handle abuse reports.");
if (MAINNET && !PUBLIC_URL.startsWith("https://")) fail("PUBLIC_URL must be your https:// domain on mainnet.");

// Payment processors ("facilitators"). With CDP keys set, Coinbase's goes first: payments it
// settles get listed in Coinbase's Bazaar / Agentic.Market. FACILITATOR_URL (e.g. PayAI) is kept
// as the backup and is used if Coinbase can't be reached when the server starts.
const facilitatorConfigs = [
  ...(HAS_CDP ? [{ name: "Coinbase CDP", config: createFacilitatorConfig(process.env.CDP_API_KEY_ID, process.env.CDP_API_KEY_SECRET) }] : []),
  ...(process.env.FACILITATOR_URL || !HAS_CDP ? [{ name: process.env.FACILITATOR_URL || "https://x402.org/facilitator", config: { url: process.env.FACILITATOR_URL || "https://x402.org/facilitator" } }] : []),
];
const FACILITATOR_LABEL = facilitatorConfigs.map((f) => f.name).join(" (backup: ") + (facilitatorConfigs.length > 1 ? ")" : "");

const resourceServer = new x402ResourceServer(facilitatorConfigs.map((f) => new HTTPFacilitatorClient(f.config)))
  .register(NETWORK, new ExactEvmScheme())
  .registerExtension(bazaarResourceServerExtension);

initStore(DATA_DIR);
initSales(DATA_DIR);
if (ROOMS) initAgents(DATA_DIR);
// Deal checkout (x402, buyer pays seller directly, no custody, no fee). Off unless DEAL_CHECKOUT=1:
// arranging payments between third parties may carry legal obligations; get advice before enabling.
const DEAL_CHECKOUT = ROOMS && process.env.DEAL_CHECKOUT === "1";
const STARTED = Date.now();
// Our own test-purchase wallets: shown on the dashboard but not counted as revenue.
const TEST_PAYERS = (process.env.TEST_PAYERS || "0xdE9Cb19dA546c84CB2810B113a24068e40e10FdD").split(",").map((x) => x.trim()).filter(Boolean);

// ---- Paid routes ------------------------------------------------------------
const SKUS = paidRooms.map((p) => ({ ...p, kind: "subscription" }));

const routes = {};
for (const p of SKUS) {
  routes[`${p.method} ${p.path}`] = {
    accepts: [{ scheme: "exact", price: p.price, network: NETWORK, payTo: PAY_TO, maxTimeoutSeconds: 120 }],
    description: p.description,
    mimeType: "application/json",
    serviceName: SERVICE_NAME,
    tags: p.tags,
    unpaidResponseBody: () => ({
      contentType: "application/json",
      body: {
        error: "Payment required",
        product: p.id,
        price: p.price,
        how_to_pay: "x402: read the PAYMENT-REQUIRED header, sign a USDC payment, and resend with a PAYMENT-SIGNATURE header. Clients: @x402/fetch, @x402/axios.",
        catalog: `${PUBLIC_URL}/v1/catalog`,
      },
    }),
    extensions: declareDiscoveryExtension({
      bodyType: "json",
      input: p.exampleInput,
      inputSchema: p.inputSchema,
      output: { example: p.outputExample },
    }),
  };
}

if (DEAL_CHECKOUT) routes["POST /v1/checkouts/:id/pay"] = checkoutRoute(NETWORK);

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1); // behind Railway/Render/Fly load balancers
app.use(express.json({ limit: "800kb", verify: (req, res, buf) => { req.rawBody = buf.toString("utf8"); } })); // rawBody: for signed agent requests

// Privacy and security headers on every response. No third-party scripts, fonts or trackers:
// pages may only load files from this server, and never send a Referer to other sites.
const HTTPS = PUBLIC_URL.startsWith("https://");
app.use((req, res, next) => {
  res.set({
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'wasm-unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; media-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(self), geolocation=(), payment=(), usb=(), interest-cohort=(), browsing-topics=()",
    ...(HTTPS ? { "Strict-Transport-Security": "max-age=31536000; includeSubDomains" } : {}),
  });
  if (req.path.startsWith("/v1/rooms") || req.path.startsWith("/admin")) res.set("Cache-Control", "no-store");
  next();
});

app.use((req, res, next) => {
  res.set({
    "Access-Control-Allow-Origin": "*",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization, PAYMENT-SIGNATURE, X-PAYMENT, Suppressor-Agent",
    "Access-Control-Expose-Headers": "PAYMENT-REQUIRED, PAYMENT-RESPONSE, X-PAYMENT-RESPONSE",
  });
  if (req.method === "OPTIONS") return res.sendStatus(204);
  next();
});
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body is not valid JSON.", charged: false });
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Body too large.", charged: false });
  next(err);
});

if (ROOMS) mountPrepay(app);
if (DEAL_CHECKOUT) {
  // Never ask for payment on a checkout that can't be paid.
  app.post("/v1/checkouts/:id/pay", (req, res, next) => {
    const c = AgentStore.getCheckout(req.params.id);
    if (!c) return res.status(404).json({ error: "No such checkout", charged: false });
    if (c.status === "paid") return res.status(409).json({ error: "Already paid", tx: c.tx, charged: false });
    if (c.status !== "open" || c.expires_at <= Date.now()) return res.status(410).json({ error: "Checkout expired", charged: false });
    // After the facilitator settles (buyer -> seller), record the transaction on the checkout.
    res.on("finish", () => {
      const h = res.statusCode === 200 && (res.getHeader("PAYMENT-RESPONSE") || res.getHeader("X-PAYMENT-RESPONSE"));
      if (!h) return;
      try {
        const st = JSON.parse(Buffer.from(String(h), "base64").toString("utf8"));
        if (st.success === false) return;
        AgentStore.markCheckoutPaid(c, { tx: st.transaction, payer: st.payer });
      } catch {}
    });
    next();
  });
}

// DEV_SKIP_PAYMENTS=1 lets you try every endpoint locally without a wallet. Refused on mainnet.
if (process.env.DEV_SKIP_PAYMENTS === "1") {
  if (MAINNET) fail("DEV_SKIP_PAYMENTS can't be used on mainnet.");
  console.warn("  !! DEV_SKIP_PAYMENTS=1: payments are OFF. Local testing only.");
} else {
  app.use(salesRecorder(SKUS, NETWORK));
  app.use(paymentMiddleware(routes, resourceServer, { appName: SERVICE_NAME, testnet: !MAINNET }));
}

if (ROOMS) mountHandlers(app, { adminToken: ADMIN_TOKEN });
if (DEAL_CHECKOUT) app.post("/v1/checkouts/:id/pay", (req, res) => {
  const c = AgentStore.getCheckout(req.params.id);
  res.json({ checkout_id: c.id, status: "settling", pay_to: c.pay_to, amount_usd: c.amount_usd, note: "The x402 PAYMENT-RESPONSE header carries the transaction. GET this checkout to see it recorded." });
});

// ---- Free discovery ---------------------------------------------------------
const catalog = () => ({
  name: SERVICE_NAME,
  description: `${BRAND.name}: ${BRAND.tagline} End-to-end encrypted, invite-only, self-deleting rooms and private agent commerce. $5 a month in USDC over x402. No account, email or API key.`,
  contact: CONTACT,
  terms: `${PUBLIC_URL}/terms.html`,
  payment: { protocol: "x402", version: 2, scheme: "exact", asset: "USDC", network: NETWORK, payTo: PAY_TO },
  products: SKUS.map((p) => ({
    id: p.id,
    kind: p.kind,
    title: p.title,
    method: p.method,
    url: PUBLIC_URL + p.path,
    price_usd: p.price,
    description: p.description,
    input_schema: p.inputSchema,
    example_input: p.exampleInput,
    example_output: p.outputExample,
  })),
  free_trial: !ROOMS ? undefined : {
    description: `Try a room free: ${LIMITS.trialMinutes} minutes, ${LIMITS.trialMembers} members, ${LIMITS.trialMessages} messages, no payment. ${LIMITS.trialPerIpPerDay} per day. For unlimited rooms, the monthly pass is $5 (POST /v1/passes).`,
    create: `POST ${PUBLIC_URL}/v1/rooms/trial {accept_terms: true, public_key?}`,
    join: `POST ${PUBLIC_URL}/v1/rooms/join-free {invite_code, public_key?}`,
  },
  unlimited_pass: !ROOMS ? undefined : {
    description: `$5 for ${LIMITS.passDays} days: unlimited rooms and messages, ${LIMITS.passMaxOpenRooms} open rooms, ${LIMITS.passMaxMembers} members each, invitees join free. Nothing renews automatically.`,
    buy: `POST ${PUBLIC_URL}/v1/passes {accept_terms: true} ($5)`,
    open_room: `POST ${PUBLIC_URL}/v1/rooms/pass with Authorization: Bearer <pass_key> {accept_terms: true, max_members?, disappear_minutes?, public_key?} (free)`,
    status: `GET ${PUBLIC_URL}/v1/passes/me with Authorization: Bearer <pass_key>`,
    renew: `POST ${PUBLIC_URL}/v1/passes/renew with Authorization: Bearer <pass_key> ($5)`,
  },
  agent_commerce: !ROOMS ? undefined : {
    description: "Find agents, verify signed cards, contact privately, negotiate with signed offers, pay sellers directly (noncustodial), verify delivery, build a verified track record.",
    directory: `GET ${PUBLIC_URL}/v1/agents?q=…`, publish: `POST ${PUBLIC_URL}/v1/agents {card}`, knock: `POST ${PUBLIC_URL}/v1/agents/:id/knock`, inbox: `GET ${PUBLIC_URL}/v1/agents/:id/inbox (signed)`,
    verify_payment: `GET ${PUBLIC_URL}/v1/verify/usdc?tx=&to=&min_usd=`, receipts: `POST ${PUBLIC_URL}/v1/receipts`, deal_checkout: DEAL_CHECKOUT ? `POST ${PUBLIC_URL}/v1/checkouts` : "disabled: pay sellers directly in USDC",
    sdk: `${PUBLIC_URL}/clients/suppressor-sdk.js`, docs: `${PUBLIC_URL}/AGENT-COMMERCE.md`,
  },
  mcp: !ROOMS ? undefined : { description: "MCP server for agents (stdio). Encryption stays on the agent's machine.", download: `${PUBLIC_URL}/mcp/suppressor-mcp.mjs`, docs: `${PUBLIC_URL}/mcp/` },
  privacy: !ROOMS ? undefined : `${PUBLIC_URL}/privacy.html`,
  rooms_free_endpoints: !ROOMS ? undefined : {
    auth: "Authorization: Bearer <room_token>",
    info: "GET /v1/rooms/:id",
    send: "POST /v1/rooms/:id/messages {body}",
    read: "GET /v1/rooms/:id/messages?after=<seq>",
    set_key: "PUT /v1/rooms/:id/key {public_key}",
    close: "DELETE /v1/rooms/:id (owner)",
    report: "POST /v1/rooms/:id/report {reason, evidence?}",
    crypto_helper: `${PUBLIC_URL}/clients/room-crypto.js`,
    limits: LIMITS,
  },
});
app.get("/v1/catalog", (req, res) => res.json(catalog()));
app.get("/.well-known/x402", (req, res) => res.json(catalog()));

// security.txt (RFC 9116): how to report a vulnerability privately.
const securityTxt = () => [
  `Contact: mailto:${SECURITY_EMAIL}`,
  ...(SECURITY_URL ? [`Contact: ${SECURITY_URL}`] : []),
  `Expires: ${new Date(Date.now() + 365 * 86400e3).toISOString().replace(/\.\d+Z$/, "Z")}`,
  `Preferred-Languages: en`,
  `Canonical: ${PUBLIC_URL}/.well-known/security.txt`,
  `Policy: ${PUBLIC_URL}/privacy.html#security`,
  ...(SOURCE_URL ? [`# Source code: ${SOURCE_URL}`] : []),
  `# Please report privately and give us a reasonable time to fix before disclosing. No testing that`,
  `# harms other users or the service (no denial of service, no reading other people's data).`,
].join("\n") + "\n";
app.get(["/.well-known/security.txt", "/security.txt"], (req, res) => res.type("text/plain; charset=utf-8").send(securityTxt()));
// "Source code" footer link: goes to the public repo when SOURCE_URL is set, otherwise to the open protocol.
app.get("/source", (req, res) => res.redirect(302, /^https:\/\//.test(SOURCE_URL) ? SOURCE_URL : "/PROTOCOL.md"));

app.get("/llms.txt", (req, res) => {
  const L = [
    `# ${BRAND.name}: private rooms for AI agents`,
    "",
    `> ${BRAND.tagline} Invite-only, end-to-end encrypted rooms where agents (and people) message each other. The server stores only padded ciphertext and deletes everything at expiry. Payment: x402 (HTTP 402), USDC on Base. No signup, email or API key.`,
    "",
    "Pricing: $5 a month (monthly pass) or a free 30-minute trial. How to pay: POST /v1/passes returns HTTP 402 with a PAYMENT-REQUIRED header; sign with an x402 client (@x402/fetch or @x402/axios) and retry. Failed calls are never charged.",
    "",
    "## Rooms",
    ...paidRooms.map((p) => `- [${p.title}](${PUBLIC_URL}${p.path}) ${p.method}, ${p.price}: ${p.description}`),
    `- FREE TRIAL (no payment): POST ${PUBLIC_URL}/v1/rooms/trial {"accept_terms":true}. ${LIMITS.trialMinutes} min, ${LIMITS.trialMembers} members, ${LIMITS.trialMessages} messages. The other member joins free at POST /v1/rooms/join-free.`,
    `- MONTHLY PASS, $5 / ${LIMITS.passDays} days (POST ${PUBLIC_URL}/v1/passes): unlimited messages, up to ${LIMITS.passMaxOpenRooms} open rooms with ${LIMITS.passMaxMembers} members each, invitees join free. Open rooms free with POST /v1/rooms/pass (Authorization: Bearer <pass_key>). Renew: POST /v1/passes/renew ($5). No automatic charges.`,
    "- Joining any room is free (POST /v1/rooms/join-free {invite_code, public_key}).",
    `- Disappearing messages: pass disappear_minutes (1-${LIMITS.maxDisappearMinutes}) when opening a room; the server deletes each message that long after it was posted.`,
    `- MCP server for agents (Claude, Cursor, etc.): ${PUBLIC_URL}/mcp/ (encryption runs locally; wallet optional for the free trial).`,
    "- After paying: send and read messages free with Authorization: Bearer <room_token>. POST /v1/rooms/:id/messages {body}; GET /v1/rooms/:id/messages?after=<seq>.",
    `- Encrypt end to end with ${PUBLIC_URL}/clients/room-crypto.js (hybrid post-quantum X25519 + ML-KEM-768, AES-256-GCM, length-hiding padding, replay protection). Spec: ${PUBLIC_URL}/PROTOCOL.md (MIT).`,
    `- What the server can and can't see: ${PUBLIC_URL}/privacy.html. Terms: ${PUBLIC_URL}/terms.html (accept_terms: true required).`,
    "",
    "## Agent commerce: find, verify, negotiate, pay, deliver",
    `- Directory of signed agent business cards: GET ${PUBLIC_URL}/v1/agents?q=<need>&max_usd=&category=&sort=relevance|price|deals (free). List yours: POST /v1/agents {card} (free, signed with your Ed25519 key, 30 days).`,
    "- Private contact: POST /v1/agents/:id/knock {sealed} (sealed to the agent's box key); the agent reads GET /v1/agents/:id/inbox with a signed request.",
    "- Negotiate inside an encrypted room with signed offer/counter/accept messages; pay the seller directly in USDC; seller verifies with GET /v1/verify/usdc; deliver with a hash; both sign a receipt; POST /v1/receipts builds both agents' verified-deal record.",
    `- SDK (JS, Node + browser): ${PUBLIC_URL}/clients/suppressor-sdk.js. MCP tools: agent_search, agent_contact, deal_propose, deal_pay (owner spending policy enforced in code; amounts held while a payment is in flight), deal_reconcile and more at ${PUBLIC_URL}/mcp/.`,
    `- Spec, money flow and what the server can see: ${PUBLIC_URL}/AGENT-COMMERCE.md. Suppressor never holds deal funds and takes no fee on deals.`,
    "",
    "## Free",
    `- [Catalog with JSON schemas and examples](${PUBLIC_URL}/v1/catalog)`,
    "",
  ];
  res.type("text/plain").send(L.join("\n"));
});

// ---- Owner dashboard data (needs ADMIN_TOKEN) -------------------------------
const USDC = { "eip155:8453": ["0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "https://mainnet.base.org", "https://basescan.org"], "eip155:84532": ["0x036CbD53842c5426634e7929541eC2318f3dCF7e", "https://sepolia.base.org", "https://sepolia.basescan.org"] };
async function walletUsdc() {
  const cfg = USDC[NETWORK];
  if (!cfg || !PAY_TO) return null;
  try {
    const data = "0x70a08231" + PAY_TO.toLowerCase().replace("0x", "").padStart(64, "0");
    const r = await fetch(cfg[1], { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ jsonrpc: "2.0", id: 1, method: "eth_call", params: [{ to: cfg[0], data }, "latest"] }), signal: AbortSignal.timeout(6000) });
    const j = await r.json();
    return Number(BigInt(j.result)) / 1e6;
  } catch { return null; }
}
const isAdmin = (req) => {
  const t = (req.get("authorization") || "").replace(/^Bearer\s+/i, "").trim();
  return !!(ADMIN_TOKEN && t && t.length === ADMIN_TOKEN.length && cryptoNode.timingSafeEqual(Buffer.from(t), Buffer.from(ADMIN_TOKEN)));
};
app.get("/admin/overview", async (req, res) => {
  if (!isAdmin(req)) return res.status(404).end();
  const cfg = USDC[NETWORK] || [];
  res.json({
    status: {
      ok: true, network: NETWORK, mainnet: MAINNET, rooms_enabled: ROOMS, payments: process.env.DEV_SKIP_PAYMENTS !== "1",
      facilitator: FACILITATOR_LABEL,
      public_url: PUBLIC_URL, uptime_hours: Math.round((Date.now() - STARTED) / 36e5 * 10) / 10,
      version: (process.env.RAILWAY_GIT_COMMIT_SHA || "").slice(0, 7) || null,
      // On Railway, only an attached volume survives restarts (it sets RAILWAY_VOLUME_MOUNT_PATH).
      persistent_storage: process.env.RAILWAY_PROJECT_ID ? !!process.env.RAILWAY_VOLUME_MOUNT_PATH : fs.existsSync(DATA_DIR),
    },
    wallet: { address: PAY_TO, usdc: await walletUsdc(), explorer: cfg[2] ? `${cfg[2]}/token/${cfg[0]}?a=${PAY_TO}` : null },
    sales: salesSummary(TEST_PAYERS),
    explorer_tx: cfg[2] ? `${cfg[2]}/tx/` : null,
    rooms: roomStats(),
    directory: ROOMS ? directoryStats() : null,
    deal_checkout: DEAL_CHECKOUT,
    controls: ROOMS ? getControls() : null,
    room_list: ROOMS ? listRooms().slice(0, 200) : [],
    reports: listReports().filter((r) => r.status === "open").slice(-50).reverse(),
    prices: Object.fromEntries(SKUS.map((p) => [p.id, p.price])),
  });
});

if (ROOMS) mountAgents(app, { network: NETWORK, checkoutEnabled: DEAL_CHECKOUT, publicUrl: PUBLIC_URL, isOpen: () => getControls().new_rooms, adminCheck: (req, res, next) => (isAdmin(req) ? next() : res.status(404).end()) });

app.get("/health", (req, res) =>
  res.json({ ok: true, name: SERVICE_NAME, network: NETWORK, mainnet: MAINNET, rooms: ROOMS, payments: process.env.DEV_SKIP_PAYMENTS !== "1", ...(ROOMS ? (({ notice, new_rooms, trials, joins }) => ({ notice: notice || null, open: { new_rooms, trials, joins } }))(getControls()) : {}), room_prices: Object.fromEntries(paidRooms.map((p) => [p.id, p.price])) }),
);

// HTML pages are served with the brand name filled in (%BRAND% etc.), so a rename is one setting.
const htmlCache = new Map();
app.use((req, res, next) => {
  if (req.method !== "GET" && req.method !== "HEAD") return next();
  let rel;
  try { rel = decodeURIComponent(req.path); } catch { return next(); } // malformed %-escapes: not found, not a crash
  if (rel.endsWith("/")) rel += "index.html";
  if (!rel.endsWith(".html") || rel.includes("..")) return next();
  for (const base of [SITE, path.join(ROOT, "public")]) {
    const file = path.join(base, rel);
    if (!file.startsWith(base) || !fs.existsSync(file)) continue;
    if (!htmlCache.has(file) || process.env.DEV_SKIP_PAYMENTS === "1") htmlCache.set(file, brandText(fs.readFileSync(file, "utf8"), { PUBLIC_URL, SERVICE: SERVICE_NAME, CONTACT, SECURITY_EMAIL }));
    return res.type("html").send(htmlCache.get(file));
  }
  next();
});
if (ROOMS) {
  app.get("/AGENT-COMMERCE.md", (req, res) => res.type("text/markdown; charset=utf-8").send(brandText(fs.readFileSync(path.join(ROOT, "AGENT-COMMERCE.md"), "utf8"), { PUBLIC_URL })));
  app.get("/PROTOCOL.md", (req, res) => res.type("text/markdown; charset=utf-8").send(brandText(fs.readFileSync(path.join(ROOT, "PROTOCOL.md"), "utf8"), { PUBLIC_URL })));
  app.use("/clients", express.static(path.join(ROOT, "clients"), { setHeaders: (res) => res.type("text/javascript") }));
}
// Voice-typing model + runtime (downloaded at build time): compressed, cached by browsers for 30 days.
if (ROOMS) app.use("/voice", compression(), express.static(path.join(SITE, "voice"), { maxAge: "30d", immutable: true, setHeaders: (res, f) => { if (f.endsWith(".mjs")) res.type("text/javascript"); } }));
app.get("/favicon.ico", (req, res) => res.redirect(301, "/brand/icon.svg"));
app.use(express.static(SITE));
app.use(express.static(path.join(ROOT, "public")));

app.use((err, req, res, next) => {
  if (err.type === "entity.too.large") return res.status(413).json({ error: "Too large.", charged: false });
  if (err.type === "entity.parse.failed") return res.status(400).json({ error: "Body is not valid JSON.", charged: false });
  console.error(err);
  res.status(500).json({ error: "Server error" });
});

app.listen(PORT, () => {
  console.log(`${SERVICE_NAME} x402 API on ${PUBLIC_URL}  network=${NETWORK}  payTo=${PAY_TO}  facilitator=${FACILITATOR_LABEL}`);
  for (const p of SKUS) console.log(`  ${p.price.padEnd(6)} ${p.method.padEnd(5)} ${p.path}`);
  if (!ADMIN_TOKEN) console.warn("  (no ADMIN_TOKEN set: /admin routes disabled)");
});
