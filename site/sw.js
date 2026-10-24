// Service worker: lets the installed app open and show its screens without the browser.
// Privacy rules: it never stores room data, messages, keys, payments or admin data. Only the
// app's own public files (pages, styles, fonts, icons, app code) are kept, and the network is
// always tried first so a fix reaches people on their next open.
const VERSION = "suppressor-shell-v1";
const SHELL = [
  "/rooms/", "/rooms/app.js", "/offline.html",
  "/brand/base.css", "/brand/glow.css", "/brand/icon.svg", "/brand/pwa.js", "/brand/prices.js",
  "/fonts/display-800.woff2", "/fonts/inter-400.woff2", "/fonts/inter-500.woff2", "/fonts/inter-600.woff2", "/fonts/mono-500.woff2",
];
const NEVER = /^\/(v1|admin|voice|clients|mcp)(\/|$)|^\/health$|^\/\.well-known\//;

self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(VERSION).then((c) => c.addAll(SHELL)).then(() => self.skipWaiting()));
});

self.addEventListener("activate", (e) => {
  e.waitUntil(caches.keys().then((keys) => Promise.all(keys.filter((k) => k !== VERSION).map((k) => caches.delete(k)))).then(() => self.clients.claim()));
});

self.addEventListener("fetch", (e) => {
  const req = e.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin || NEVER.test(url.pathname)) return; // straight to the network, never stored
  const page = req.mode === "navigate";
  if (!page && !SHELL.includes(url.pathname)) return;
  e.respondWith((async () => {
    try {
      const res = await fetch(req);
      // Keep the latest copy of the app's own files for offline use. Never other pages.
      if (res.ok && SHELL.includes(url.pathname)) { const copy = res.clone(); caches.open(VERSION).then((c) => c.put(url.pathname, copy)); }
      return res;
    } catch (err) {
      const hit = await caches.match(url.pathname);
      if (hit) return hit;
      if (page) return (await caches.match("/offline.html")) || Response.error();
      throw err;
    }
  })());
});
