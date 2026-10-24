// Makes the site installable as an app: registers the service worker and shows an
// "Install app" button (Android, Chrome, Edge) or "Add to Home Screen" steps (iPhone, iPad).
(() => {
  if ("serviceWorker" in navigator) addEventListener("load", () => navigator.serviceWorker.register("/sw.js").catch(() => {}));

  const standalone = matchMedia("(display-mode: standalone)").matches || navigator.standalone === true;
  if (standalone) { document.documentElement.classList.add("is-app"); return; }

  const head = document.querySelector(".site-head .wrap");
  if (!head) return;
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn small line install-app";
  btn.textContent = "Install app";
  btn.hidden = true;
  head.appendChild(btn);

  let prompt = null;
  addEventListener("beforeinstallprompt", (e) => { e.preventDefault(); prompt = e; btn.hidden = false; });
  addEventListener("appinstalled", () => { prompt = null; btn.hidden = true; });

  // iPhone and iPad have no install prompt: Safari's Share menu does it.
  const ios = /iphone|ipad|ipod/i.test(navigator.userAgent) || (navigator.platform === "MacIntel" && navigator.maxTouchPoints > 1);
  let tip = null;
  if (ios) btn.hidden = false;

  btn.addEventListener("click", async () => {
    if (prompt) { prompt.prompt(); await prompt.userChoice.catch(() => {}); prompt = null; btn.hidden = true; return; }
    if (!ios) return;
    if (tip) { tip.remove(); tip = null; return; }
    tip = document.createElement("p");
    tip.className = "install-tip";
    tip.setAttribute("role", "status");
    tip.textContent = "In Safari, tap the Share button, then “Add to Home Screen”. Suppressor then opens like an app, without the browser.";
    head.parentElement.after(tip);
  });
})();
