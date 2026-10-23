// Language menu. The server picks the language from ?lang= or the browser's settings; a choice made
// here is remembered in this browser only (no cookie), and links keep it as you move around.
(() => {
  const LANGS = [["en", "English"], ["ko", "한국어"], ["uk", "Українська"], ["ar", "العربية"], ["vi", "Tiếng Việt"], ["fil", "Filipino"], ["ja", "日本語"], ["zh-Hant", "繁體中文"]];
  const cur = document.documentElement.lang || "en";
  let strings = {};
  try { strings = JSON.parse(document.getElementById("i18n-strings")?.textContent || "{}"); } catch {}
  const t = (s) => strings[s] || s;
  const url = new URL(location.href);
  const asked = url.searchParams.get("lang");
  let saved = null;
  try { saved = localStorage.getItem("sup.lang"); } catch {}
  if (!asked && saved && saved !== cur && LANGS.some(([c]) => c === saved)) {
    url.searchParams.set("lang", saved);
    location.replace(url);
    return;
  }
  // Keep an explicit language on links to our other pages.
  if (asked) {
    for (const a of document.querySelectorAll("a[href]")) {
      const raw = a.getAttribute("href");
      if (raw.startsWith("#") || raw.startsWith("mailto:") || raw.startsWith("?")) continue;
      const u = new URL(a.href, location.href);
      if (u.origin !== location.origin || !/(\/|\.html)$/.test(u.pathname) || u.searchParams.has("lang")) continue;
      u.searchParams.set("lang", cur);
      a.setAttribute("href", u.pathname + u.search + u.hash);
    }
  }
  const sel = document.createElement("select");
  sel.className = "lang-pick";
  sel.setAttribute("aria-label", t("Language"));
  for (const [code, name] of LANGS) sel.append(new Option(name, code, false, code === cur));
  sel.addEventListener("change", () => {
    try { localStorage.setItem("sup.lang", sel.value); } catch {}
    const u = new URL(location.href);
    u.searchParams.set("lang", sel.value);
    location.assign(u);
  });
  const head = document.querySelector(".site-head .wrap");
  if (head) head.append(sel);
  else { sel.classList.add("lang-float"); (document.querySelector(".wrap") || document.body).prepend(sel); }
})();
