// Loaded synchronously in <head> so the theme is set before first paint.
(() => {
  const KEY = "theme";
  const root = document.documentElement;
  const system = matchMedia("(prefers-color-scheme: dark)");

  const pref = () => {
    try {
      return localStorage.getItem(KEY) || "auto";
    } catch {
      return "auto";
    }
  };

  const apply = () => {
    const p = pref();
    root.dataset.theme = p === "dark" || (p === "auto" && system.matches) ? "dark" : "light";
    for (const b of document.querySelectorAll("[data-theme-set]")) {
      b.setAttribute("aria-pressed", String(b.dataset.themeSet === p));
    }
  };

  const flash = (el, text) => {
    const old = el.textContent;
    el.textContent = text;
    setTimeout(() => (el.textContent = old), 1500);
  };

  apply();
  system.addEventListener("change", apply);
  document.addEventListener("DOMContentLoaded", apply);
  document.addEventListener("click", (e) => {
    const set = e.target.closest("[data-theme-set]");
    if (set) {
      try {
        localStorage.setItem(KEY, set.dataset.themeSet);
      } catch {}
      apply();
      return;
    }
    const copy = e.target.closest("[data-copy]");
    if (copy) {
      navigator.clipboard
        .writeText(copy.dataset.copy)
        .then(() => flash(copy, "Copied"), () => flash(copy, "Copy failed"));
    }
  });
})();
