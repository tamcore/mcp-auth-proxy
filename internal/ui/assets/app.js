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

  const showTools = async (name) => {
    const dialog = document.getElementById("tools-dialog");
    const status = dialog.querySelector("[data-tools-status]");
    const list = dialog.querySelector("[data-tools-list]");
    dialog.querySelector("h2").textContent = `Tools of ${name}`;
    status.textContent = "Loading…";
    list.replaceChildren();
    dialog.showModal();
    try {
      const res = await fetch(`/portal/upstream/tools?name=${encodeURIComponent(name)}`);
      const body = await res.json();
      if (!res.ok) {
        status.textContent = body.error || "Could not load tools.";
        return;
      }
      status.textContent = `${body.tools.length} tools`;
      for (const t of body.tools) {
        const li = document.createElement("li");
        const code = document.createElement("code");
        code.className = "mono";
        code.textContent = t.name;
        const p = document.createElement("p");
        p.className = "muted mt-1";
        p.textContent = t.description;
        li.append(code, p);
        list.append(li);
      }
    } catch {
      status.textContent = "Could not load tools.";
    }
  };

  const flash = (el, text) => {
    const old = el.textContent;
    el.textContent = text;
    setTimeout(() => (el.textContent = old), 1500);
  };

  // Reload when pending requests appear or resolve, unless the user is busy.
  const watchPending = () => {
    if (!document.querySelector("[data-pending-watch]")) return;
    const shown = () =>
      [...document.querySelectorAll("[data-pending-id]")].map((e) => e.dataset.pendingId).sort().join();
    setInterval(async () => {
      const busy =
        document.activeElement?.matches("input, textarea, select") ||
        document.querySelector("details[open], dialog[open]");
      if (busy || document.hidden) return;
      try {
        const res = await fetch("/portal/pending");
        if (!res.ok) return;
        const { ids } = await res.json();
        if (ids.sort().join() !== shown()) location.reload();
      } catch {}
    }, 5000);
  };

  apply();
  system.addEventListener("change", apply);
  document.addEventListener("DOMContentLoaded", watchPending);
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
    const tools = e.target.closest("[data-tools]");
    if (tools) {
      showTools(tools.dataset.tools);
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
