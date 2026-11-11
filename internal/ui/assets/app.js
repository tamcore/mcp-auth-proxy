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

  const b64 = {
    enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, ""),
    dec: (s) => Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/")), (c) => c.charCodeAt(0)).buffer,
  };

  const postJSON = async (url, body) => {
    const res = await fetch(url, { method: "POST", headers: { "Content-Type": "application/json" }, body });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(data.error || `request failed (${res.status})`);
    return data;
  };

  const showError = (msg) => {
    const el = document.querySelector("[data-passkey-error]");
    if (el) {
      el.textContent = msg;
      el.hidden = false;
    }
  };

  const addPasskey = async () => {
    const { publicKey } = await postJSON("/settings/passkeys/begin");
    publicKey.challenge = b64.dec(publicKey.challenge);
    publicKey.user.id = b64.dec(publicKey.user.id);
    for (const c of publicKey.excludeCredentials || []) c.id = b64.dec(c.id);
    const cred = await navigator.credentials.create({ publicKey });
    const name = document.getElementById("passkey-name")?.value || "";
    const body = JSON.stringify({
      id: cred.id,
      rawId: b64.enc(cred.rawId),
      type: cred.type,
      response: {
        attestationObject: b64.enc(cred.response.attestationObject),
        clientDataJSON: b64.enc(cred.response.clientDataJSON),
        transports: cred.response.getTransports?.() || [],
      },
      clientExtensionResults: cred.getClientExtensionResults(),
    });
    const { redirect } = await postJSON(`/settings/passkeys/finish?name=${encodeURIComponent(name)}`, body);
    location.assign(redirect);
  };

  const loginWithPasskey = async (next) => {
    const { publicKey } = await postJSON("/login/passkey/begin");
    publicKey.challenge = b64.dec(publicKey.challenge);
    for (const c of publicKey.allowCredentials || []) c.id = b64.dec(c.id);
    const cred = await navigator.credentials.get({ publicKey });
    const r = cred.response;
    const body = JSON.stringify({
      id: cred.id,
      rawId: b64.enc(cred.rawId),
      type: cred.type,
      response: {
        authenticatorData: b64.enc(r.authenticatorData),
        clientDataJSON: b64.enc(r.clientDataJSON),
        signature: b64.enc(r.signature),
        userHandle: r.userHandle ? b64.enc(r.userHandle) : null,
      },
      clientExtensionResults: cred.getClientExtensionResults(),
    });
    const { redirect } = await postJSON(`/login/passkey/finish?next=${encodeURIComponent(next || "/")}`, body);
    location.assign(redirect);
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

  // Passkeys need a secure context and the WebAuthn API; say why when absent.
  const checkPasskeys = () => {
    const buttons = document.querySelectorAll("[data-passkey-login], [data-passkey-add]");
    if (!buttons.length || (window.isSecureContext && window.PublicKeyCredential && navigator.credentials)) return;
    for (const b of buttons) b.disabled = true;
    showError(
      window.isSecureContext
        ? "This browser does not offer passkeys. Use another browser or log in with your password."
        : `Passkeys need https. Open https://${location.host}${location.pathname}.`,
    );
  };

  apply();
  system.addEventListener("change", apply);
  document.addEventListener("DOMContentLoaded", checkPasskeys);
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
    const add = e.target.closest("[data-passkey-add]");
    if (add) {
      addPasskey().catch((err) => showError(err.message));
      return;
    }
    const login = e.target.closest("[data-passkey-login]");
    if (login) {
      loginWithPasskey(login.dataset.passkeyLogin).catch((err) => showError(err.message));
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
