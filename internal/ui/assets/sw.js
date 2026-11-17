// Service worker for Web Push: shows the auth request and answers its
// Approve/Deny buttons with a POST to the signed URL.
self.addEventListener("push", (e) => {
  let d = {};
  try {
    d = e.data ? e.data.json() : {};
  } catch {}
  const actions = [];
  if (d.approve) actions.push({ action: "approve", title: "Approve" });
  if (d.deny) actions.push({ action: "deny", title: "Deny" });
  e.waitUntil(
    self.registration.showNotification(d.title || "mcp-auth-proxy", {
      body: d.body || "",
      tag: d.approve || "mcp-auth-proxy",
      requireInteraction: actions.length > 0,
      actions,
      data: { approve: d.approve, deny: d.deny },
    }),
  );
});

self.addEventListener("notificationclick", (e) => {
  e.notification.close();
  const url = e.notification.data && e.notification.data[e.action];
  e.waitUntil(url ? fetch(url, { method: "POST" }) : self.clients.openWindow("/"));
});
