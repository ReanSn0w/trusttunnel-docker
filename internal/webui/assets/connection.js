document.addEventListener("change", function(e) {
  if (e.target.id !== "connection-preset" || !e.target.value) return;
  const f = document.getElementById("connection-settings"), preset = e.target.value;
  f.elements.protocol.value = preset === "quic" ? "http3" : "http2";
  f.elements.anti_dpi.checked = preset === "dpi";
  f.elements.tls_profile.value = "chrome";
  f.elements.post_quantum.checked = preset !== "compact";
});
document.addEventListener("click", async function(e) {
  if (!e.target.closest("[data-copy-link]")) return;
  const status = document.getElementById("copy-status");
  try {
    await navigator.clipboard.writeText(document.getElementById("client-link").textContent);
    status.textContent = "Copied";
  } catch (_) { status.textContent = "Copy the link below manually."; }
});
