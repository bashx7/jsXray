async function loadAdminModule() {
  const adminChunk = await import("./chunks/admin-dashboard.chunk.js");
  const reportChunk = await import("./modules/reporting.js");
  return { adminChunk, reportChunk };
}
