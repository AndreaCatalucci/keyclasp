import type { VaultStatus } from "./types.js";

// Check if keyblind CLI is available via localhost MCP server
async function checkKeyblindStatus(): Promise<VaultStatus> {
  try {
    const res = await fetch("http://localhost:3100/health", { signal: AbortSignal.timeout(2000) });
    if (res.ok) {
      const data = await res.json();
      return { initialized: true, secretCount: data.secretCount || 0 };
    }
  } catch {
    // MCP server not running
  }
  return { initialized: false, secretCount: 0 };
}

async function getSecretValue(name: string): Promise<string | null> {
  try {
    const res = await fetch("http://localhost:3100/mcp", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "tools/call",
        params: { name: "resolve_secret", arguments: { name } },
        id: Date.now(),
      }),
      signal: AbortSignal.timeout(3000),
    });
    if (res.ok) {
      const data = await res.json();
      const result = JSON.parse(data.result?.content?.[0]?.text || "{}");
      return result.value || null;
    }
  } catch {
    // Failed
  }
  return null;
}

// Message handlers
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  switch (msg.type) {
    case "getStatus":
      checkKeyblindStatus().then(sendResponse);
      return true; // Keep channel open for async
    case "resolveSecret":
      getSecretValue(msg.name).then(sendResponse);
      return true;
    default:
      sendResponse({ error: "Unknown message type" });
  }
});

// Set default state on install
chrome.runtime.onInstalled.addListener(() => {
  chrome.storage.local.set({
    keyblind_state: {
      enabled: true,
      pasteInterception: true,
      highlightSecrets: true,
      monitoredSites: [],
    },
  });
});
