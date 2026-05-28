import type { ExtensionState, VaultStatus } from "../types.js";

// Load and display vault status
async function loadStatus(): Promise<void> {
  try {
    const res = await chrome.runtime.sendMessage({ type: "getStatus" });
    updateStatusUI(res);
  } catch {
    updateStatusUI({ initialized: false, secretCount: 0 });
  }
}

function updateStatusUI(status: VaultStatus): void {
  const dot = document.getElementById("status-dot")!;
  const count = document.getElementById("secret-count")!;

  if (status.initialized) {
    dot.className = "status-dot green";
    dot.title = "Keyblind is running";
    count.textContent = String(status.secretCount);
  } else {
    dot.className = "status-dot red";
    dot.title = "Keyblind server not running (port 3100)";
    count.textContent = "--";
  }

  if (status.license) {
    const info = document.getElementById("license-info")!;
    info.style.display = "flex";
    document.getElementById("license-tier")!.textContent = status.license.tier;
  }
}

// Query active tab for detected secrets
async function queryActiveTab(): Promise<void> {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.id) return;

    const results = await chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => {
        const highlights = document.querySelectorAll(".keyblind-highlight");
        return Array.from(highlights).map((el) => el.textContent || "");
      },
    });

    const secrets = results[0]?.result || [];
    const container = document.getElementById("found-secrets-container")!;
    const empty = document.getElementById("empty-state")!;

    if (secrets.length === 0) {
      container.innerHTML = "";
      empty.style.display = "block";
    } else {
      empty.style.display = "none";
      container.innerHTML = secrets
        .slice(0, 10)
        .map((s) => `<div class="found-secret">${s}</div>`)
        .join("");
    }
  } catch {
    // Can't access this tab
  }
}

// Toggle handlers
const state: ExtensionState = {
  enabled: true,
  pasteInterception: true,
  highlightSecrets: true,
  monitoredSites: [],
};

function setupToggle(id: string, key: keyof ExtensionState): void {
  const checkbox = document.getElementById(id) as HTMLInputElement;
  checkbox.addEventListener("change", () => {
    (state as any)[key] = checkbox.checked;
    chrome.storage.local.set({ keyblind_state: state });
    // Notify content script
    chrome.tabs.query({ active: true, currentWindow: true }, ([tab]) => {
      if (tab?.id) {
        chrome.tabs.sendMessage(tab.id, { type: "updateState", state });
      }
    });
  });
}

// Refresh button
document.getElementById("btn-refresh")?.addEventListener("click", () => {
  loadStatus();
  queryActiveTab();
});

// Init
document.addEventListener("DOMContentLoaded", () => {
  // Load saved state
  chrome.storage.local.get(["keyblind_state"], (result) => {
    if (result.keyblind_state) {
      Object.assign(state, result.keyblind_state);
      (document.getElementById("toggle-enabled") as HTMLInputElement).checked = state.enabled;
      (document.getElementById("toggle-paste") as HTMLInputElement).checked = state.pasteInterception;
      (document.getElementById("toggle-highlight") as HTMLInputElement).checked = state.highlightSecrets;
    }
  });

  setupToggle("toggle-enabled", "enabled");
  setupToggle("toggle-paste", "pasteInterception");
  setupToggle("toggle-highlight", "highlightSecrets");

  loadStatus();
  queryActiveTab();
});
