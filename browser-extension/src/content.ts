import { matchSecrets, AI_CHAT_DOMAINS } from "./patterns.js";
import type { DetectedSecret, ExtensionState } from "./types.js";

let state: ExtensionState = {
  enabled: true,
  pasteInterception: true,
  highlightSecrets: true,
  monitoredSites: [],
};

// Load state from storage
chrome.storage.local.get(["keyblind_state"], (result) => {
  if (result.keyblind_state) {
    state = { ...state, ...result.keyblind_state };
  }
});

// Listen for state updates from popup
chrome.runtime.onMessage.addListener((msg) => {
  if (msg.type === "updateState") {
    state = { ...state, ...msg.state };
  }
});

// --- Page Scanning ---
function scanPage(): DetectedSecret[] {
  if (!state.enabled) return [];

  const textNodes: { node: Text; parent: Element }[] = [];
  const walker = document.createTreeWalker(
    document.body,
    NodeFilter.SHOW_TEXT,
    {
      acceptNode(node) {
        // Skip script/style tags, input/textarea elements
        const parent = node.parentElement;
        if (!parent) return NodeFilter.FILTER_REJECT;
        const tag = parent.tagName.toLowerCase();
        if (["script", "style", "noscript", "input", "textarea", "select"].includes(tag)) {
          return NodeFilter.FILTER_REJECT;
        }
        return NodeFilter.FILTER_ACCEPT;
      },
    }
  );

  let node: Text | null;
  while ((node = walker.nextNode() as Text | null)) {
    if (node.textContent && node.textContent.trim()) {
      textNodes.push({ node, parent: node.parentElement! });
    }
  }

  const allSecrets: DetectedSecret[] = [];
  for (const { node, parent } of textNodes) {
    const secrets = matchSecrets(node.textContent || "");
    for (const s of secrets) {
      s.element = getCSSPath(parent);
      allSecrets.push(s);
    }
  }

  return allSecrets;
}

function getCSSPath(el: Element): string {
  const path: string[] = [];
  let current: Element | null = el;
  while (current && current !== document.body) {
    let selector = current.tagName.toLowerCase();
    if (current.id) {
      selector = "#" + current.id;
      path.unshift(selector);
      break;
    }
    if (current.className && typeof current.className === "string") {
      const classes = current.className.trim().split(/\s+/).slice(0, 2);
      if (classes.length) selector += "." + classes.join(".");
    }
    path.unshift(selector);
    current = current.parentElement;
  }
  return path.join(" > ");
}

// --- Warning Banner ---
function addWarningBanner(secrets: DetectedSecret[]): void {
  if (document.getElementById("keyblind-warning")) return;

  const banner = document.createElement("div");
  banner.id = "keyblind-warning";
  banner.style.cssText = `
    position: fixed; top: 0; left: 0; right: 0; z-index: 999999;
    background: linear-gradient(135deg, #dc2626, #991b1b);
    color: white; padding: 10px 16px; font-family: system-ui, sans-serif;
    font-size: 14px; display: flex; align-items: center; justify-content: space-between;
    box-shadow: 0 2px 8px rgba(0,0,0,0.3);
  `;
  banner.innerHTML = `
    <span>Keyblind detected ${secrets.length} secret(s) on this page — be careful sharing or screenshotting.</span>
    <button id="keyblind-dismiss" style="background:rgba(255,255,255,0.2);border:none;color:white;padding:4px 12px;border-radius:4px;cursor:pointer;font-size:13px">Dismiss</button>
  `;
  document.body.prepend(banner);
  banner.querySelector("#keyblind-dismiss")?.addEventListener("click", () => banner.remove());
}

// --- Paste Interception ---
function interceptPasteEvent(e: ClipboardEvent): void {
  if (!state.enabled || !state.pasteInterception) return;

  const hostname = window.location.hostname;
  const isAIChat = AI_CHAT_DOMAINS.some((d) => hostname.includes(d));
  if (!isAIChat) return;

  const clipboardData = e.clipboardData;
  if (!clipboardData) return;

  const text = clipboardData.getData("text/plain");
  if (!text) return;

  const secrets = matchSecrets(text);
  if (secrets.length === 0) return;

  // Replace detected values with placeholders
  let sanitized = text;
  for (const pattern of matchSecrets(text)) {
    // Use the original regex to find and replace
    for (const sp of SECRET_PATTERNS_ARRAY) {
      sp.regex.lastIndex = 0;
      sanitized = sanitized.replace(sp.regex, (match) => {
        return `KEYBLIND_${sp.name.toUpperCase().replace(/\s+/g, "_")}_${match.slice(0, 4)}...${match.slice(-4)}`;
      });
    }
  }

  e.preventDefault();
  const target = e.target as HTMLElement;

  if (target.isContentEditable || target.tagName === "TEXTAREA" || target.tagName === "INPUT") {
    document.execCommand("insertText", false, sanitized);
  }

  // Show toast notification
  showToast(`${secrets.length} secret(s) intercepted and sanitized`);
}

// For re-importing patterns in the paste handler
const SECRET_PATTERNS_ARRAY = (() => {
  const patterns: { name: string; regex: RegExp; severity: string }[] = [];
  // Re-import to get fresh regex instances
  import("./patterns.js").then((mod) => {
    patterns.push(...mod.SECRET_PATTERNS);
  });
  return patterns;
})();

function showToast(message: string): void {
  const toast = document.createElement("div");
  toast.style.cssText = `
    position: fixed; bottom: 20px; right: 20px; z-index: 9999999;
    background: #1a1a2e; color: #58a6ff; border: 1px solid #30363d;
    padding: 10px 16px; border-radius: 8px; font-family: system-ui, sans-serif;
    font-size: 13px; box-shadow: 0 4px 12px rgba(0,0,0,0.4);
    animation: keyblind-fade-in 0.3s ease;
  `;
  toast.textContent = message;
  document.body.appendChild(toast);
  setTimeout(() => {
    toast.style.opacity = "0";
    toast.style.transition = "opacity 0.3s";
    setTimeout(() => toast.remove(), 300);
  }, 3000);
}

// --- DOM Observer ---
let scanTimeout: number | undefined;
const observer = new MutationObserver(() => {
  if (!state.enabled) return;
  clearTimeout(scanTimeout);
  scanTimeout = window.setTimeout(() => {
    const secrets = scanPage();
    if (secrets.length > 0) {
      addWarningBanner(secrets);
      if (state.highlightSecrets) highlightSecrets(secrets);
    }
  }, 500);
});

function highlightSecrets(secrets: DetectedSecret[]): void {
  // Remove old highlights
  document.querySelectorAll(".keyblind-highlight").forEach((el) => {
    const parent = el.parentNode;
    if (parent) {
      parent.replaceChild(document.createTextNode(el.textContent || ""), el);
      parent.normalize();
    }
  });

  // Highlight detected secrets
  for (const secret of secrets.slice(0, 20)) {
    try {
      const el = document.querySelector(secret.element);
      if (el && el.textContent) {
        const span = document.createElement("span");
        span.className = "keyblind-highlight";
        span.style.cssText =
          "background:rgba(220,38,38,0.3);border-bottom:2px wavy #dc2626;padding:1px 2px;border-radius:2px";
        span.textContent = el.textContent.slice(secret.position.col, secret.position.col + 20);
        span.title = `Keyblind: ${secret.pattern} detected`;
        el.replaceChild(span, el.firstChild!);
      }
    } catch {
      // Skip elements that can't be highlighted
    }
  }
}

// --- Init ---
document.addEventListener("DOMContentLoaded", () => {
  if (!state.enabled) return;
  observer.observe(document.body, { childList: true, subtree: true, characterData: true });
  const secrets = scanPage();
  if (secrets.length > 0) {
    addWarningBanner(secrets);
  }
});

// Attach paste listener
document.addEventListener("paste", interceptPasteEvent, true);

// Inject styles
const style = document.createElement("style");
style.textContent = `
  @keyframes keyblind-fade-in {
    from { opacity: 0; transform: translateY(10px); }
    to { opacity: 1; transform: translateY(0); }
  }
  .keyblind-highlight {
    cursor: help;
  }
`;
document.head.appendChild(style);
