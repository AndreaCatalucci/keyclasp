# Chrome Web Store Listing — Keyblind

---

## Store Listing Fields

### Description (Short — max 132 chars)
```
Detect and protect API keys & secrets on web pages. Intercepts paste events on AI chat sites to prevent accidental leaks.
```

### Description (Detailed)
```
Keyblind detects API keys, tokens, and secrets exposed on web pages and prevents you from accidentally pasting them into AI chat sites.

WHAT IT DOES:
- Scans web pages for 13+ types of secrets (OpenAI keys, GitHub tokens, AWS keys, Stripe keys, JWTs, private keys, .env files, and more)
- Shows a red warning banner when secrets are found on a page
- Intercepts paste events on AI chat sites (Claude.ai, ChatGPT, Copilot, Cursor, Gemini, Perplexity, Poe) and sanitizes pasted text — replacing real keys with placeholder markers
- Highlights detected secrets inline so you can see exactly what's exposed
- Popup shows vault status (requires Keyblind CLI running) and detected secrets on the current page

REQUIRES:
- Keyblind CLI (free, open source) running on your machine for vault integration
- Install: npm install -g keyblind

PRIVACY:
- 100% local — no data ever sent to any server
- No analytics, no telemetry, no tracking
- Open source (MIT): https://github.com/aarifmms/keyblind

Keyblind is part of the Keyblind secrets management platform — the MCP-native encrypted vault for AI agents. Learn more at https://keyblind.dev
```

### Category
**Productivity**

### Language
**English (United States)** — en-US

### Store Icon
Use `icons/icon128.png` (already generated, 128x128 solid blue #1f6feb with keyhole icon)

---

## Graphic Assets Required

### Small Promo Tile — 440x280 PNG
Design suggestion: Dark background (#0d1117), "Keyblind" wordmark in #58a6ff, subtitle "Blind AI to Your Keys", keyhole icon on the right. No corner radius.

### Marquee Promo Tile — 1400x560 PNG
Same design, wider layout. Keyblind logo/keyhole on left, tagline "Detect & Protect API Keys on the Web" + feature bullets on right.

### Screenshots — 1280x800 PNG (at least 1 required, recommend 3-4)

**Screenshot 1: Popup with detected secrets**
- Open the extension popup on a GitHub page with a token visible
- Shows vault status, toggle switches, and detected secrets list

**Screenshot 2: Warning banner on page**
- Show a page (e.g., a GitHub issue or Pastebin) where an API key is visible
- The red Keyblind warning banner at the top: "Keyblind detected 1 secret(s) on this page"

**Screenshot 3: Paste interception toast**
- On Claude.ai or ChatGPT, paste an OpenAI API key
- Show the bottom-right toast: "1 secret(s) intercepted and sanitized"

**Screenshot 4: Inline highlighting**
- Show a code block where a secret is highlighted with red underline

---

## Website Links

| Field | URL |
|-------|-----|
| **Official URL** | For the extension listing — use `https://keyblind.dev` |
| **Homepage URL** | `https://keyblind.dev` |
| **Support URL** | `https://github.com/aarifmms/keyblind/issues` |
| **Privacy Policy** | `https://keyblind.dev/privacy` (create if needed — extension uses zero data collection) |

---

## Additional Fields

### Price
**Free**

### Visibility
**Public**

### Regions
**All regions**

### Content Rating
**No special permissions required** — select "No" for all mature content questions.

---

## Notes for Submission

1. The extension ZIP is at: `keyblind-extension-v0.1.0.zip` (9.1KB)
2. Icon files are in dist/icons/ (16, 48, 128)
3. For promo tiles and screenshots, you'll need graphic design tools or I can generate placeholder PNGs programmatically
4. If keyblind.dev doesn't have a privacy policy page yet, the extension qualifies for "No data collection" exemption — you can state "This extension does not collect, store, or transmit any user data" in the privacy practices tab
