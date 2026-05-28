import type { DetectedSecret } from "./types.js";

export const SECRET_PATTERNS: { name: string; regex: RegExp; severity: "critical" | "high" | "medium" }[] = [
  { name: "OpenAI API Key", regex: /sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}/g, severity: "critical" },
  { name: "GitHub Token", regex: /gh[pousr]_[A-Za-z0-9_]{36,}/g, severity: "critical" },
  { name: "GitHub PAT (classic)", regex: /ghp_[A-Za-z0-9]{36,}/g, severity: "critical" },
  { name: "AWS Access Key", regex: /AKIA[0-9A-Z]{16}/g, severity: "critical" },
  { name: "AWS Secret Key", regex: /(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])/g, severity: "high" },
  { name: "Google API Key", regex: /AIza[0-9A-Za-z_-]{35}/g, severity: "high" },
  { name: "Stripe Secret Key", regex: /sk_live_[0-9a-zA-Z]{24,}/g, severity: "critical" },
  { name: "Stripe Publishable Key", regex: /pk_(?:live|test)_[0-9a-zA-Z]{24,}/g, severity: "medium" },
  { name: "Slack Webhook", regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9/]+/g, severity: "high" },
  { name: "JWT Token", regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g, severity: "high" },
  { name: "Generic API Key", regex: /(?:api[_-]?key|apikey|secret|token|password|access[_-]?token)\s*[:=]\s*['"]([^'"]{8,})['"]/gi, severity: "high" },
  { name: "Private Key (PEM)", regex: /-----BEGIN (?:RSA|EC|DSA|OPENSSH|PGP) PRIVATE KEY-----/g, severity: "critical" },
  { name: ".env Assignment", regex: /^[A-Z_][A-Z0-9_]{0,50}=.{4,}$/gm, severity: "high" },
];

export const AI_CHAT_DOMAINS: string[] = [
  "claude.ai", "chat.openai.com", "chatgpt.com",
  "githubcopilot.com", "cursor.sh", "gemini.google.com",
  "poe.com", "perplexity.ai", "you.com",
];

export function matchSecrets(text: string): DetectedSecret[] {
  const results: DetectedSecret[] = [];
  for (const pattern of SECRET_PATTERNS) {
    let match: RegExpExecArray | null;
    pattern.regex.lastIndex = 0;
    while ((match = pattern.regex.exec(text)) !== null) {
      results.push({
        pattern: pattern.name,
        match: match[0].slice(0, 8) + "..." + match[0].slice(-4),
        position: { line: 0, col: match.index },
        element: "",
      });
    }
  }
  return results;
}
