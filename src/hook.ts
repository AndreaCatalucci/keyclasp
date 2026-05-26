import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const SECRET_PATTERNS: { name: string; regex: RegExp }[] = [
  { name: "OpenAI API Key", regex: /sk-(proj-)?[A-Za-z0-9_-]{20,}/g },
  { name: "GitHub Token", regex: /gh[pousr]_[A-Za-z0-9_]{20,}/g },
  { name: "GitHub PAT", regex: /github_pat_[A-Za-z0-9_]{20,}/g },
  { name: "AWS Access Key", regex: /(?:AKIA|ASIA)[A-Z0-9]{16}/g },
  { name: "Stripe Live Key", regex: /[rs]k_live_[A-Za-z0-9]{20,}/g },
  { name: "Stripe Test Key", regex: /[rs]k_test_[A-Za-z0-9]{20,}/g },
  { name: "Slack Webhook", regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_/]+/g },
  { name: "Google API Key", regex: /AIza[0-9A-Za-z_-]{35}/g },
  { name: "Private Key", regex: /-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----/g },
  { name: "JWT Token", regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { name: "Generic Password", regex: /(?:password|passwd|pwd)\s*[:=]\s*["'][^\s'"]{8,}["']/gi },
  { name: "Generic Secret", regex: /(?:secret|token|api[_-]?key)\s*[:=]\s*["'][^\s'"]{8,}["']/gi },
  { name: "NPM Token", regex: /npm_[A-Za-z0-9]{36}/g },
  { name: "Basic Auth", regex: /https?:\/\/[^:]+:[^@]+@/g },
];

export function scanFiles(filePaths: string[]): { file: string; line: number; match: string; pattern: string }[] {
  const findings: { file: string; line: number; match: string; pattern: string }[] = [];

  for (const filePath of filePaths) {
    try {
      const content = fs.readFileSync(filePath, "utf-8");
      const lines = content.split("\n");

      for (let i = 0; i < lines.length; i++) {
        const line = lines[i];
        // Skip comments and obvious non-secret lines
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("//") || trimmed.startsWith("#") || trimmed.startsWith("/*") || trimmed.startsWith("*")) {
          continue;
        }

        for (const { name, regex } of SECRET_PATTERNS) {
          regex.lastIndex = 0; // Reset regex state
          let match: RegExpExecArray | null;
          while ((match = regex.exec(line)) !== null) {
            findings.push({
              file: filePath,
              line: i + 1,
              match: maskSecret(match[0]),
              pattern: name,
            });
          }
        }
      }
    } catch {
      // Skip unreadable files
    }
  }

  return findings;
}

function maskSecret(value: string): string {
  if (value.length <= 12) return "***";
  return value.slice(0, 6) + "..." + value.slice(-4);
}

export function getStagedFiles(): string[] {
  try {
    const result = execSync("git diff --cached --name-only --diff-filter=ACM", {
      encoding: "utf-8",
      stdio: ["pipe", "pipe", "ignore"],
    });
    return result.trim().split("\n").filter(Boolean);
  } catch {
    return [];
  }
}

export function installHook(): string {
  const hooksDir = path.join(process.cwd(), ".git", "hooks");
  if (!fs.existsSync(hooksDir)) {
    throw new Error("Not a git repository (no .git/hooks directory). Run: git init");
  }

  const hookPath = path.join(hooksDir, "pre-commit");
  const hookScript = `#!/usr/bin/env bash
# Keyblind pre-commit hook — detect secrets before committing
# Installed by: keyblind install-hook

if command -v keyblind &>/dev/null; then
  keyblind check-secrets
  exit $?
elif command -v npx &>/dev/null; then
  npx keyblind check-secrets
  exit $?
else
  echo "⚠️  keyblind not found — skipping secret check"
  exit 0
fi
`;

  fs.writeFileSync(hookPath, hookScript, { mode: 0o755 });
  return hookPath;
}

export function checkAndReport(): { found: number; output: string } {
  const files = getStagedFiles();

  if (files.length === 0) {
    return { found: 0, output: "" };
  }

  const findings = scanFiles(files);

  if (findings.length === 0) {
    return { found: 0, output: "" };
  }

  let output = "\n⚠️  KEYBLIND: Possible secrets found in staged files:\n\n";
  for (const f of findings) {
    output += `  ${f.file}:${f.line}  [${f.pattern}]  ${f.match}\n`;
  }
  output += `\n  ${findings.length} potential secret(s) detected.\n`;
  output += "  If these are real secrets, use 'keyblind sandbox' or 'keyblind set'\n";
  output += "  to store them securely before committing.\n";
  output += "  To bypass: git commit --no-verify\n";

  return { found: findings.length, output };
}
