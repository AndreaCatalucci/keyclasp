import { execSync } from "node:child_process";

export interface SetupResult {
  editor: string;
  action: "configured" | "already_configured" | "failed";
  error?: string;
}

function hasCommand(cmd: string): boolean {
  try {
    execSync(`which ${cmd}`, { stdio: "ignore" });
    return true;
  } catch {
    return false;
  }
}

function setupClaudeCode(): SetupResult {
  if (!hasCommand("claude")) {
    return { editor: "Claude Code", action: "failed", error: "claude CLI not found. Install Claude Code first." };
  }

  // Check if already configured
  try {
    const list = execSync("claude mcp list 2>/dev/null", { encoding: "utf8" });
    if (list.includes("keyblind")) {
      return { editor: "Claude Code", action: "already_configured" };
    }
  } catch {
    // mcp list might fail if no servers configured yet — that's fine
  }

  try {
    execSync("claude mcp add --scope user keyblind -- keyblind start", {
      encoding: "utf8",
      stdio: "pipe",
    });
    return { editor: "Claude Code", action: "configured" };
  } catch (err: any) {
    return { editor: "Claude Code", action: "failed", error: err.stderr || err.message };
  }
}

export function setupAll(): SetupResult[] {
  return [setupClaudeCode()];
}
