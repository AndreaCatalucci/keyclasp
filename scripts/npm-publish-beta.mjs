#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { spawnSync } from "node:child_process";

const args = process.argv.slice(2);
if (args[0] !== "publish") {
  console.error("This release helper only supports npm publish.");
  process.exit(1);
}

// Keep the terminal attached so npm can open the browser and request MFA.
// Inspect private diagnostic logs instead of capturing authentication output.
for (let attempt = 0; attempt < 2; attempt++) {
  const logs = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-npm-publish-"));
  let result;
  let expiredWebAuth = false;
  try {
    result = spawnSync("npm", [...args, "--logs-dir", logs], { stdio: "inherit" });
    if (result.status !== 0 && !result.error && !result.signal) {
      expiredWebAuth = fs.readdirSync(logs).some(file => {
        const log = fs.readFileSync(path.join(logs, file), "utf8");
        return /error code E404\b/.test(log)
          && /error 404[^\n]*GET https:\/\/registry\.npmjs\.org\/-\/v1\/done\?authId=/.test(log);
      });
    }
  } finally {
    fs.rmSync(logs, { recursive: true, force: true });
  }
  if (result.status === 0) process.exit(0);
  if (attempt === 0 && expiredWebAuth) {
    console.error("npm browser authentication returned 404. Retrying once with a fresh authentication request; complete the new browser prompt.");
    continue;
  }
  if (result.error) console.error("Could not start npm publish:", result.error.message);
  process.exit(result.status ?? 1);
}
