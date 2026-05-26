import fs from "node:fs";
import path from "node:path";
import { sandboxEnvFile } from "./sandbox.js";

export function watchEnvFile(filePath?: string): void {
  const target = path.resolve(filePath || ".env");

  if (!fs.existsSync(target)) {
    console.error(`File not found: ${target}`);
    process.exit(1);
  }

  console.log(`Watching ${target} for changes... (Ctrl+C to stop)`);

  // Initial sandbox
  const result = sandboxEnvFile(target);
  if (result.sandboxed.length > 0) {
    console.log(`Initial sandbox: ${result.sandboxed.length} value(s) replaced.`);
  } else {
    console.log("No secrets detected in current file.");
  }

  let debounce: ReturnType<typeof setTimeout> | null = null;

  fs.watch(target, (eventType) => {
    if (eventType !== "change") return;
    if (debounce) clearTimeout(debounce);
    debounce = setTimeout(() => {
      try {
        const result = sandboxEnvFile(target);
        if (result.sandboxed.length > 0) {
          console.log(`Sandboxed ${result.sandboxed.length} value(s) in ${target}`);
        }
      } catch (err: any) {
        console.error(`Sandbox error: ${err.message}`);
      }
    }, 100);
  });
}
