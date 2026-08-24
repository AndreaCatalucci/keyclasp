import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

export function collectNativeSourceFiles(directory, relative = "", output = []) {
  for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
    if (relative === "" && entry.name === "build") continue;
    const entryRelative = path.posix.join(relative, entry.name);
    const entryPath = path.join(directory, entry.name);
    if (entry.isDirectory()) collectNativeSourceFiles(entryPath, entryRelative, output);
    else if (entry.isFile()) output.push({
      path: entryRelative,
      sha256: crypto.createHash("sha256").update(fs.readFileSync(entryPath)).digest("hex"),
    });
    else throw new Error(`Unsupported native dependency package entry: ${entryRelative}`);
  }
  return output.sort((left, right) => left.path.localeCompare(right.path));
}
