import esbuild from "esbuild";
import { readFileSync, copyFileSync, mkdirSync } from "fs";
import { dirname } from "path";
import { fileURLToPath } from "url";

// Always resolve paths relative to this script's directory
const root = dirname(fileURLToPath(import.meta.url));
process.chdir(root);

const watch = process.argv.includes("--watch");

/** @type {esbuild.BuildOptions} */
const opts = {
  entryPoints: {
    "content": "src/content.ts",
    "background": "src/background.ts",
    "popup/popup": "src/popup/popup.ts",
  },
  outExtension: { ".js": ".js" },
  bundle: true,
  outdir: "dist",
  target: "es2022",
  format: "esm",
  sourcemap: false,
  minify: false,
  logLevel: "info",
};

if (watch) {
  const ctx = await esbuild.context(opts);
  await ctx.watch();
  console.log("Watching for changes...");
} else {
  await esbuild.build(opts);
  // Copy manifest and HTML to dist
  mkdirSync("dist/popup", { recursive: true });
  copyFileSync("manifest.json", "dist/manifest.json");
  copyFileSync("src/popup/popup.html", "dist/popup/popup.html");
  console.log("Build complete → dist/");
}
