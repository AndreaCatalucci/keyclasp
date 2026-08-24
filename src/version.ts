import { execFileSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

export interface GitState {
  available: boolean;
  shortSha?: string;
  dirty: boolean;
}

export type GitRunner = (args: string[]) => string;

export interface PackageVersionOptions {
  startDir?: string;
}

export interface GitStateOptions {
  cwd?: string;
  runGit?: GitRunner;
}

export interface DisplayVersionOptions extends PackageVersionOptions, GitStateOptions {
  plain?: boolean;
}

const DEFAULT_PACKAGE_START_DIR = path.dirname(fileURLToPath(import.meta.url));

function defaultRunGit(cwd: string): GitRunner {
  return (args: string[]) => execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "ignore"],
    timeout: 500,
  });
}

function findPackageJson(startDir: string): string {
  let current = path.resolve(startDir);

  while (true) {
    const candidate = path.join(current, "package.json");
    if (fs.existsSync(candidate)) return candidate;

    const parent = path.dirname(current);
    if (parent === current) {
      throw new Error(`Could not find package.json from ${startDir}`);
    }
    current = parent;
  }
}

export function getDeclaredPackageVersion(options: PackageVersionOptions = {}): string {
  const packageJsonPath = findPackageJson(options.startDir ?? DEFAULT_PACKAGE_START_DIR);
  const parsed = JSON.parse(fs.readFileSync(packageJsonPath, "utf8")) as { version?: unknown };

  if (typeof parsed.version !== "string" || parsed.version.length === 0) {
    throw new Error(`${packageJsonPath} is missing a string version`);
  }

  return parsed.version;
}

export function getGitState(options: GitStateOptions = {}): GitState {
  const cwd = options.cwd ?? process.cwd();
  const runGit = options.runGit ?? defaultRunGit(cwd);

  try {
    if (runGit(["rev-parse", "--is-inside-work-tree"]).trim() !== "true") {
      return { available: false, dirty: false };
    }

    const shortSha = runGit(["rev-parse", "--short", "HEAD"]).trim();
    if (!shortSha) return { available: false, dirty: false };

    return {
      available: true,
      shortSha,
      dirty: runGit(["status", "--porcelain"]).trim().length > 0,
    };
  } catch {
    return { available: false, dirty: false };
  }
}

export function formatDisplayVersion(packageVersion: string, gitState: GitState, options: { plain?: boolean } = {}): string {
  if (options.plain || !gitState.available || !gitState.shortSha) return packageVersion;

  const dirtySuffix = gitState.dirty ? ".dirty" : "";
  return `${packageVersion}-dev+git.${gitState.shortSha}${dirtySuffix}`;
}

export function getDisplayVersion(options: DisplayVersionOptions = {}): string {
  const packageJsonPath = findPackageJson(options.startDir ?? DEFAULT_PACKAGE_START_DIR);
  const packageRoot = path.dirname(packageJsonPath);
  const packageVersion = getDeclaredPackageVersion({ startDir: packageRoot });
  const hasOwnGitMetadata = fs.existsSync(path.join(packageRoot, ".git"));
  const gitState = options.cwd !== undefined || options.runGit !== undefined || hasOwnGitMetadata
    ? getGitState({ cwd: options.cwd ?? packageRoot, runGit: options.runGit })
    : { available: false, dirty: false };
  return formatDisplayVersion(packageVersion, gitState, { plain: options.plain });
}
