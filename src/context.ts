import fs from "node:fs";
import path from "node:path";
import { getVaultLocation, validateScopeName } from "./vault.js";

export interface GlobalFlags {
  project?: string;
  environment?: string;
  rest: string[];
}

export type FlagScanMode = "scan-all" | "scan-until-terminator";

// Pulls --project/-p and --environment/-E (or their --flag=value forms) out
// of argv, wherever they appear. "scan-all" scans the whole array — safe for
// commands with a single positional arg, since a global flag can't be
// confused with it. "scan-until-terminator" stops recognizing global flags
// at the first literal "--" so a child command's own arguments (keyclasp
// run's case) are never mistaken for them; everything at/after "--" is
// copied into `rest` untouched.
export function extractGlobalFlags(args: string[], mode: FlagScanMode = "scan-all"): GlobalFlags {
  const rest: string[] = [];
  let project: string | undefined;
  let environment: string | undefined;
  let scanning = true;

  for (let i = 0; i < args.length; i++) {
    const arg = args[i];

    if (mode === "scan-until-terminator" && arg === "--") {
      scanning = false;
      rest.push(...args.slice(i));
      break;
    }

    if (scanning && (arg === "--project" || arg === "-p")) {
      const value = args[i + 1];
      if (value === undefined) throw new Error("Missing value for --project.");
      project = value;
      i += 1;
      continue;
    }
    if (scanning && arg.startsWith("--project=")) {
      project = arg.slice("--project=".length);
      continue;
    }
    if (scanning && (arg === "--environment" || arg === "-E")) {
      const value = args[i + 1];
      if (value === undefined) throw new Error("Missing value for --environment.");
      environment = value;
      i += 1;
      continue;
    }
    if (scanning && arg.startsWith("--environment=")) {
      environment = arg.slice("--environment=".length);
      continue;
    }

    rest.push(arg);
  }

  return { project, environment, rest };
}

export type ContextSource = "flag" | "env" | "context-file" | "default";

export interface ResolvedContext {
  project: string;
  projectSource: ContextSource;
  environment: string;
  environmentSource: ContextSource;
}

export interface StoredContext {
  project?: string;
  environment?: string;
}

function contextFilePath(): string {
  return path.join(getVaultLocation(), "context.json");
}

// Missing file, malformed JSON, or invalid field types are all treated as
// "no persisted context" — never throws, so a corrupted context.json can't
// break unrelated commands.
export function readContext(): StoredContext | null {
  try {
    const parsed = JSON.parse(fs.readFileSync(contextFilePath(), "utf8"));
    if (typeof parsed !== "object" || parsed === null) return null;
    const project = typeof parsed.project === "string" ? parsed.project : undefined;
    const environment = typeof parsed.environment === "string" ? parsed.environment : undefined;
    if (project === undefined && environment === undefined) return null;
    return { project, environment };
  } catch {
    return null;
  }
}

export function writeContext(project: string, environment: string): void {
  validateScopeName(project, "project");
  validateScopeName(environment, "environment");
  const dir = getVaultLocation();
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { mode: 0o700, recursive: true });
  fs.writeFileSync(contextFilePath(), `${JSON.stringify({ project, environment }, null, 2)}\n`, { mode: 0o600 });
}

export function clearContext(): void {
  try {
    fs.unlinkSync(contextFilePath());
  } catch (err: any) {
    if (err?.code !== "ENOENT") throw err;
  }
}

function resolveField(
  flagValue: string | undefined,
  envValue: string | undefined,
  fileValue: string | undefined,
): { value: string; source: ContextSource } {
  if (flagValue !== undefined) return { value: flagValue, source: "flag" };
  if (envValue) return { value: envValue, source: "env" };
  if (fileValue !== undefined) return { value: fileValue, source: "context-file" };
  return { value: "default", source: "default" };
}

// Resolves project and environment independently through the same
// precedence ladder: explicit flag > KEYCLASP_PROJECT/KEYCLASP_ENVIRONMENT
// env var > persisted context.json > "default". A flag for one axis doesn't
// force the other axis to also come from a flag.
export function resolveContext(explicitProject?: string, explicitEnvironment?: string): ResolvedContext {
  const fileContext = readContext();
  const project = resolveField(explicitProject, process.env.KEYCLASP_PROJECT, fileContext?.project);
  const environment = resolveField(explicitEnvironment, process.env.KEYCLASP_ENVIRONMENT, fileContext?.environment);
  return {
    project: project.value,
    projectSource: project.source,
    environment: environment.value,
    environmentSource: environment.source,
  };
}
