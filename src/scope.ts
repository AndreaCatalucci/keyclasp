export const SCOPE_NAME_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

export interface Scope {
  project: string;
  environment: string;
}

export interface ExtractedScopeFlags {
  project?: string;
  environment?: string;
  rest: string[];
}

export function validateScopeName(value: string, label: "project" | "environment"): void {
  if (!value || value.includes("\0") || !SCOPE_NAME_PATTERN.test(value)) {
    throw new Error(`Invalid ${label} name "${value}".`);
  }
}

export function extractScopeFlags(args: string[]): ExtractedScopeFlags {
  const rest: string[] = [];
  let project: string | undefined;
  let environment: string | undefined;

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index];
    if (arg === "--project" || arg === "-p") {
      const value = args[index + 1];
      if (value === undefined) throw new Error("Missing value for --project.");
      project = value;
      index += 1;
      continue;
    }
    if (arg.startsWith("--project=")) {
      project = arg.slice("--project=".length);
      continue;
    }
    if (arg === "--environment" || arg === "-E") {
      const value = args[index + 1];
      if (value === undefined) throw new Error("Missing value for --environment.");
      environment = value;
      index += 1;
      continue;
    }
    if (arg.startsWith("--environment=")) {
      environment = arg.slice("--environment=".length);
      continue;
    }
    rest.push(arg);
  }

  return { project, environment, rest };
}

export function resolveScope(project?: string, environment?: string): Scope {
  const resolved = {
    project: project ?? process.env.KEYCLASP_PROJECT ?? "default",
    environment: environment ?? process.env.KEYCLASP_ENVIRONMENT ?? "default",
  };
  validateScopeName(resolved.project, "project");
  validateScopeName(resolved.environment, "environment");
  return resolved;
}
