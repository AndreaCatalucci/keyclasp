export type RunResultKind = "blocked" | "exit" | "leak" | "error";

export interface RunResult {
  kind: RunResultKind;
  exitCode: number;
}

export interface RuntimeScope {
  project: string;
  environment: string;
}

export interface ScopedRunRequest {
  allowUnsafe: boolean;
  envSpecs: readonly RunEnvSpec[];
  commandArgs: readonly string[];
  scope: RuntimeScope;
}

export interface RunEnvSpec {
  sourceName: string;
  targetName: string;
}

/**
 * Shared command-level boundary for software and hardware implementations.
 * Requests contain scope and command metadata; results contain process status.
 * The contract defines no field for vault keys, secret plaintext, or raw errors.
 */
export interface RunRuntime {
  run(request: ScopedRunRequest): Promise<RunResult>;
}
