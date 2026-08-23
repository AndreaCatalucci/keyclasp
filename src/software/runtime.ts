import {
  runPreparedCommandWithSecrets,
  type PreparedRunCommandOptions,
} from "../run.js";
import type { RunRuntime } from "../runtime.js";

type RunExecutor = (
  options: PreparedRunCommandOptions,
) => ReturnType<typeof runPreparedCommandWithSecrets>;

export interface SoftwareRunRuntimeDependencies {
  ensureUnlocked: () => Promise<void>;
  listSecretNames: (project: string, environment: string) => string[];
  resolveSecret: (project: string, environment: string, name: string) => string | null;
  resolveSecrets: (project: string, environment: string, names: readonly string[]) => ReadonlyMap<string, string>;
  baseEnv: () => NodeJS.ProcessEnv;
  stdout: (chunk: string) => void;
  stderr: (chunk: string) => void;
  execute?: RunExecutor;
}

export function createSoftwareRunRuntime(
  dependencies: SoftwareRunRuntimeDependencies,
): RunRuntime {
  const execute = dependencies.execute ?? runPreparedCommandWithSecrets;

  return {
    async run(request) {
      const { project, environment } = request.scope;
      const secretNames = dependencies.listSecretNames(project, environment);
      if (secretNames.length === 0) {
        dependencies.stderr(
          `Note: no secrets stored yet for project "${project}" environment "${environment}"; running with zero secrets injected.\n`,
        );
      }

      const outcome = await execute({
        request,
        baseEnv: dependencies.baseEnv(),
        secretNames,
        resolveSecret: (name) => dependencies.resolveSecret(project, environment, name),
        resolveSecrets: (names) => dependencies.resolveSecrets(project, environment, names),
        stdout: dependencies.stdout,
        stderr: dependencies.stderr,
        ensureUnlocked: dependencies.ensureUnlocked,
      });
      return { kind: outcome.kind, exitCode: outcome.exitCode };
    },
  };
}
