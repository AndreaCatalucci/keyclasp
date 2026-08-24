import {
  runPreparedCommandWithSecrets,
  type PreparedRunCommandOptions,
} from "../run.js";
import { displayOperatorField } from "../runtime.js";
import type { OperatorAuthorizer, RunRuntime, ScopedRunRequest } from "../runtime.js";

type RunExecutor = (
  options: PreparedRunCommandOptions,
) => ReturnType<typeof runPreparedCommandWithSecrets>;

function displayCommand(commandArgs: readonly string[]): string {
  return commandArgs.map(displayOperatorField).join(" ");
}

function authorizationReason(
  request: ScopedRunRequest,
  selectedNames: readonly string[],
): string {
  const displayedSecrets = request.envSpecs.length === 0
    ? selectedNames.map(displayOperatorField)
    : request.envSpecs.map((spec) => spec.sourceName === spec.targetName
      ? displayOperatorField(spec.sourceName)
      : `${displayOperatorField(spec.sourceName)} → ${displayOperatorField(spec.targetName)}`);
  const reason = [
    `Run: ${displayCommand(request.commandArgs)}`,
    `Scope: ${displayOperatorField(request.scope.project)} / ${displayOperatorField(request.scope.environment)}`,
    `Secrets: ${displayedSecrets.join(", ") || "none"}`,
    `Output protection: ${request.allowUnsafe ? "DISABLED" : "enabled"}`,
  ].join("\n");
  return reason;
}

export interface SoftwareRunRuntimeDependencies {
  ensureUnlocked: () => Promise<void>;
  listSecretNames: (project: string, environment: string) => string[];
  resolveSecret: (project: string, environment: string, name: string) => string | null;
  resolveSecrets: (project: string, environment: string, names: readonly string[]) => ReadonlyMap<string, string>;
  baseEnv: () => NodeJS.ProcessEnv;
  stdout: (chunk: string) => void;
  stderr: (chunk: string) => void;
  readAuthorizationState: (project: string, environment: string, secret?: string) => "locked" | "unlocked";
  readKeyClass?: (project: string, environment: string, secret: string) => "machine" | "interactive" | null;
  authorize: OperatorAuthorizer;
  execute?: RunExecutor;
}

export function createSoftwareRunRuntime(
  dependencies: SoftwareRunRuntimeDependencies,
): RunRuntime {
  const execute = dependencies.execute ?? runPreparedCommandWithSecrets;

  return {
    async run(request) {
      const { project, environment } = request.scope;
      const locked = request.envSpecs.some((spec) =>
        dependencies.readAuthorizationState(project, environment, spec.sourceName) === "locked");
      const secretNames = dependencies.listSecretNames(project, environment);
      const selectedNames = request.envSpecs.length === 0
        ? secretNames
        : [...new Set(request.envSpecs.map((spec) => spec.sourceName))];
      const needsInteractive = selectedNames.some((name) =>
        dependencies.readKeyClass
          ? dependencies.readKeyClass(project, environment, name) === "interactive"
          : true);
      if (secretNames.length === 0) {
        dependencies.stderr(
          `Note: no secrets stored yet for project "${project}" environment "${environment}"; running with zero secrets injected.\n`,
        );
      }

      let reason: string | undefined;
      if (request.envSpecs.length === 0 || locked) {
        reason = authorizationReason(request, selectedNames);
      }

      const outcome = await execute({
        request,
        baseEnv: dependencies.baseEnv(),
        secretNames,
        resolveSecret: (name) => dependencies.resolveSecret(project, environment, name),
        resolveSecrets: (names) => dependencies.resolveSecrets(project, environment, names),
        stdout: dependencies.stdout,
        stderr: dependencies.stderr,
        ensureUnlocked: needsInteractive ? dependencies.ensureUnlocked : async () => undefined,
        authorizationRequired: locked,
        authorizationReason: reason,
        authorize: dependencies.authorize,
      });
      return { kind: outcome.kind, exitCode: outcome.exitCode };
    },
  };
}
