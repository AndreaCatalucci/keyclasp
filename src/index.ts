// Note: deleteProject/deleteEnvironmentInProject/deleteEnvironmentAcrossAllProjects
// and the rename* functions below run with no confirmation prompt at this
// layer — the CLI's typed-confirmation / non-TTY-refusal safety net for bulk
// deletes lives entirely in cli.ts. Library callers are responsible for their
// own confirmation before invoking these.
export {
  initializeVault,
  storeSecret,
  resolveSecret,
  listSecrets,
  deleteSecret,
  isInitialized,
  getKey,
  getVaultLocation,
  closeDb,
  checkVaultDecryptability,
  validateScopeName,
  isNewProjectEnvironment,
  projects,
  environments,
  deleteProject,
  deleteEnvironmentInProject,
  deleteEnvironmentAcrossAllProjects,
  renameProject,
  renameEnvironmentInProject,
  renameEnvironmentAcrossAllProjects,
  renameScope,
  type DecryptabilityCheck,
  type ScopedSecret,
} from "./vault.js";
export { parseRunArgs, runCommandWithSecrets, buildRunEnvironment, checkUnsafeCommand, createSecretRedactor, type RunOutcome, type RunEnvSpec } from "./run.js";
export {
  requireBiometricAuthentication,
  resolveSecretForOperator,
  type BiometricAuthenticationOptions,
  type BiometricRunner,
  type BiometricRunnerResult,
} from "./biometric.js";
export {
  extractGlobalFlags,
  resolveContext,
  readContext,
  writeContext,
  clearContext,
  type GlobalFlags,
  type ResolvedContext,
  type StoredContext,
} from "./context.js";
