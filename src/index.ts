// The npm package exposes metadata and validation helpers only. Vault mutation,
// plaintext resolution, authentication state, and child-process execution stay
// behind the CLI boundary so package callers cannot bypass its safety checks.
export {
  getVaultLocation,
  validateScopeName,
} from "./vault.js";
export { parseRunArgs, checkUnsafeCommand, type RunEnvSpec } from "./run.js";
export {
  evaluateBiometricAuthentication,
  type BiometricEvaluation,
  type BiometricRunner,
  type BiometricRunnerResult,
} from "./biometric.js";
export {
  extractGlobalFlags,
  resolveContext,
  readContext,
  type GlobalFlags,
  type ResolvedContext,
  type StoredContext,
} from "./context.js";
