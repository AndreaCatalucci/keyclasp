export { initializeVault, storeSecret, resolveSecret, listSecrets, deleteSecret, isInitialized, getKey, closeDb, setRequireSession, setProjectName, getProjectName } from "./vault.js";
export { createServer, startServer } from "./server.js";
export { sandboxEnvFile, unsandboxEnvFile, getEnvBackups } from "./sandbox.js";
export { setBackend, getBackend, listAvailableBackends, type SecretBackend } from "./backends.js";
export { authenticateWithBiometric, biometricAvailable, createSession, sessionActive, clearSession } from "./auth.js";
