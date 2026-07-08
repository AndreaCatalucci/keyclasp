import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { storeSecret, listSecrets, deleteSecret, resolveSecret, isInitialized, getAuditLog, setClientInfo, checkExpired, setExpiry, getExpiry, getProjectName } from "./vault.js";
import { getBackend, setBackend, listAvailableBackends } from "./backends.js";
import { sandboxEnvFile, unsandboxEnvFile, getEnvBackups } from "./sandbox.js";
import { generateTOTPCode, storeTOTP, listTOTP, deleteTOTP, parseOTPAuthURI } from "./totp.js";
import { createShareLink, receiveShare } from "./share.js";
import { readConfig, mergeConfig, generateSecret } from "./config.js";
import { saveHistory, getSecretHistory, rollbackSecret, getExpiringSoon } from "./sync.js";

const CAPABILITIES = [
  { name: "resolve_secret", category: "secret", safety: "read-secret", destructive: false, idempotent: true, returnsPlaintext: true },
  { name: "store_secret", category: "secret", safety: "write", destructive: false, idempotent: false, secretSensitiveInputs: ["value"] },
  { name: "list_secrets", category: "secret", safety: "read-metadata", destructive: false, idempotent: true },
  { name: "delete_secret", category: "secret", safety: "destructive", destructive: true, idempotent: true },
  { name: "sandbox_env", category: "env", safety: "state-changing", destructive: false, idempotent: false },
  { name: "unsandbox_env", category: "env", safety: "state-changing", destructive: false, idempotent: false },
  { name: "audit_log", category: "audit", safety: "read-metadata", destructive: false, idempotent: true },
  { name: "totp_code", category: "totp", safety: "read-secret-derived", destructive: false, idempotent: false },
  { name: "totp_store", category: "totp", safety: "write", destructive: false, idempotent: false, secretSensitiveInputs: ["uri"] },
  { name: "totp_list", category: "totp", safety: "read-metadata", destructive: false, idempotent: true },
  { name: "totp_delete", category: "totp", safety: "destructive", destructive: true, idempotent: true },
  { name: "create_share_link", category: "share", safety: "read-secret-derived", destructive: false, idempotent: false },
  { name: "receive_share", category: "share", safety: "write", destructive: false, idempotent: false, secretSensitiveInputs: ["fragment"] },
  { name: "vault_status", category: "context", safety: "read-metadata", destructive: false, idempotent: true },
  { name: "config_status", category: "context", safety: "read-metadata", destructive: false, idempotent: true },
  { name: "backend_status", category: "context", safety: "read-metadata", destructive: false, idempotent: true },
  { name: "capabilities", category: "context", safety: "read-metadata", destructive: false, idempotent: true },
  { name: "recent_activity", category: "context", safety: "read-metadata", destructive: false, idempotent: true },
  { name: "generate_secret", category: "secret", safety: "write", destructive: false, idempotent: false },
  { name: "rotate_secret", category: "secret", safety: "write", destructive: false, idempotent: false, secretSensitiveInputs: ["value"] },
  { name: "secret_history", category: "lifecycle", safety: "read-metadata", destructive: false, idempotent: true },
  { name: "rollback_secret", category: "lifecycle", safety: "state-changing", destructive: false, idempotent: false },
  { name: "check_expired", category: "lifecycle", safety: "read-metadata", destructive: false, idempotent: true },
  { name: "expiring_soon", category: "lifecycle", safety: "read-metadata", destructive: false, idempotent: true },
  { name: "set_config", category: "config", safety: "state-changing", destructive: false, idempotent: true },
  { name: "set_backend", category: "config", safety: "state-changing", destructive: false, idempotent: true },
];

function visibleSecretNames(): string[] {
  return listSecrets().filter((n) => !n.startsWith("_keyblind") && !n.startsWith("_totp") && !n.startsWith("__keyblind"));
}

function safeRecentActivity(limit: number): { total: number; byAction: Record<string, number>; recent: { action: string; timestamp: string }[] } {
  const entries = getAuditLog(limit);
  const byAction: Record<string, number> = {};
  for (const entry of entries) byAction[entry.action] = (byAction[entry.action] ?? 0) + 1;
  return {
    total: entries.length,
    byAction,
    recent: entries.slice(0, Math.min(limit, 10)).map((entry) => ({ action: entry.action, timestamp: entry.timestamp })),
  };
}

export function createServer(): McpServer {
  setClientInfo("mcp");

  const server = new McpServer({
    name: "keyblind",
    version: "0.6.0",
  });

  server.tool(
    "resolve_secret",
    "Read-secret/idempotent. Resolve a secret by name using the configured backend. Contract: this tool returns the plaintext secret value in MCP response content so the caller can use it at runtime; clients must avoid pasting that value into prompts, logs, or chat transcripts.",
    {
      name: z.string().describe("The name of the secret to resolve (e.g., OPENAI_API_KEY, DATABASE_URL)"),
    },
    async ({ name }) => {
      if (!isInitialized()) {
        return {
          content: [{ type: "text", text: '{"error":"Keyblind vault not initialized. Run: keyblind init"}' }],
          isError: true,
        };
      }

      const backend = getBackend();
      const value = backend.resolve(name);
      if (value === null) {
        const allNames = backend.list();
        return {
          content: [{ type: "text", text: JSON.stringify({ error: `Secret "${name}" not found. Available: ${allNames.join(", ") || "(none)"}` }) }],
          isError: true,
        };
      }

      return {
        content: [{ type: "text", text: JSON.stringify({ name, value }) }],
      };
    },
  );

  server.tool(
    "store_secret",
    "Write/non-idempotent. Store a secret in the encrypted vault. Secret-sensitive input: value. The value is encrypted with AES-256-GCM before storage.",
    {
      name: z.string().describe("A unique name for the secret (e.g., OPENAI_API_KEY, DATABASE_URL)"),
      value: z.string().describe("The secret value to encrypt and store"),
    },
    async ({ name, value }) => {
      if (!isInitialized()) {
        return {
          content: [{ type: "text", text: '{"error":"Keyblind vault not initialized. Run: keyblind init"}' }],
          isError: true,
        };
      }

      storeSecret(name, value);
      return {
        content: [{ type: "text", text: JSON.stringify({ stored: name, status: "encrypted_and_saved" }) }],
      };
    },
  );

  server.tool(
    "list_secrets",
    "Read-metadata/idempotent. List all stored secret names. Values are never returned.",
    {},
    async () => {
      if (!isInitialized()) {
        return {
          content: [{ type: "text", text: JSON.stringify({ secrets: [] }) }],
        };
      }

      const names = visibleSecretNames();
      return {
        content: [{ type: "text", text: JSON.stringify({ secrets: names }) }],
      };
    },
  );

  server.tool(
    "sandbox_env",
    "State-changing/non-idempotent. Replace real values in your .env file with deterministic fake values. Real values are encrypted and backed up to the vault. Use unsandbox_env to restore real values.",
    {
      filePath: z.string().optional().describe("Path to the .env file. Defaults to .env in current directory."),
    },
    async ({ filePath }) => {
      if (!isInitialized()) {
        return {
          content: [{ type: "text", text: '{"error":"Keyblind vault not initialized. Run: keyblind init"}' }],
          isError: true,
        };
      }

      try {
        const result = sandboxEnvFile(filePath);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              sandboxed: result.sandboxed,
              message: `${result.sandboxed.length} value(s) replaced with deterministic fakes. Real values backed up to vault.`,
            }),
          }],
        };
      } catch (err: any) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: err.message }) }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "unsandbox_env",
    "State-changing/non-idempotent. Restore real .env values from the vault. Reverses the sandbox operation.",
    {
      filePath: z.string().optional().describe("Path to the .env file. Defaults to .env in current directory."),
    },
    async ({ filePath }) => {
      if (!isInitialized()) {
        return {
          content: [{ type: "text", text: '{"error":"Keyblind vault not initialized. Run: keyblind init"}' }],
          isError: true,
        };
      }

      try {
        const restored = unsandboxEnvFile(filePath);
        return {
          content: [{
            type: "text",
            text: JSON.stringify({
              restored,
              message: `${restored.length} value(s) restored from vault.`,
            }),
          }],
        };
      } catch (err: any) {
        return {
          content: [{ type: "text", text: JSON.stringify({ error: err.message }) }],
          isError: true,
        };
      }
    },
  );

  server.tool(
    "delete_secret",
    "Destructive/idempotent. Delete a secret from the vault.",
    {
      name: z.string().describe("The name of the secret to delete"),
    },
    async ({ name }) => {
      if (!isInitialized()) {
        return {
          content: [{ type: "text", text: '{"error":"Keyblind vault not initialized. Run: keyblind init"}' }],
          isError: true,
        };
      }

      const deleted = deleteSecret(name);
      return {
        content: [{ type: "text", text: JSON.stringify({ deleted, name }) }],
      };
    },
  );

  server.tool(
    "audit_log",
    "Read-metadata/idempotent. View the audit log of secret resolutions, stores, and deletes. This legacy audit tool includes secret names; use recent_activity for a redacted summary.",
    {
      limit: z.number().optional().describe("Maximum number of entries to return (default: 50)"),
    },
    async ({ limit }) => {
      if (!isInitialized()) {
        return {
          content: [{ type: "text", text: JSON.stringify({ entries: [] }) }],
        };
      }

      const entries = getAuditLog(limit ?? 50);
      return {
        content: [{ type: "text", text: JSON.stringify({ entries }) }],
      };
    },
  );

  // TOTP tools
  server.tool(
    "totp_code",
    "Generate a TOTP 2FA code for a stored secret. Returns the current 6 or 8 digit code and seconds remaining until rotation.",
    { name: z.string().describe("Name of the stored TOTP configuration") },
    async ({ name }) => {
      if (!isInitialized()) {
        return { content: [{ type: "text", text: JSON.stringify({ error: "Vault not initialized" }) }], isError: true };
      }
      const result = generateTOTPCode(name);
      if (!result) {
        return { content: [{ type: "text", text: JSON.stringify({ error: `TOTP "${name}" not found` }) }], isError: true };
      }
      return { content: [{ type: "text", text: JSON.stringify({ name, code: result.code, remainingSeconds: result.remaining }) }] };
    },
  );

  server.tool(
    "totp_store",
    "Store a TOTP configuration from an otpauth:// URI (from QR code scan or manual entry).",
    {
      name: z.string().describe("A name to identify this TOTP config"),
      uri: z.string().describe("otpauth:// URI for the TOTP secret"),
    },
    async ({ name, uri }) => {
      if (!isInitialized()) {
        return { content: [{ type: "text", text: JSON.stringify({ error: "Vault not initialized" }) }], isError: true };
      }
      try {
        storeTOTP(name, uri);
        const config = parseOTPAuthURI(uri);
        return { content: [{ type: "text", text: JSON.stringify({ stored: name, issuer: config.issuer, account: config.account }) }] };
      } catch (err: any) {
        return { content: [{ type: "text", text: JSON.stringify({ error: err.message }) }], isError: true };
      }
    },
  );

  server.tool(
    "totp_list",
    "List all stored TOTP configurations.",
    {},
    async () => {
      if (!isInitialized()) {
        return { content: [{ type: "text", text: JSON.stringify({ totps: [] }) }] };
      }
      return { content: [{ type: "text", text: JSON.stringify({ totps: listTOTP() }) }] };
    },
  );

  server.tool(
    "totp_delete",
    "Delete a stored TOTP configuration.",
    { name: z.string().describe("Name of the TOTP config to delete") },
    async ({ name }) => {
      if (!isInitialized()) {
        return { content: [{ type: "text", text: JSON.stringify({ error: "Vault not initialized" }) }], isError: true };
      }
      const deleted = deleteTOTP(name);
      return { content: [{ type: "text", text: JSON.stringify({ deleted, name }) }] };
    },
  );

  // Secret sharing tools
  server.tool(
    "create_share_link",
    "Create an encrypted, expiring share link for a secret. The secret is encrypted into the URL fragment and never sent to any server.",
    {
      name: z.string().describe("Name of the secret to share"),
      ttl: z.string().optional().describe("Time to live, e.g. 24h, 7d, 30m (default: 24h)"),
      maxViews: z.number().optional().describe("Maximum number of times the link can be used (informational only)"),
    },
    async ({ name, ttl, maxViews }) => {
      if (!isInitialized()) {
        return { content: [{ type: "text", text: JSON.stringify({ error: "Vault not initialized" }) }], isError: true };
      }
      try {
        const { url, fragment } = createShareLink(name, { ttl, maxViews });
        return { content: [{ type: "text", text: JSON.stringify({ url, fragment: fragment.slice(0, 16) + "..." }) }] };
      } catch (err: any) {
        return { content: [{ type: "text", text: JSON.stringify({ error: err.message }) }], isError: true };
      }
    },
  );

  server.tool(
    "receive_share",
    "Receive and decrypt a shared secret from a share URL fragment.",
    {
      fragment: z.string().describe("The share URL fragment (everything after # in the share link)"),
      targetName: z.string().optional().describe("Optional: store under a different name"),
    },
    async ({ fragment, targetName }) => {
      if (!isInitialized()) {
        return { content: [{ type: "text", text: JSON.stringify({ error: "Vault not initialized" }) }], isError: true };
      }
      try {
        const { name } = receiveShare(fragment, targetName);
        return { content: [{ type: "text", text: JSON.stringify({ received: name, stored: true }) }] };
      } catch (err: any) {
        return { content: [{ type: "text", text: JSON.stringify({ error: err.message }) }], isError: true };
      }
    },
  );

  server.tool(
    "vault_status",
    "Read-metadata/idempotent. Return safe vault state: initialization, project, backend, visible secret count, sandbox backup count, warnings, and plaintext response contract.",
    {},
    async () => {
      const initialized = isInitialized();
      const warnings: string[] = [];
      if (!initialized) warnings.push("Vault not initialized. Run: keyblind init");
      const backend = getBackend();
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            initialized,
            project: getProjectName(),
            backend: backend.name,
            secretCount: initialized ? visibleSecretNames().length : 0,
            sandboxBackupCount: initialized ? getEnvBackups().size : 0,
            warnings,
            secretValueHandling: "resolve_secret returns plaintext in MCP response content by explicit contract",
          }),
        }],
      };
    },
  );

  server.tool(
    "config_status",
    "Read-metadata/idempotent. Return safe project config values without secret values.",
    {},
    async () => {
      const config = readConfig();
      return { content: [{ type: "text", text: JSON.stringify({ configured: config !== null, config: config ?? {} }) }] };
    },
  );

  server.tool(
    "backend_status",
    "Read-metadata/idempotent. Return current backend and available optional backend adapters.",
    {},
    async () => {
      return {
        content: [{
          type: "text",
          text: JSON.stringify({
            current: getBackend().name,
            available: listAvailableBackends(),
            defaultBackend: "local",
            note: "External backends are optional adapters and may require local CLIs or cloud credentials.",
          }),
        }],
      };
    },
  );

  server.tool(
    "capabilities",
    "Read-metadata/idempotent. Return retained MCP tools grouped with safety semantics.",
    {},
    async () => ({ content: [{ type: "text", text: JSON.stringify({ tools: CAPABILITIES }) }] }),
  );

  server.tool(
    "recent_activity",
    "Read-metadata/idempotent. Return a redacted audit summary without secret names or client info.",
    { limit: z.number().optional().describe("Maximum audit rows to summarize (default: 50)") },
    async ({ limit }) => {
      if (!isInitialized()) return { content: [{ type: "text", text: JSON.stringify({ total: 0, byAction: {}, recent: [] }) }] };
      return { content: [{ type: "text", text: JSON.stringify(safeRecentActivity(limit ?? 50)) }] };
    },
  );

  server.tool(
    "generate_secret",
    "Write/non-idempotent. Generate a strong random secret and store it in the configured backend. Returns metadata only, never the generated value.",
    {
      name: z.string().describe("Name to store the generated secret under"),
      length: z.number().optional().describe("Generated secret length (default: 32)"),
      symbols: z.boolean().optional().describe("Include symbols (default: true)"),
    },
    async ({ name, length, symbols }) => {
      if (!isInitialized()) return { content: [{ type: "text", text: JSON.stringify({ error: "Vault not initialized" }) }], isError: true };
      const value = generateSecret(length ?? 32, symbols ?? true);
      getBackend().store(name, value);
      return { content: [{ type: "text", text: JSON.stringify({ stored: name, generated: true, length: value.length }) }] };
    },
  );

  server.tool(
    "rotate_secret",
    "Write/non-idempotent. Replace an existing secret value and save previous value to encrypted history. Secret-sensitive input: value.",
    {
      name: z.string().describe("Name of the secret to rotate"),
      value: z.string().optional().describe("New secret value. If omitted, a generated value is stored."),
      length: z.number().optional().describe("Generated value length when value is omitted (default: 32)"),
      symbols: z.boolean().optional().describe("Include symbols when generating (default: true)"),
      expiresAt: z.string().optional().describe("Optional ISO expiry timestamp"),
    },
    async ({ name, value, length, symbols, expiresAt }) => {
      if (!isInitialized()) return { content: [{ type: "text", text: JSON.stringify({ error: "Vault not initialized" }) }], isError: true };
      const existing = resolveSecret(name);
      if (existing === null) return { content: [{ type: "text", text: JSON.stringify({ error: `Secret "${name}" not found` }) }], isError: true };
      saveHistory(name, existing);
      const nextValue = value ?? generateSecret(length ?? 32, symbols ?? true);
      storeSecret(name, nextValue);
      if (expiresAt) setExpiry(name, expiresAt);
      return { content: [{ type: "text", text: JSON.stringify({ rotated: name, generated: value === undefined, expiresAt: getExpiry(name) }) }] };
    },
  );

  server.tool(
    "secret_history",
    "Read-metadata/idempotent. List encrypted history versions for a secret without returning historical values.",
    {
      name: z.string().describe("Secret name"),
      limit: z.number().optional().describe("Maximum versions to return (default: 10)"),
    },
    async ({ name, limit }) => {
      if (!isInitialized()) return { content: [{ type: "text", text: JSON.stringify({ error: "Vault not initialized" }) }], isError: true };
      const history = getSecretHistory(name, limit ?? 10).map(({ version, createdAt }) => ({ version, createdAt }));
      return { content: [{ type: "text", text: JSON.stringify({ name, history }) }] };
    },
  );

  server.tool(
    "rollback_secret",
    "State-changing/non-idempotent. Restore a secret from encrypted history. Returns metadata only.",
    {
      name: z.string().describe("Secret name"),
      version: z.number().optional().describe("Specific version to restore; latest history entry if omitted"),
    },
    async ({ name, version }) => {
      if (!isInitialized()) return { content: [{ type: "text", text: JSON.stringify({ error: "Vault not initialized" }) }], isError: true };
      const rolledBack = rollbackSecret(name, version);
      return { content: [{ type: "text", text: JSON.stringify({ name, rolledBack, version: version ?? "latest" }) }] };
    },
  );

  server.tool(
    "check_expired",
    "Read-metadata/idempotent. List names of secrets past their expiry date. Values are never returned.",
    {},
    async () => {
      if (!isInitialized()) return { content: [{ type: "text", text: JSON.stringify({ expired: [] }) }] };
      return { content: [{ type: "text", text: JSON.stringify({ expired: checkExpired() }) }] };
    },
  );

  server.tool(
    "expiring_soon",
    "Read-metadata/idempotent. List names and expiry metadata for secrets expiring within a threshold. Values are never returned.",
    { days: z.number().optional().describe("Threshold in days (default: 30)") },
    async ({ days }) => {
      if (!isInitialized()) return { content: [{ type: "text", text: JSON.stringify({ expiring: [] }) }] };
      return { content: [{ type: "text", text: JSON.stringify({ expiring: getExpiringSoon(days ?? 30) }) }] };
    },
  );

  server.tool(
    "set_config",
    "State-changing/idempotent. Set safe project config keys: backend, projectName, expiryDays, autoSandbox, watchPath.",
    {
      key: z.enum(["backend", "projectName", "expiryDays", "autoSandbox", "watchPath"]),
      value: z.union([z.string(), z.number(), z.boolean()]).describe("Config value"),
    },
    async ({ key, value }) => {
      const config = mergeConfig({ [key]: value });
      return { content: [{ type: "text", text: JSON.stringify({ updated: key, config }) }] };
    },
  );

  server.tool(
    "set_backend",
    "State-changing/idempotent. Switch the active backend for this process and persist it in project config.",
    { name: z.string().describe("Backend name") },
    async ({ name }) => {
      try {
        const backend = setBackend(name);
        mergeConfig({ backend: name });
        return { content: [{ type: "text", text: JSON.stringify({ backend: backend.name }) }] };
      } catch (err: any) {
        return { content: [{ type: "text", text: JSON.stringify({ error: err.message }) }], isError: true };
      }
    },
  );

  return server;
}

export async function startServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
