import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { storeSecret, listSecrets, deleteSecret, resolveSecret, isInitialized, getAuditLog, setClientInfo } from "./vault.js";
import { getBackend } from "./backends.js";
import { sandboxEnvFile, unsandboxEnvFile } from "./sandbox.js";
import { generateTOTPCode, storeTOTP, listTOTP, deleteTOTP, parseOTPAuthURI } from "./totp.js";
import { createShareLink, receiveShare } from "./share.js";
import { getDeadmanStatus, checkin } from "./deadman.js";
import { getSSOToken, isSSOAuthenticated } from "./sso.js";
import { teamInit, teamPush, teamPull, teamList, teamResolve, teamDelete } from "./team.js";

export function createServer(): McpServer {
  setClientInfo("mcp");

  const server = new McpServer({
    name: "keyblind",
    version: "0.6.0",
  });

  server.tool(
    "resolve_secret",
    "Resolve a secret by name using the configured backend (local vault, 1Password, Bitwarden, or env vars). Returns the decrypted value at runtime. The secret value is never visible in the LLM conversation transcript — it is resolved just-in-time for the current operation.",
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
    "Store a secret in the encrypted vault. The value is encrypted with AES-256-GCM before storage. The secret value is never visible in the LLM conversation transcript after this call.",
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
    "List all stored secret names (names only — values are never revealed in this listing).",
    {},
    async () => {
      if (!isInitialized()) {
        return {
          content: [{ type: "text", text: JSON.stringify({ secrets: [] }) }],
        };
      }

      const names = listSecrets().filter((n) => !n.startsWith("_keyblind") && !n.startsWith("_totp") && !n.startsWith("__keyblind"));
      return {
        content: [{ type: "text", text: JSON.stringify({ secrets: names }) }],
      };
    },
  );

  server.tool(
    "sandbox_env",
    "Replace real values in your .env file with deterministic fake values. Real values are encrypted and backed up to the vault. AI agents reading .env files will only see fakes. Use unsandbox_env to restore real values.",
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
    "Restore real .env values from the vault. Reverses the sandbox operation.",
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
    "Delete a secret from the vault.",
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
    "View the audit log of secret resolutions, stores, and deletes. Shows who accessed which secret and when.",
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

  // Dead man's switch tools
  server.tool(
    "deadman_status",
    "Check dead man's switch status — days until vault access is released to designated contacts.",
    {},
    async () => {
      if (!isInitialized()) {
        return { content: [{ type: "text", text: JSON.stringify({ error: "Vault not initialized" }) }], isError: true };
      }
      const status = getDeadmanStatus();
      return { content: [{ type: "text", text: JSON.stringify(status) }] };
    },
  );

  server.tool(
    "deadman_checkin",
    "Check in to reset the dead man's switch timer.",
    {},
    async () => {
      if (!isInitialized()) {
        return { content: [{ type: "text", text: JSON.stringify({ error: "Vault not initialized" }) }], isError: true };
      }
      checkin();
      const status = getDeadmanStatus();
      return { content: [{ type: "text", text: JSON.stringify({ checkedIn: true, daysRemaining: status.daysRemaining }) }] };
    },
  );

  // Team vault tools
  server.tool(
    "team_init",
    "Create a new shared team vault (encrypted SQLite). Requires a passphrase.",
    {
      passphrase: z.string().describe("Passphrase to encrypt the team vault"),
      path: z.string().optional().describe("Optional path for the team vault file"),
    },
    async ({ passphrase, path }) => {
      try {
        const vaultPath = teamInit(passphrase, path);
        return { content: [{ type: "text", text: JSON.stringify({ success: true, path: vaultPath }) }] };
      } catch (err: any) {
        return { content: [{ type: "text", text: JSON.stringify({ error: err.message }) }], isError: true };
      }
    },
  );

  server.tool(
    "team_push",
    "Push a local secret to the shared team vault.",
    {
      name: z.string().describe("Name of the secret to push"),
      passphrase: z.string().describe("Team vault passphrase"),
      value: z.string().optional().describe("Optional: value to push (if omitted, resolves from local vault)"),
    },
    async ({ name, passphrase, value }) => {
      try {
        const resolved = resolveSecret(name);
        if (!resolved && !value) {
          return { content: [{ type: "text", text: JSON.stringify({ error: `Secret "${name}" not found in local vault. Provide a value.` }) }], isError: true };
        }
        const secretValue = value || resolved!;
        teamPush(name, secretValue, passphrase);
        return { content: [{ type: "text", text: JSON.stringify({ success: true, name }) }] };
      } catch (err: any) {
        return { content: [{ type: "text", text: JSON.stringify({ error: err.message }) }], isError: true };
      }
    },
  );

  server.tool(
    "team_pull",
    "Import all secrets from the team vault into your local vault.",
    {
      passphrase: z.string().describe("Team vault passphrase"),
    },
    async ({ passphrase }) => {
      try {
        const names = teamPull(passphrase);
        return { content: [{ type: "text", text: JSON.stringify({ success: true, imported: names.length, names }) }] };
      } catch (err: any) {
        return { content: [{ type: "text", text: JSON.stringify({ error: err.message }) }], isError: true };
      }
    },
  );

  server.tool(
    "team_list",
    "List all secret names in the team vault.",
    {
      passphrase: z.string().describe("Team vault passphrase"),
    },
    async ({ passphrase }) => {
      try {
        const names = teamList(passphrase);
        return { content: [{ type: "text", text: JSON.stringify({ names }) }] };
      } catch (err: any) {
        return { content: [{ type: "text", text: JSON.stringify({ error: err.message }) }], isError: true };
      }
    },
  );

  server.tool(
    "team_resolve",
    "Resolve (decrypt) a single secret from the team vault.",
    {
      name: z.string().describe("Name of the secret to resolve"),
      passphrase: z.string().describe("Team vault passphrase"),
    },
    async ({ name, passphrase }) => {
      try {
        const value = teamResolve(name, passphrase);
        if (value === null) {
          return { content: [{ type: "text", text: JSON.stringify({ error: `Secret "${name}" not found in team vault` }) }], isError: true };
        }
        return { content: [{ type: "text", text: JSON.stringify({ name, value }) }] };
      } catch (err: any) {
        return { content: [{ type: "text", text: JSON.stringify({ error: err.message }) }], isError: true };
      }
    },
  );

  server.tool(
    "team_delete",
    "Delete a secret from the team vault.",
    {
      name: z.string().describe("Name of the secret to delete"),
      passphrase: z.string().describe("Team vault passphrase"),
    },
    async ({ name, passphrase }) => {
      try {
        const deleted = teamDelete(name, passphrase);
        return { content: [{ type: "text", text: JSON.stringify({ success: deleted, name }) }] };
      } catch (err: any) {
        return { content: [{ type: "text", text: JSON.stringify({ error: err.message }) }], isError: true };
      }
    },
  );

  // SSO tools
  server.tool(
    "sso_status",
    "Check SSO/OIDC authentication status for team vault access.",
    {},
    async () => {
      const token = getSSOToken();
      if (token && token.expiresAt * 1000 > Date.now()) {
        return { content: [{ type: "text", text: JSON.stringify({ authenticated: true, email: token.claims.email, expiresAt: token.expiresAt }) }] };
      }
      return { content: [{ type: "text", text: JSON.stringify({ authenticated: false }) }] };
    },
  );

  return server;
}

export async function startServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
