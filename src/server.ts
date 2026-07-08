import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { StreamableHTTPServerTransport } from "@modelcontextprotocol/sdk/server/streamableHttp.js";
import { z } from "zod";
import http from "node:http";
import { storeSecret, listSecrets, deleteSecret, resolveSecret, isInitialized, getAuditLog, setClientInfo } from "./vault.js";
import { getBackend } from "./backends.js";
import { sandboxEnvFile, unsandboxEnvFile } from "./sandbox.js";
import { generateTOTPCode, storeTOTP, listTOTP, deleteTOTP, parseOTPAuthURI, getTOTP, type TOTPConfig } from "./totp.js";
import { createShareLink, receiveShare } from "./share.js";
import { getDeadmanStatus, checkin } from "./deadman.js";
import { verifyPairingToken } from "./pairing.js";
import { getSSOToken, isSSOAuthenticated } from "./sso.js";
import { createHttpsServer, certExists, certExpiringSoon, provisionCert, startAutoRenewal, type ACMEOptions } from "./https.js";
import { generateSecret } from "./config.js";
import { teamInit, teamPush, teamPull, teamList, teamResolve, teamDelete } from "./team.js";

function readBody(req: http.IncomingMessage): Promise<string> {
  return new Promise((resolve, reject) => {
    let body = "";
    req.on("data", (chunk: Buffer) => { body += chunk.toString(); });
    req.on("end", () => resolve(body));
    req.on("error", reject);
  });
}

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

export async function startHttpServer(port: number = 3100, httpsConfig?: ACMEOptions): Promise<void> {
  const mcpServer = createServer();

  // Single transport instance handles all requests with session management
  const transport = new StreamableHTTPServerTransport({
    sessionIdGenerator: undefined,
  });
  await mcpServer.connect(transport);

  const appHandler = async (req: http.IncomingMessage, res: http.ServerResponse) => {
    // CORS for browser-based clients
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type, Mcp-Session-Id, Accept");

    if (req.method === "OPTIONS") {
      res.writeHead(204);
      res.end();
      return;
    }

    // Health check
    if (req.url === "/health" || req.url === "/") {
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ status: "ok", server: "keyblind", version: "0.5.1", secretCount: isInitialized() ? listSecrets().filter((n: string) => !n.startsWith("_keyblind") && !n.startsWith("_totp")).length : 0 }));
      return;
    }

    // ── REST API (for browser dashboard) ──
    if (req.url === "/api/secrets" && req.method === "GET") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      const names = listSecrets().filter((n: string) => !n.startsWith("_keyblind") && !n.startsWith("_totp") && !n.startsWith("__keyblind"));
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ secrets: names }));
      return;
    }

    if (req.url === "/api/secrets" && req.method === "POST") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      const body = await readBody(req);
      try {
        const { name, value } = JSON.parse(body);
        if (!name || value === undefined) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "name and value required" })); return; }
        storeSecret(name, value);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ stored: name }));
      } catch { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Invalid JSON" })); }
      return;
    }

    if (req.url?.startsWith("/api/secrets/") && req.method === "GET") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      const name = decodeURIComponent(req.url.slice("/api/secrets/".length));
      const backend = getBackend();
      const value = backend.resolve(name);
      if (value === null) { res.writeHead(404, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not found" })); return; }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ name, value }));
      return;
    }

    if (req.url?.startsWith("/api/secrets/") && req.method === "DELETE") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      const name = decodeURIComponent(req.url.slice("/api/secrets/".length));
      deleteSecret(name);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ deleted: name }));
      return;
    }

    if (req.url?.startsWith("/api/audit") && req.method === "GET") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      const url = new URL(req.url, `http://localhost:${port}`);
      const limit = parseInt(url.searchParams.get("limit") || "50", 10);
      const entries = getAuditLog(limit);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ entries }));
      return;
    }

    // ── TOTP REST API ──
    if (req.url === "/api/totp" && req.method === "GET") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      const totps = listTOTP().map((name: string) => {
        const config = getTOTP(name);
        return config ? { name: config.name, issuer: config.issuer, account: config.account } : { name };
      });
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ configs: totps }));
      return;
    }

    if (req.url === "/api/totp" && req.method === "POST") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      const body = await readBody(req);
      try {
        const { name, uri } = JSON.parse(body);
        if (!name || !uri) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "name and uri required" })); return; }
        storeTOTP(name, uri);
        const config = parseOTPAuthURI(uri);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ stored: name, issuer: config.issuer, account: config.account }));
      } catch (err: any) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: err.message || "Invalid request" })); }
      return;
    }

    if (req.url?.startsWith("/api/totp/") && req.url.endsWith("/code") && req.method === "GET") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      const name = decodeURIComponent(req.url.slice("/api/totp/".length, -"/code".length));
      const result = generateTOTPCode(name);
      if (!result) { res.writeHead(404, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not found" })); return; }
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ name, code: result.code, remainingSeconds: result.remaining }));
      return;
    }

    if (req.url?.startsWith("/api/totp/") && req.method === "DELETE") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      const name = decodeURIComponent(req.url.slice("/api/totp/".length));
      deleteTOTP(name);
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ deleted: name }));
      return;
    }

    // ── Share REST API ──
    if (req.url === "/api/share" && req.method === "POST") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      const body = await readBody(req);
      try {
        const { name, ttl, maxViews } = JSON.parse(body);
        if (!name) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "name required" })); return; }
        const { url } = createShareLink(name, { ttl, maxViews });
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ url }));
      } catch (err: any) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: err.message || "Invalid request" })); }
      return;
    }

    if (req.url === "/api/share/receive" && req.method === "POST") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      const body = await readBody(req);
      try {
        const { fragment, targetName } = JSON.parse(body);
        if (!fragment) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "fragment required" })); return; }
        const { name } = receiveShare(fragment, targetName);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ received: name, stored: true }));
      } catch (err: any) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: err.message || "Invalid request" })); }
      return;
    }

    // ── Deadman REST API ──
    if (req.url === "/api/deadman" && req.method === "GET") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      const status = getDeadmanStatus();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify(status));
      return;
    }

    if (req.url === "/api/deadman/checkin" && req.method === "POST") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      checkin();
      const status = getDeadmanStatus();
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ checkedIn: true, ...status }));
      return;
    }

    // ── Team REST API ──
    if (req.url === "/api/team/init" && req.method === "POST") {
      const body = await readBody(req);
      try {
        const { passphrase, path } = JSON.parse(body);
        if (!passphrase) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "passphrase required" })); return; }
        const vaultPath = teamInit(passphrase, path);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true, path: vaultPath }));
      } catch (err: any) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: err.message })); }
      return;
    }

    if (req.url === "/api/team/list" && req.method === "POST") {
      const body = await readBody(req);
      try {
        const { passphrase } = JSON.parse(body);
        if (!passphrase) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "passphrase required" })); return; }
        const names = teamList(passphrase);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ names }));
      } catch (err: any) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: err.message })); }
      return;
    }

    if (req.url === "/api/team/push" && req.method === "POST") {
      const body = await readBody(req);
      try {
        const { name, value, passphrase } = JSON.parse(body);
        if (!name || !passphrase) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "name and passphrase required" })); return; }
        const resolved = resolveSecret(name);
        if (!resolved && !value) { res.writeHead(404, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: `Secret "${name}" not found in local vault` })); return; }
        const secretValue = value || resolved!;
        teamPush(name, secretValue, passphrase);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true, name }));
      } catch (err: any) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: err.message })); }
      return;
    }

    if (req.url === "/api/team/pull" && req.method === "POST") {
      const body = await readBody(req);
      try {
        const { passphrase } = JSON.parse(body);
        if (!passphrase) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "passphrase required" })); return; }
        const names = teamPull(passphrase);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: true, imported: names.length, names }));
      } catch (err: any) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: err.message })); }
      return;
    }

    if (req.url?.startsWith("/api/team/") && req.method === "DELETE") {
      const body = await readBody(req);
      try {
        const name = decodeURIComponent(req.url.slice("/api/team/".length));
        const { passphrase } = JSON.parse(body);
        if (!passphrase) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "passphrase required" })); return; }
        const deleted = teamDelete(name, passphrase);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ success: deleted, name }));
      } catch (err: any) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: err.message })); }
      return;
    }

    // ── Misc REST API ──
    if (req.url === "/api/generate" && req.method === "POST") {
      if (!isInitialized()) { res.writeHead(500, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Not initialized" })); return; }
      const body = await readBody(req);
      try {
        const { name, length, noSymbols } = JSON.parse(body);
        if (!name) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "name required" })); return; }
        const value = generateSecret(length || 32, !noSymbols);
        storeSecret(name, value);
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ stored: name, generated: true }));
      } catch (err: any) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: err.message || "Invalid request" })); }
      return;
    }

    // ── Dashboard pairing ──
    if (req.url === "/api/auth/pair" && req.method === "POST") {
      const body = await readBody(req);
      try {
        const { token } = JSON.parse(body);
        if (!token) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "token required" })); return; }
        const result = await verifyPairingToken(token);
        if (!result.valid) { res.writeHead(401, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: "Invalid or expired pairing token" })); return; }
        res.writeHead(200, { "Content-Type": "application/json" });
        res.end(JSON.stringify({ verified: true }));
      } catch (err: any) { res.writeHead(400, { "Content-Type": "application/json" }); res.end(JSON.stringify({ error: err.message || "Invalid request" })); }
      return;
    }

    // MCP endpoint
    if (req.url === "/mcp" || req.url?.startsWith("/mcp")) {
      await transport.handleRequest(req, res);
      return;
    }

    res.writeHead(404);
    res.end("Not found");
  };

  if (httpsConfig) {
    // HTTPS mode with Let's Encrypt
    if (!certExists(httpsConfig.domain) || certExpiringSoon(httpsConfig.domain)) {
      console.log(`[keyblind] Provisioning Let's Encrypt certificate for ${httpsConfig.domain}...`);
      await provisionCert(httpsConfig);
    }
    startAutoRenewal(httpsConfig.domain, httpsConfig.email);

    const { httpsServer, httpServer } = createHttpsServer(appHandler, httpsConfig);

    return new Promise((resolve) => {
      httpServer.listen(httpsConfig.httpPort || 80, () => {
        console.log(`HTTP redirect listening on port ${httpsConfig.httpPort || 80}`);
      });
      httpsServer.listen(httpsConfig.port || 443, () => {
        console.log(`Keyblind MCP HTTPS server listening on https://${httpsConfig.domain}:${httpsConfig.port || 443}`);
        console.log(`  MCP endpoint: https://${httpsConfig.domain}/mcp`);
        console.log(`  Health:       https://${httpsConfig.domain}/health`);
        resolve();
      });
    });
  }

  const httpServer = http.createServer(appHandler);

  return new Promise((resolve) => {
    httpServer.listen(port, () => {
      console.log(`Keyblind MCP HTTP server listening on http://localhost:${port}`);
      console.log(`  MCP endpoint: http://localhost:${port}/mcp`);
      console.log(`  Health:       http://localhost:${port}/health`);
      resolve();
    });
  });
}
