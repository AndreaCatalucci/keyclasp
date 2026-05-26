import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { storeSecret, listSecrets, deleteSecret, isInitialized } from "./vault.js";
import { getBackend } from "./backends.js";
import { sandboxEnvFile, unsandboxEnvFile } from "./sandbox.js";

export function createServer(): McpServer {
  const server = new McpServer({
    name: "keyblind",
    version: "0.1.0",
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

      const names = listSecrets().filter((n) => !n.startsWith("__keyblind"));
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

  return server;
}

export async function startServer(): Promise<void> {
  const server = createServer();
  const transport = new StdioServerTransport();
  await server.connect(transport);
}
