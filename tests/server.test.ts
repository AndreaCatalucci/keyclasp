import { afterAll, beforeAll, describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createServer } from "../src/server.js";
import { getDisplayVersion } from "../src/version.js";
import { initializeVault, isInitialized, storeSecret, deleteSecret, deleteAlias, listAliases, closeDb } from "../src/vault.js";
import { setBackend } from "../src/backends.js";

const tmpDir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), "keyblind-server-test-")));
const vaultDir = path.join(tmpDir, ".keyblind");
const previousKeyblindHome = process.env.KEYBLIND_HOME;

beforeAll(() => {
  process.env.KEYBLIND_HOME = vaultDir;
  fs.mkdirSync(vaultDir, { recursive: true });
  if (!isInitialized()) initializeVault("server-test-passphrase");
  setBackend("local");
});

afterAll(() => {
  closeDb();
  if (previousKeyblindHome === undefined) {
    delete process.env.KEYBLIND_HOME;
  } else {
    process.env.KEYBLIND_HOME = previousKeyblindHome;
  }
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

describe("MCP server surface", () => {
  it("uses shared version metadata for MCP server info", () => {
    const server = createServer() as any;

    expect(server.server._serverInfo).toEqual({
      name: "keyblind",
      version: getDisplayVersion(),
    });
  });

  it("registers the retained core tools and excludes removed surfaces", () => {
    const server = createServer() as any;
    const tools = Object.keys(server._registeredTools).sort();

    expect(tools).toEqual([
      "audit_log",
      "backend_status",
      "capabilities",
      "check_expired",
      "config_status",
      "create_alias",
      "create_share_link",
      "delete_alias",
      "delete_secret",
      "expiring_soon",
      "generate_secret",
      "list_aliases",
      "list_secrets",
      "receive_share",
      "recent_activity",
      "resolve_secret",
      "rollback_secret",
      "rotate_secret",
      "sandbox_env",
      "secret_history",
      "set_backend",
      "set_config",
      "store_secret",
      "totp_code",
      "totp_delete",
      "totp_list",
      "totp_store",
      "unsandbox_env",
      "vault_status",
    ]);

    expect(tools).not.toContain("team_init");
    expect(tools).not.toContain("deadman_status");
    expect(tools).not.toContain("sso_status");
  });

  it("resolves local aliases through resolve_secret with safe metadata", async () => {
    const server = createServer() as any;
    storeSecret("MCP_ALIAS_HELLO", "mcp-secret-value");
    await server._registeredTools.create_alias.handler({
      target: "MCP_ALIAS_HELLO",
      alias: "MCP_ALIAS_WORLD",
    });

    const result = await server._registeredTools.resolve_secret.handler({ name: "MCP_ALIAS_WORLD" });
    const body = JSON.parse(result.content[0].text);

    expect(result.isError).not.toBe(true);
    expect(body).toEqual({
      name: "MCP_ALIAS_WORLD",
      value: "mcp-secret-value",
      alias: { requestedName: "MCP_ALIAS_WORLD", resolvedName: "MCP_ALIAS_HELLO" },
    });
  });

  it("lists aliases without plaintext values", async () => {
    const server = createServer() as any;
    storeSecret("MCP_ALIAS_LIST_TARGET", "metadata-only-secret");
    await server._registeredTools.create_alias.handler({
      target: "MCP_ALIAS_LIST_TARGET",
      alias: "MCP_ALIAS_LIST_ALIAS",
    });

    const result = await server._registeredTools.list_aliases.handler({});
    const text = result.content[0].text;
    const body = JSON.parse(text);

    expect(body.aliases).toEqual(expect.arrayContaining([
      { alias: "MCP_ALIAS_LIST_ALIAS", target: "MCP_ALIAS_LIST_TARGET" },
    ]));
    expect(text).not.toContain("metadata-only-secret");
  });

  it("rejects invalid alias creation through MCP", async () => {
    const server = createServer() as any;
    storeSecret("MCP_ALIAS_INVALID_TARGET", "value");

    const result = await server._registeredTools.create_alias.handler({
      target: "MCP_ALIAS_INVALID_TARGET",
      alias: "__keyblind_invalid",
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).error).toContain("reserved");
    expect(listAliases().map((entry) => entry.alias)).not.toContain("__keyblind_invalid");
  });

  it("deletes aliases through MCP without deleting the target", async () => {
    const server = createServer() as any;
    storeSecret("MCP_ALIAS_DELETE_TARGET", "value");
    await server._registeredTools.create_alias.handler({
      target: "MCP_ALIAS_DELETE_TARGET",
      alias: "MCP_ALIAS_DELETE_ALIAS",
    });

    const result = await server._registeredTools.delete_alias.handler({ alias: "MCP_ALIAS_DELETE_ALIAS" });

    expect(JSON.parse(result.content[0].text)).toEqual({ alias: "MCP_ALIAS_DELETE_ALIAS", deleted: true });
    expect(deleteSecret("MCP_ALIAS_DELETE_TARGET")).toBe(true);
    expect(deleteAlias("MCP_ALIAS_DELETE_ALIAS")).toBe(false);
  });

  it("returns a structured error when storing over an alias name", async () => {
    const server = createServer() as any;
    storeSecret("MCP_ALIAS_STORE_TARGET", "value");
    await server._registeredTools.create_alias.handler({
      target: "MCP_ALIAS_STORE_TARGET",
      alias: "MCP_ALIAS_STORE_ALIAS",
    });

    const result = await server._registeredTools.store_secret.handler({
      name: "MCP_ALIAS_STORE_ALIAS",
      value: "new-value",
    });

    expect(result.isError).toBe(true);
    expect(JSON.parse(result.content[0].text).error).toContain("already exists as an alias");
  });
});
