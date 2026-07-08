import { describe, expect, it } from "vitest";
import { createServer } from "../src/server.js";

describe("MCP server surface", () => {
  it("registers the retained core tools and excludes removed surfaces", () => {
    const server = createServer() as any;
    const tools = Object.keys(server._registeredTools).sort();

    expect(tools).toEqual([
      "audit_log",
      "backend_status",
      "capabilities",
      "check_expired",
      "config_status",
      "create_share_link",
      "delete_secret",
      "expiring_soon",
      "generate_secret",
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
});
