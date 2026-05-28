export class KeyblindClient {
  constructor(
    private baseUrl: string = "http://localhost:3100",
    private token?: string
  ) {}

  private async call(tool: string, args: Record<string, any> = {}) {
    const res = await fetch(`${this.baseUrl}/mcp`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
      },
      body: JSON.stringify({
        jsonrpc: "2.0",
        method: "tools/call",
        params: { name: tool, arguments: args },
        id: Date.now(),
      }),
    });
    if (!res.ok) throw new Error(`MCP call failed: ${res.status}`);
    const data = await res.json();
    if (data.error) throw new Error(data.error.message || "MCP error");
    return JSON.parse(data.result?.content?.[0]?.text || "{}");
  }

  async checkHealth(): Promise<boolean> {
    try {
      const res = await fetch(`${this.baseUrl}/health`);
      return res.ok;
    } catch {
      return false;
    }
  }

  async getSecrets(): Promise<string[]> {
    const result = await this.call("list_secrets");
    return result.secrets || [];
  }

  async getSecret(name: string): Promise<string> {
    const result = await this.call("resolve_secret", { name });
    return result.value || "";
  }

  async storeSecret(name: string, value: string): Promise<void> {
    await this.call("store_secret", { name, value });
  }

  async deleteSecret(name: string): Promise<void> {
    await this.call("delete_secret", { name });
  }

  async getAuditLog(limit: number = 50): Promise<any[]> {
    const result = await this.call("audit_log", { limit });
    return result.entries || [];
  }
}
