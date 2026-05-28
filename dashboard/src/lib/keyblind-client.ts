export class KeyblindClient {
  constructor(
    private baseUrl: string = "http://localhost:3100",
    private token?: string
  ) {}

  private async rest(path: string, options: RequestInit = {}): Promise<any> {
    const res = await fetch(`${this.baseUrl}${path}`, {
      headers: {
        "Content-Type": "application/json",
        ...(this.token ? { Authorization: `Bearer ${this.token}` } : {}),
      },
      ...options,
    });
    if (!res.ok) {
      const data = await res.json().catch(() => ({}));
      throw new Error(data.error || `HTTP ${res.status}`);
    }
    return res.json();
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
    const result = await this.rest("/api/secrets");
    return result.secrets || [];
  }

  async getSecret(name: string): Promise<string> {
    const result = await this.rest(`/api/secrets/${encodeURIComponent(name)}`);
    return result.value || "";
  }

  async storeSecret(name: string, value: string): Promise<void> {
    await this.rest("/api/secrets", {
      method: "POST",
      body: JSON.stringify({ name, value }),
    });
  }

  async deleteSecret(name: string): Promise<void> {
    await this.rest(`/api/secrets/${encodeURIComponent(name)}`, {
      method: "DELETE",
    });
  }

  async getAuditLog(limit: number = 50): Promise<any[]> {
    const result = await this.rest(`/api/audit?limit=${limit}`);
    return result.entries || [];
  }
}
