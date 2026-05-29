export interface TOTPConfig {
  name: string;
  issuer?: string;
  account?: string;
}

export interface DeadmanStatus {
  enabled: boolean;
  daysConfigured: number;
  daysSinceCheckin: number;
  daysRemaining: number;
  contactEmail: string;
  lastCheckin: string | null;
  nextDeadline: string;
  triggered: boolean;
}

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

  // Secrets
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

  async generateSecret(name: string, length?: number): Promise<{ name: string; value: string }> {
    return this.rest("/api/generate", {
      method: "POST",
      body: JSON.stringify({ name, length }),
    });
  }

  // Audit
  async getAuditLog(limit: number = 50): Promise<any[]> {
    const result = await this.rest(`/api/audit?limit=${limit}`);
    return result.entries || [];
  }

  // TOTP
  async getTOTPConfigs(): Promise<TOTPConfig[]> {
    const result = await this.rest("/api/totp");
    return result.configs || [];
  }

  async storeTOTP(name: string, uri: string): Promise<void> {
    await this.rest("/api/totp", {
      method: "POST",
      body: JSON.stringify({ name, uri }),
    });
  }

  async getTOTPCode(name: string): Promise<{ name: string; code: string; remainingSeconds: number }> {
    return this.rest(`/api/totp/${encodeURIComponent(name)}/code`);
  }

  async deleteTOTP(name: string): Promise<void> {
    await this.rest(`/api/totp/${encodeURIComponent(name)}`, {
      method: "DELETE",
    });
  }

  // Secret Sharing
  async createShareLink(
    name: string,
    options?: { ttl?: string; maxViews?: number }
  ): Promise<{ url: string; expiresAt?: string; maxViews?: number }> {
    return this.rest("/api/share", {
      method: "POST",
      body: JSON.stringify({ name, ...options }),
    });
  }

  async receiveShare(
    fragment: string,
    targetName?: string
  ): Promise<{ received: string; stored: boolean }> {
    return this.rest("/api/share/receive", {
      method: "POST",
      body: JSON.stringify({ fragment, targetName }),
    });
  }

  // Dead Man's Switch
  async getDeadmanStatus(): Promise<DeadmanStatus> {
    return this.rest("/api/deadman");
  }

  async deadmanCheckin(): Promise<{ message: string; nextCheckinBy?: string }> {
    return this.rest("/api/deadman/checkin", {
      method: "POST",
    });
  }
}
