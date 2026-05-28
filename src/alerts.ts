import { readConfig } from "./config.js";

interface WebhookConfig {
  url: string;
  events: ("resolve" | "store" | "delete" | "rotate" | "expiry")[];
}

let _configs: WebhookConfig[] = [];

export function configureAlerts(configs: WebhookConfig[]): void {
  _configs = configs;
}

export function loadAlertsFromConfig(): void {
  const cfg = readConfig();
  if (cfg && (cfg as any).alertWebhooks) {
    _configs = (cfg as any).alertWebhooks;
  }
}

async function sendWebhook(url: string, payload: Record<string, any>): Promise<boolean> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);

    const response = await fetch(url, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
      signal: controller.signal,
    });
    clearTimeout(timeout);
    return response.ok;
  } catch {
    return false;
  }
}

export async function fireAlert(
  event: "resolve" | "store" | "delete" | "rotate" | "expiry",
  secretName: string,
  metadata?: Record<string, any>
): Promise<void> {
  if (_configs.length === 0) return;

  const payload = {
    event,
    secret: `[REDACTED]`, // Never expose secret values in alerts
    name: secretName,
    timestamp: new Date().toISOString(),
    hostname: process.env.HOSTNAME || "unknown",
    ...metadata,
  };

  for (const cfg of _configs) {
    if (cfg.events.includes(event)) {
      await sendWebhook(cfg.url, payload);
    }
  }
}

export function formatSlackPayload(payload: Record<string, any>): Record<string, any> {
  const emoji: Record<string, string> = {
    resolve: ":unlock:",
    store: ":lock:",
    delete: ":wastebasket:",
    rotate: ":arrows_counterclockwise:",
    expiry: ":warning:",
  };

  return {
    text: `${emoji[payload.event as string] || ":key:"} *${payload.event}* — \`${payload.name}\``,
    attachments: [{
      color: payload.event === "delete" ? "danger" : payload.event === "expiry" ? "warning" : "good",
      fields: [
        { title: "Event", value: payload.event, short: true },
        { title: "Secret", value: `\`${payload.name}\``, short: true },
        { title: "Time", value: payload.timestamp, short: true },
        { title: "Host", value: payload.hostname, short: true },
      ],
    }],
  };
}

export function formatDiscordPayload(payload: Record<string, any>): Record<string, any> {
  const colors: Record<string, number> = {
    resolve: 0x3fb950,
    store: 0x58a6ff,
    delete: 0xf85149,
    rotate: 0xd29922,
    expiry: 0xf0883e,
  };

  return {
    embeds: [{
      title: `${payload.event} — ${payload.name}`,
      color: colors[payload.event as string] || 0x58a6ff,
      fields: [
        { name: "Event", value: payload.event, inline: true },
        { name: "Secret", value: `\`${payload.name}\``, inline: true },
        { name: "Timestamp", value: payload.timestamp, inline: true },
        { name: "Host", value: payload.hostname, inline: true },
      ],
      footer: { text: "Keyblind Audit Alert" },
    }],
  };
}
