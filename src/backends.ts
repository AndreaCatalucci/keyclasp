import { execSync } from "node:child_process";
import { resolveSecret, listSecrets, storeSecret, isInitialized } from "./vault.js";

export interface SecretBackend {
  name: string;
  resolve(name: string): string | null;
  list(): string[];
  store(name: string, value: string): void;
  isAvailable(): boolean;
}

// --- Local Encrypted Vault ---

function createLocalBackend(): SecretBackend {
  return {
    name: "local",
    resolve: (name) => resolveSecret(name),
    list: () => listSecrets().filter((n: string) => !n.startsWith("__keyblind")),
    store: (name, value) => storeSecret(name, value),
    isAvailable: () => isInitialized(),
  };
}

// --- 1Password CLI ---

function create1PasswordBackend(): SecretBackend {
  return {
    name: "1password",
    resolve: (name) => {
      try {
        const result = execSync(`op read "op://${name}"`, {
          encoding: "utf-8",
          stdio: ["pipe", "pipe", "ignore"],
        });
        return result.trim();
      } catch {
        return null;
      }
    },
    list: () => {
      try {
        const result = execSync("op item list --format json", {
          encoding: "utf-8",
          stdio: ["pipe", "pipe", "ignore"],
        });
        const items = JSON.parse(result) as { title: string }[];
        return items.map((i) => i.title);
      } catch {
        return [];
      }
    },
    store: (name, value) => {
      execSync(`op item create --category login --title "${name}" --password "${value}"`, {
        stdio: "ignore",
      });
    },
    isAvailable: () => {
      try {
        execSync("op --version", { stdio: "ignore" });
        return true;
      } catch {
        return false;
      }
    },
  };
}

// --- Bitwarden CLI ---

function createBitwardenBackend(): SecretBackend {
  return {
    name: "bitwarden",
    resolve: (name) => {
      try {
        const result = execSync(`bw get password "${name}"`, {
          encoding: "utf-8",
          stdio: ["pipe", "pipe", "ignore"],
        });
        return result.trim();
      } catch {
        return null;
      }
    },
    list: () => {
      try {
        const result = execSync('bw list items --search ""', {
          encoding: "utf-8",
          stdio: ["pipe", "pipe", "ignore"],
        });
        const items = JSON.parse(result) as { name: string }[];
        return items.map((i) => i.name);
      } catch {
        return [];
      }
    },
    store: () => {
      throw new Error("Bitwarden backend does not support storing via Keyblind. Use 'bw create' directly.");
    },
    isAvailable: () => {
      try {
        execSync("bw --version", { stdio: "ignore" });
        return true;
      } catch {
        return false;
      }
    },
  };
}

// --- Environment Variables ---

function createEnvBackend(): SecretBackend {
  return {
    name: "env",
    resolve: (name) => process.env[name] ?? null,
    list: () => Object.keys(process.env).filter((k) => !k.startsWith("npm_") && !k.startsWith("_")),
    store: () => {
      throw new Error("Env backend is read-only. Use 'keyblind set' with local backend.");
    },
    isAvailable: () => true,
  };
}

// --- Registry ---

const BACKEND_FACTORIES: Record<string, () => SecretBackend> = {
  local: createLocalBackend,
  "1password": create1PasswordBackend,
  bitwarden: createBitwardenBackend,
  env: createEnvBackend,
};

let _currentBackend: SecretBackend | null = null;

export function setBackend(name: string): SecretBackend {
  const factory = BACKEND_FACTORIES[name];
  if (!factory) {
    throw new Error(`Unknown backend: ${name}. Available: ${Object.keys(BACKEND_FACTORIES).join(", ")}`);
  }
  const backend = factory();
  if (!backend.isAvailable()) {
    throw new Error(`Backend "${name}" is not available on this system.`);
  }
  _currentBackend = backend;
  return backend;
}

export function getBackend(): SecretBackend {
  if (_currentBackend) return _currentBackend;
  _currentBackend = createLocalBackend();
  return _currentBackend;
}

export function listAvailableBackends(): { name: string; available: boolean }[] {
  return Object.entries(BACKEND_FACTORIES).map(([name, factory]) => ({
    name,
    available: (() => { try { return factory().isAvailable(); } catch { return false; } })(),
  }));
}
