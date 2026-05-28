export interface VaultStatus {
  initialized: boolean;
  secretCount: number;
  license?: { tier: string; email: string };
}

export interface DetectedSecret {
  pattern: string;
  match: string;
  position: { line: number; col: number };
  element: string;
}

export interface ExtensionState {
  enabled: boolean;
  pasteInterception: boolean;
  highlightSecrets: boolean;
  monitoredSites: string[];
}
