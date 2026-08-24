export type RunResultKind = "blocked" | "exit" | "leak" | "error";

export interface RunResult {
  kind: RunResultKind;
  exitCode: number;
}

export interface RuntimeScope {
  project: string;
  environment: string;
}

export interface ScopedRunRequest {
  allowUnsafe: boolean;
  envSpecs: readonly RunEnvSpec[];
  commandArgs: readonly string[];
  scope: RuntimeScope;
}

export interface RunEnvSpec {
  sourceName: string;
  targetName: string;
}

export type OperatorAuthorization =
  | { method: "touch-id" }
  | { method: "passphrase"; passphrase: string };

export type OperatorAuthorizer = (reason: string) =>
  OperatorAuthorization | Promise<OperatorAuthorization>;

export function displayOperatorField(value: string): string {
  const reverseSolidus = String.fromCodePoint(92);
  let displayed = "";
  for (const character of value) {
    if (/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(character)) {
      displayed += `${reverseSolidus}u{${character.codePointAt(0)!.toString(16).toUpperCase()}}`;
    } else if (character === reverseSolidus) {
      displayed += reverseSolidus.repeat(2);
    } else if (character === '"') {
      displayed += `${reverseSolidus}"`;
    } else {
      displayed += character;
    }
  }
  return `"${displayed}"`;
}

export function revealSecretReason(parts: readonly string[]): string {
  return `Reveal secret ${parts.map(displayOperatorField).join("/")}`;
}

/**
 * Shared command-level boundary for software and hardware implementations.
 * Requests contain scope and command metadata; results contain process status.
 * The contract defines no field for vault keys, secret plaintext, or raw errors.
 */
export interface RunRuntime {
  run(request: ScopedRunRequest): Promise<RunResult>;
}
