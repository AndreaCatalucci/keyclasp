import { afterEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { createSoftwareRunRuntime } from "../src/software/runtime.js";
import { readAuthorizationState, setAuthorizationRule } from "../src/policy.js";
import {
  clearKey,
  closeDb,
  initializeVault,
  listSecrets,
  resolveSecret,
  resolveSecretsForRun,
  setMachineIdentityForTests,
  storeSecret,
} from "../src/vault.js";

describe("run selection authorization decision", () => {
  const roots: string[] = [];
  const previousHome = process.env.KEYCLASP_HOME;

  afterEach(() => {
    closeDb();
    clearKey();
    setMachineIdentityForTests(null);
    if (previousHome === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previousHome;
    for (const root of roots.splice(0)) fs.rmSync(root, { recursive: true, force: true });
  });

  for (const selection of ["named", "whole"] as const) {
    for (const locked of [false, true]) {
      it(`${selection}, ${locked ? "locked" : "unlocked"}`, async () => {
          const root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-auth-matrix-"));
          roots.push(root);
          process.env.KEYCLASP_HOME = path.join(root, ".keyclasp");
          setMachineIdentityForTests({ stable: Buffer.alloc(32, 5) });
          initializeVault("");
          storeSecret("app", "prod", "API_KEY", "matrix-secret");
          setAuthorizationRule({ project: "app", environment: "prod", secret: "API_KEY" }, locked);
          clearKey();

          const authorize = vi.fn(() => ({ method: "touch-id" } as const));
          const runtime = createSoftwareRunRuntime({
            ensureUnlocked: async () => undefined,
            listSecretNames: (project, environment) => listSecrets(project, environment) as string[],
            resolveSecret,
            resolveSecrets: resolveSecretsForRun,
            readAuthorizationState,
            authorize,
            baseEnv: () => ({}),
            stdout: () => {},
            stderr: () => {},
          });
          const result = await runtime.run({
            allowUnsafe: false,
            envSpecs: selection === "named" ? [{ sourceName: "API_KEY", targetName: "API_KEY" }] : [],
            commandArgs: [process.execPath, "-e", "process.exit(process.env.API_KEY === 'matrix-secret' ? 0 : 9)"],
            scope: { project: "app", environment: "prod" },
          });
          expect(result).toEqual({ kind: "exit", exitCode: 0 });
          expect(authorize).toHaveBeenCalledTimes(selection === "whole" || locked ? 1 : 0);
      });
    }
  }
});
