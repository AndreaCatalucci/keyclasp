import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import fs from "node:fs";
import crypto from "node:crypto";
import os from "node:os";
import path from "node:path";
import Database from "better-sqlite3";
import { spawnSync } from "node:child_process";
import { pathToFileURL } from "node:url";
import {
  clearKey,
  closeDb,
  getVaultDescriptor,
  initializeVault,
  setMachineIdentityForTests,
} from "../src/vault.js";
import { appendAuthorizationPolicyAudit, authorizationSelectorFromCommand, readAuthorizationState, setAuthorizationRule, setAuthorizationRuleAuthorized, setPolicyMutationFaultForTests } from "../src/policy.js";

describe("authenticated authorization policy", () => {
  let root: string;
  let previousHome: string | undefined;
  const appScope = { project: "app", environment: "prod" } as const;
  const setAppScope = (locked: boolean) => setAuthorizationRule(appScope, locked);
  const readAppScope = () => readAuthorizationState("app", "prod");

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-policy-"));
    previousHome = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = path.join(root, ".keyclasp");
    closeDb();
    clearKey();
    setMachineIdentityForTests({ stable: Buffer.alloc(32, 7) });
    initializeVault("");
  });

  afterEach(() => {
    closeDb();
    clearKey();
    setMachineIdentityForTests(null);
    setPolicyMutationFaultForTests(null);
    if (previousHome === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previousHome;
    fs.rmSync(root, { recursive: true, force: true });
  });

  it("resolves exact, scope, one-dimensional, conflicting, override, and future-secret rules", () => {
    expect(readAuthorizationState("other", "dev", "FUTURE")).toBe("unlocked");

    setAuthorizationRule({ project: "app" }, true);
    expect(readAuthorizationState("app", "dev", "API_KEY")).toBe("locked");
    expect(readAuthorizationState("other", "dev", "API_KEY")).toBe("unlocked");

    setAuthorizationRule({ environment: "prod" }, false);
    expect(readAuthorizationState("app", "prod", "API_KEY")).toBe("locked");

    setAuthorizationRule({ project: "app", environment: "prod" }, false);
    expect(readAuthorizationState("app", "prod", "API_KEY")).toBe("unlocked");

    setAuthorizationRule({ project: "app", environment: "prod", secret: "API_KEY" }, true);
    expect(readAuthorizationState("app", "prod", "API_KEY")).toBe("locked");
    expect(readAuthorizationState("app", "prod", "OTHER")).toBe("unlocked");

    setAuthorizationRule({ project: "app", environment: "prod", secret: "API_KEY" }, false);
    expect(readAuthorizationState("app", "prod", "API_KEY")).toBe("unlocked");

    setAuthorizationRule({ environment: "future" }, true);
    expect(readAuthorizationState("new-project", "future", "NOT_STORED_YET")).toBe("locked");
  });

  it.each([
    { lockedDimension: "project", order: ["project", "environment"] },
    { lockedDimension: "project", order: ["environment", "project"] },
    { lockedDimension: "environment", order: ["project", "environment"] },
    { lockedDimension: "environment", order: ["environment", "project"] },
  ] as const)("lets locked win an equal-specificity conflict when $lockedDimension is locked and insertion order is $order", ({ lockedDimension, order }) => {
    for (const dimension of order) {
      setAuthorizationRule(
        dimension === "project" ? { project: "app" } : { environment: "prod" },
        dimension === lockedDimension,
      );
    }
    expect(readAuthorizationState("app", "prod", "API_KEY")).toBe("locked");
  });

  it("accepts every public rule shape and requires both flags for a secret", () => {
    expect(authorizationSelectorFromCommand("app", undefined, [])).toEqual({ project: "app" });
    expect(authorizationSelectorFromCommand(undefined, "prod", [])).toEqual({ environment: "prod" });
    expect(authorizationSelectorFromCommand("app", "prod", [])).toEqual({ project: "app", environment: "prod" });
    expect(authorizationSelectorFromCommand("app", "prod", ["API_KEY"])).toEqual({ project: "app", environment: "prod", secret: "API_KEY" });
    expect(() => authorizationSelectorFromCommand(undefined, undefined, [])).toThrow(/scope/i);
    expect(() => authorizationSelectorFromCommand("app", undefined, ["API_KEY"])).toThrow(/scope/i);
    expect(() => authorizationSelectorFromCommand(undefined, "prod", ["API_KEY"])).toThrow(/scope/i);
  });

  it("stores explicit unlocks and does not advance an unchanged rule", () => {
    const home = process.env.KEYCLASP_HOME!;
    expect(setAuthorizationRule({ project: "app", environment: "prod" }, false)).toBe("unlocked");
    expect(fs.existsSync(path.join(home, "strict-policy.v1.json"))).toBe(true);
    const enabled = JSON.parse(fs.readFileSync(path.join(home, "strict-policy.v1.json"), "utf8"));
    setAuthorizationRule({ project: "app", environment: "prod" }, false);
    const repeated = JSON.parse(fs.readFileSync(path.join(home, "strict-policy.v1.json"), "utf8"));
    expect(repeated.generation).toBe(enabled.generation);
    expect(repeated.rules).toEqual([{ project: "app", environment: "prod", locked: false }]);
  });

  it("reads an authenticated v1 scope lock and upgrades it on the next mutation", () => {
    const home = process.env.KEYCLASP_HOME!;
    const key = crypto.randomBytes(32);
    const payload = {
      version: 1,
      vaultId: getVaultDescriptor().vaultId.toString("base64"),
      generation: 1,
      records: [{ project: "legacy", environment: "prod", strict: true }],
    };
    const mac = crypto.createHmac("sha256", key)
      .update("keyclasp:strict-policy:v1")
      .update("\0")
      .update(JSON.stringify(payload))
      .digest("base64");
    const document = { ...payload, mac };
    const documentHash = crypto.createHash("sha256").update(JSON.stringify(document)).digest("base64");
    fs.writeFileSync(path.join(home, "strict-policy.v1.json"), `${JSON.stringify(document)}\n`, { mode: 0o600 });
    fs.writeFileSync(path.join(home, ".strict-policy.key"), `${JSON.stringify({
      version: 1,
      key: key.toString("base64"),
      generation: 1,
      documentHash,
    })}\n`, { mode: 0o600 });
    closeDb();
    const db = new Database(path.join(home, "vault.db"));
    db.exec("ALTER TABLE vault_metadata ADD COLUMN strict_policy_generation INTEGER");
    db.exec("ALTER TABLE vault_metadata ADD COLUMN strict_policy_required INTEGER NOT NULL DEFAULT 0");
    db.exec("ALTER TABLE vault_metadata ADD COLUMN strict_policy_document_hash TEXT");
    db.prepare("UPDATE vault_metadata SET strict_policy_required = 1, strict_policy_generation = 1, strict_policy_document_hash = ? WHERE singleton = 1")
      .run(documentHash);
    db.close();

    expect(readAuthorizationState("legacy", "prod", "FUTURE")).toBe("locked");
    setAuthorizationRule({ project: "legacy", environment: "prod" }, false);
    const upgraded = JSON.parse(fs.readFileSync(path.join(home, "strict-policy.v1.json"), "utf8"));
    expect(upgraded.version).toBe(2);
    expect(upgraded.rules).toEqual([{ project: "legacy", environment: "prod", locked: false }]);
  });

  it("authorizes before unlock and mutation, and cancellation changes nothing", async () => {
    const unlock = vi.fn(async () => undefined);
    const mutate = vi.fn(setAuthorizationRule);
    await expect(setAuthorizationRuleAuthorized({ project: "app", environment: "prod" }, true, {
      authorize: () => { throw new Error("Touch ID cancelled."); },
      ensureUnlocked: unlock,
      mutate,
    })).rejects.toThrow(/cancelled/i);
    expect(unlock).not.toHaveBeenCalled();
    expect(mutate).not.toHaveBeenCalled();
    expect(readAuthorizationState("app", "prod")).toBe("unlocked");
  });

  it("authenticates the stored policy before requesting authorization or unlocking", async () => {
    const authorize = vi.fn();
    const unlock = vi.fn(async () => undefined);
    const mutate = vi.fn(setAuthorizationRule);
    await expect(setAuthorizationRuleAuthorized({ project: "app" }, true, {
      validatePolicy: () => { throw new Error("policy authentication failed"); },
      authorize,
      ensureUnlocked: unlock,
      mutate,
    })).rejects.toThrow(/authentication failed/i);
    expect(authorize).not.toHaveBeenCalled();
    expect(unlock).not.toHaveBeenCalled();
    expect(mutate).not.toHaveBeenCalled();
  });

  it("never follows an authorization audit symlink", () => {
    const home = process.env.KEYCLASP_HOME!;
    const target = path.join(home, ".keyclasp.key");
    const before = fs.readFileSync(target);
    fs.symlinkSync(target, path.join(home, "strict-policy-audit.jsonl"));

    expect(() => appendAuthorizationPolicyAudit({ project: "app" }, "lock", "success")).toThrow(/symbolic links|ELOOP/i);
    expect(fs.readFileSync(target)).toEqual(before);
  });

  it("rejects record tampering and scope transplant before vault unlock", () => {
    setAppScope(true);
    clearKey();
    const policyPath = path.join(process.env.KEYCLASP_HOME!, "strict-policy.v1.json");
    const document = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    document.rules[0].project = "other";
    fs.writeFileSync(policyPath, `${JSON.stringify(document)}\n`);
    expect(() => readAppScope()).toThrow(/failed authentication/i);
  });

  it("rejects replay of an older complete signed disabled policy", () => {
    setAppScope(true);
    setAppScope(false);
    const policyPath = path.join(process.env.KEYCLASP_HOME!, "strict-policy.v1.json");
    const anchorPath = path.join(process.env.KEYCLASP_HOME!, ".strict-policy.key");
    const oldDocument = fs.readFileSync(policyPath);
    const oldAnchor = fs.readFileSync(anchorPath);
    setAppScope(true);
    fs.writeFileSync(policyPath, oldDocument);
    fs.writeFileSync(anchorPath, oldAnchor);
    clearKey();
    expect(() => readAppScope()).toThrow(/commitment.*anchor/i);
  });

  it("rejects deletion of the complete strict-policy pair", () => {
    setAppScope(true);
    fs.unlinkSync(path.join(process.env.KEYCLASP_HOME!, "strict-policy.v1.json"));
    fs.unlinkSync(path.join(process.env.KEYCLASP_HOME!, ".strict-policy.key"));
    expect(() => readAppScope()).toThrow(/policy is missing/i);
  });

  it("does not let a forged pending transaction roll the generation anchor back", () => {
    setAppScope(true);
    setAppScope(false);
    const policyPath = path.join(process.env.KEYCLASP_HOME!, "strict-policy.v1.json");
    const anchorPath = path.join(process.env.KEYCLASP_HOME!, ".strict-policy.key");
    const oldDocument = fs.readFileSync(policyPath);
    const oldAnchor = fs.readFileSync(anchorPath);
    setAppScope(true);
    fs.writeFileSync(policyPath, oldDocument);
    fs.writeFileSync(anchorPath, oldAnchor);
    fs.writeFileSync(path.join(process.env.KEYCLASP_HOME!, ".strict-policy.pending"), `${JSON.stringify({
      version: 1,
      previousDocument: oldDocument.toString("base64"),
      previousAnchor: oldAnchor.toString("base64"),
      previousGeneration: 2,
      previousDocumentHash: JSON.parse(oldAnchor.toString("utf8")).documentHash,
    })}\n`, { mode: 0o600 });
    expect(() => readAppScope()).toThrow(/does not match the committed vault generation/i);
  });

  it("rejects a forged policy pair at the committed generation", () => {
    setAppScope(true);
    const home = process.env.KEYCLASP_HOME!;
    const policyPath = path.join(home, "strict-policy.v1.json");
    const anchorPath = path.join(home, ".strict-policy.key");
    const document = JSON.parse(fs.readFileSync(policyPath, "utf8"));
    const anchor = JSON.parse(fs.readFileSync(anchorPath, "utf8"));
    document.rules = [];
    const canonical = JSON.stringify({
      version: document.version,
      vaultId: document.vaultId,
      generation: document.generation,
      rules: document.rules,
    });
    document.mac = crypto.createHmac("sha256", Buffer.from(anchor.key, "base64"))
      .update("keyclasp:authorization-policy:v2")
      .update("\0")
      .update(canonical)
      .digest("base64");
    anchor.documentHash = crypto.createHash("sha256").update(JSON.stringify(document)).digest("base64");
    fs.writeFileSync(policyPath, `${JSON.stringify(document)}\n`);
    fs.writeFileSync(anchorPath, `${JSON.stringify(anchor)}\n`);
    expect(() => readAppScope()).toThrow(/commitment.*anchor/i);
  });

  for (const boundary of ["after-document", "after-anchor"] as const) {
    it(`recovers the prior authenticated generation after interruption ${boundary}`, () => {
      setAppScope(false);
      setPolicyMutationFaultForTests(boundary);
      expect(() => setAppScope(true)).toThrow(/Injected authorization-policy interruption/);
      setPolicyMutationFaultForTests(null);
      expect(readAppScope()).toBe("unlocked");
    });
  }

  for (const boundary of ["crash-after-document", "crash-after-anchor"] as const) {
    it(`recovers the prior generation on the first open after simulated process death ${boundary}`, () => {
      setAppScope(false);
      setPolicyMutationFaultForTests(boundary);
      expect(() => setAppScope(true)).toThrow(/Injected authorization-policy interruption/);
      expect(fs.existsSync(path.join(process.env.KEYCLASP_HOME!, ".strict-policy.pending"))).toBe(true);
      setPolicyMutationFaultForTests(null);
      expect(readAppScope()).toBe("unlocked");
      expect(fs.existsSync(path.join(process.env.KEYCLASP_HOME!, ".strict-policy.pending"))).toBe(false);
    });
  }

  it.each(["crash-after-document", "crash-after-anchor"] as const)("recovers %s in a fresh process after the faulting process exits", (boundary) => {
    setAppScope(false);
    closeDb();
    clearKey();
    const moduleUrl = pathToFileURL(path.join(process.cwd(), "dist", "policy.js")).href;
    const environment = { ...process.env, KEYCLASP_HOME: process.env.KEYCLASP_HOME };
    const crashed = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import { setAuthorizationRule, setPolicyMutationFaultForTests } from ${JSON.stringify(moduleUrl)};`,
      `setPolicyMutationFaultForTests(${JSON.stringify(boundary)});`,
      "try { setAuthorizationRule({ project: 'app', environment: 'prod' }, true); } catch { process.exit(23); }",
      "process.exit(24);",
    ].join("\n")], { encoding: "utf8", env: environment });
    expect(crashed.status, crashed.stderr).toBe(23);

    const recovered = spawnSync(process.execPath, ["--input-type=module", "-e", [
      `import { readAuthorizationState } from ${JSON.stringify(moduleUrl)};`,
      "process.stdout.write(readAuthorizationState('app', 'prod'));",
    ].join("\n")], { encoding: "utf8", env: environment });
    expect(recovered.status, recovered.stderr).toBe(0);
    expect(recovered.stdout).toBe("unlocked");
    expect(fs.existsSync(path.join(process.env.KEYCLASP_HOME!, ".strict-policy.pending"))).toBe(false);
  });

  it("reports success after the generation commits even when cleanup fails", () => {
    setAppScope(true);
    setPolicyMutationFaultForTests("after-commit-cleanup");
    expect(setAppScope(false)).toBe("unlocked");
    setPolicyMutationFaultForTests(null);
    expect(readAppScope()).toBe("unlocked");
  });

  it("finishes pending cleanup after a crash following the generation commit", () => {
    setAppScope(false);
    setPolicyMutationFaultForTests("crash-after-commit");
    expect(() => setAppScope(true)).toThrow(/committed generation/);
    expect(fs.existsSync(path.join(process.env.KEYCLASP_HOME!, ".strict-policy.pending"))).toBe(true);
    setPolicyMutationFaultForTests(null);
    expect(readAppScope()).toBe("locked");
    expect(fs.existsSync(path.join(process.env.KEYCLASP_HOME!, ".strict-policy.pending"))).toBe(false);
  });

  it("binds policy records to the vault identity", () => {
    setAppScope(true);
    const policy = fs.readFileSync(path.join(process.env.KEYCLASP_HOME!, "strict-policy.v1.json"));
    const anchor = fs.readFileSync(path.join(process.env.KEYCLASP_HOME!, ".strict-policy.key"));

    closeDb();
    clearKey();
    const otherHome = path.join(root, "other");
    process.env.KEYCLASP_HOME = otherHome;
    initializeVault("");
    fs.writeFileSync(path.join(otherHome, "strict-policy.v1.json"), policy, { mode: 0o600 });
    fs.writeFileSync(path.join(otherHome, ".strict-policy.key"), anchor, { mode: 0o600 });
    clearKey();
    expect(() => readAppScope()).toThrow(/failed authentication/i);
  });
});
