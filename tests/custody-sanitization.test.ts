import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  clearKey,
  closeDb,
  completePendingCustodySanitization,
  getDb,
  getKey,
  getVaultDescriptor,
  hasPendingCustodySanitization,
  initializeVault,
  machineKeyAuthenticatesActiveVaultForTests,
  readOwnedKeyBuffersForTests,
  readSecretKeyClass,
  resolveSecret,
  setCustodySanitizationFaultForTests,
  setMachineIdentityForTests,
  storeSecret,
  summarizeKeyClasses,
  transitionRecordCustody,
  unlockVault,
} from "../src/vault.js";
import {
  evaluateAuthorizationRules,
  initializeAuthorizationPolicy,
  mutateAuthorizationRule,
  setAuthorizationRule,
} from "../src/policy.js";

const MACHINE_IDENTITY_BYTE = 41;
const PASSPHRASE = "synthetic-custody-passphrase";

describe("custody sanitization", () => {
  let root: string;
  let home: string;
  let previousHome: string | undefined;

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-custody-sanitize-"));
    home = path.join(root, ".keyclasp");
    previousHome = process.env.KEYCLASP_HOME;
    process.env.KEYCLASP_HOME = home;
    closeDb();
    clearKey();
    setMachineIdentityForTests({ stable: Buffer.alloc(32, MACHINE_IDENTITY_BYTE) });
    initializeVault(PASSPHRASE);
    initializeAuthorizationPolicy("machine");
  });

  afterEach(() => {
    closeDb();
    clearKey();
    setCustodySanitizationFaultForTests(null);
    setMachineIdentityForTests(null);
    if (previousHome === undefined) delete process.env.KEYCLASP_HOME;
    else process.env.KEYCLASP_HOME = previousHome;
    fs.rmSync(root, { recursive: true, force: true });
  });

  function seedMachineRecords(count: number): void {
    for (let index = 0; index < count; index += 1) {
      storeSecret("app", "prod", `API_KEY_${index}`, `synthetic-value-${index}-${"a".repeat(80)}`, "machine");
    }
  }

  function lockProject(): { changed: number; tightened: number; machineRemaining: number } {
    let summary = { changed: 0, tightened: 0, machineRemaining: 0 };
    mutateAuthorizationRule({ project: "app" }, "lock", (database, rules, _generation, defaultCustody) => {
      summary = transitionRecordCustody(database, rules, evaluateAuthorizationRules, defaultCustody);
    });
    return summary;
  }

  function freshProcessRecoveredCount(): number {
    closeDb();
    clearKey();
    const code = `
      import fs from 'node:fs';
      import crypto from 'node:crypto';
      import path from 'node:path';
      import * as v from ${JSON.stringify(new URL("../dist/vault.js", import.meta.url).href)};
      v.setMachineIdentityForTests({stable:Buffer.alloc(32,${MACHINE_IDENTITY_BYTE})});
      const files=['vault.db','vault.db-wal','vault.db-shm'].flatMap(name=>{
        const file=path.join(process.env.KEYCLASP_HOME,name);return fs.existsSync(file)?[fs.readFileSync(file)]:[];
      });
      const raw=Buffer.concat(files), key=v.getKey(), vaultId=v.getVaultDescriptor().vaultId;
      const rows=v.getDb().prepare("SELECT * FROM secrets WHERE key_class = 'interactive'").all();
      let recovered=0;
      for(const row of rows){
        const marker=Buffer.concat([row.record_id,Buffer.from('secretmachine')]);
        let offset=raw.indexOf(marker);
        while(offset>=0){
          const start=offset+marker.length,len=row.encrypted_value.length;
          try{
            const decipher=crypto.createDecipheriv('aes-256-gcm',key,raw.subarray(start+len,start+len+12),{authTagLength:16});
            decipher.setAAD(v.buildRecordAssociatedData({vaultId,recordId:row.record_id,project:row.project,environment:row.environment,name:row.name,keyClass:'machine'}));
            decipher.setAuthTag(raw.subarray(start+len+12,start+len+28));
            const plaintext=Buffer.concat([decipher.update(raw.subarray(start,start+len)),decipher.final()]).toString();
            if(plaintext.startsWith('synthetic-value-')) recovered++;
            break;
          }catch{}
          offset=raw.indexOf(marker,offset+1);
        }
      }
      console.log(JSON.stringify({recovered}));
      v.closeDb();v.clearKey();
    `;
    const child = spawnSync(process.execPath, ["--input-type=module", "-e", code], {
      cwd: process.cwd(),
      env: { ...process.env, KEYCLASP_HOME: home },
      encoding: "utf8",
      timeout: 30_000,
    });
    expect(child.status, child.stderr).toBe(0);
    return (JSON.parse(child.stdout) as { recovered: number }).recovered;
  }

  it("enables secure deletion before writable secret storage", () => {
    expect(getDb().pragma("secure_delete", { simple: true })).toBe(1);
    storeSecret("app", "prod", "CHECK", "value", "machine");
    expect(getDb().pragma("secure_delete", { simple: true })).toBe(1);
  });

  it("sanitizes a whole-vault tightening and retires the old machine key", () => {
    seedMachineRecords(500);
    const oldMachineKey = Buffer.from(getKey());
    const initialGeneration = getVaultDescriptor().generation;
    expect(lockProject()).toEqual({ changed: 500, tightened: 500, machineRemaining: 0 });
    expect(hasPendingCustodySanitization()).toBe(true);

    expect(completePendingCustodySanitization(PASSPHRASE)).toEqual({ completed: true, machineKeyRetired: true });
    expect(hasPendingCustodySanitization()).toBe(false);
    expect(summarizeKeyClasses()).toEqual({ machine: 0, interactive: 500 });
    expect(getVaultDescriptor().generation).toBe(initialGeneration + 1);
    expect(machineKeyAuthenticatesActiveVaultForTests(oldMachineKey)).toBe(false);
    oldMachineKey.fill(0);
    clearKey();
    getKey();
    expect(() => resolveSecret("app", "prod", "API_KEY_0")).toThrow(/locked/i);
    unlockVault(PASSPHRASE);
    expect(resolveSecret("app", "prod", "API_KEY_0")).toMatch(/^synthetic-value-0-/);
    expect(freshProcessRecoveredCount()).toBe(0);
  }, 30_000);

  it("forces one-time sanitization for a pre-slice dual-key vault with no new custody delta", () => {
    seedMachineRecords(300);
    const oldMachineKey = Buffer.from(getKey());
    expect(lockProject()).toEqual({ changed: 300, tightened: 300, machineRemaining: 0 });
    getDb().prepare(`UPDATE vault_metadata SET custody_sanitization_required = 0,
      custody_sanitization_bundle_generation = NULL, custody_sanitization_version = 0 WHERE singleton = 1`).run();

    expect(hasPendingCustodySanitization()).toBe(true);
    expect(completePendingCustodySanitization(PASSPHRASE)).toEqual({ completed: true, machineKeyRetired: true });
    expect(hasPendingCustodySanitization()).toBe(false);
    expect(machineKeyAuthenticatesActiveVaultForTests(oldMachineKey)).toBe(false);
    oldMachineKey.fill(0);
    expect(freshProcessRecoveredCount()).toBe(0);
  }, 30_000);

  it("keeps remaining machine records usable while removing transitioned representations", () => {
    seedMachineRecords(100);
    for (let index = 0; index < 50; index += 1) {
      setAuthorizationRule({ project: "app", environment: "prod", secret: `API_KEY_${index}` }, false);
    }
    const initialGeneration = getVaultDescriptor().generation;
    expect(lockProject()).toEqual({ changed: 50, tightened: 50, machineRemaining: 50 });
    expect(completePendingCustodySanitization(PASSPHRASE)).toEqual({ completed: true, machineKeyRetired: false });
    expect(getVaultDescriptor().generation).toBe(initialGeneration);
    expect(summarizeKeyClasses()).toEqual({ machine: 50, interactive: 50 });
    expect(resolveSecret("app", "prod", "API_KEY_0")).toMatch(/^synthetic-value-0-/);
    expect(readSecretKeyClass("app", "prod", "API_KEY_50")).toBe("interactive");
    expect(freshProcessRecoveredCount()).toBe(0);
  }, 30_000);

  it.each([
    "after-checkpoint",
    "after-vacuum",
    "after-sidecar-cleanup",
    "after-validation",
    "after-machine-retirement",
    "after-clear",
  ] as const)("resumes safely after cleanup interruption %s", (fault) => {
    seedMachineRecords(500);
    lockProject();
    const owned = readOwnedKeyBuffersForTests();
    setCustodySanitizationFaultForTests(fault);
    expect(() => completePendingCustodySanitization(PASSPHRASE)).toThrow(/Injected custody sanitization interruption/);
    expect(owned.machine).toEqual(Buffer.alloc(32));
    expect(owned.interactive).toEqual(Buffer.alloc(32));
    expect(hasPendingCustodySanitization()).toBe(fault !== "after-clear");
    setCustodySanitizationFaultForTests(null);
    getKey();
    unlockVault(PASSPHRASE);
    expect(completePendingCustodySanitization(PASSPHRASE).completed).toBe(fault !== "after-clear");
    expect(hasPendingCustodySanitization()).toBe(false);
    expect(freshProcessRecoveredCount()).toBe(0);
  }, 60_000);

  it("does not report completion while retirement is waiting for a passphrase", () => {
    seedMachineRecords(10);
    lockProject();
    clearKey();
    expect(() => completePendingCustodySanitization()).toThrow(/sanitization is pending/i);
    expect(hasPendingCustodySanitization()).toBe(true);
  });

  it("overwrites owned cached key buffers when clearing succeeds", () => {
    const owned = readOwnedKeyBuffersForTests();
    expect(owned.machine).not.toBeNull();
    expect(owned.interactive).not.toBeNull();
    clearKey();
    expect(owned.machine).toEqual(Buffer.alloc(32));
    expect(owned.interactive).toEqual(Buffer.alloc(32));
  });
});
