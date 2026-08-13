#!/usr/bin/env node
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";
import { execFileSync } from "node:child_process";
import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const Database = require("better-sqlite3");

const V2_MAGIC = Buffer.from("keyclasp:v2\n", "utf8");
const V3_MAGIC = Buffer.from("keyclasp:v3\n", "utf8");
const MODE_PASSPHRASE = 0x50;
const MODE_MACHINE = 0x4d;
const KDF_PBKDF2 = 0x01;
const PBKDF2_ITERATIONS = 600_000;
const SALT_LENGTH = 32;
const KEY_LENGTH = 32;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;

function vaultHome() {
  return process.env.KEYCLASP_HOME
    ? path.resolve(process.env.KEYCLASP_HOME)
    : path.join(os.homedir(), ".keyclasp");
}

function xorWithKey(key, wrappingKey) {
  const output = Buffer.alloc(key.length);
  for (let i = 0; i < key.length; i++) output[i] = key[i] ^ wrappingKey[i % wrappingKey.length];
  return output;
}

function deriveLegacyMachineIdentity() {
  return crypto.createHash("sha256")
    .update([os.hostname(), os.userInfo().username, os.platform(), os.arch()].join(":"))
    .digest();
}

function deriveStableMachineIdentities() {
  const platform = os.platform();
  const probes = [];
  if (platform === "darwin") {
    probes.push(() => {
      try {
        const output = execFileSync("/usr/sbin/ioreg", ["-rd1", "-c", "IOPlatformExpertDevice"], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
          timeout: 2000,
        });
        return output.match(/"IOPlatformUUID"\s=\s"([^"]+)"/)?.[1] ?? null;
      } catch {
        return null;
      }
    });
  }
  probes.push(() => {
    for (const candidate of ["/etc/machine-id", "/var/lib/dbus/machine-id", "/var/db/db.uuid"]) {
      try {
        const value = fs.readFileSync(candidate, "utf8").trim();
        if (value) return value;
      } catch {
        // keep probing
      }
    }
    return null;
  });
  if (platform === "win32") {
    probes.push(() => {
      try {
        const output = execFileSync("reg", ["query", "HKLM\\SOFTWARE\\Microsoft\\Cryptography", "/v", "MachineGuid"], {
          encoding: "utf8",
          stdio: ["ignore", "pipe", "ignore"],
          timeout: 2000,
        });
        return output.match(/MachineGuid\s+REG_SZ\s+([^\r\n]+)/)?.[1]?.trim() ?? null;
      } catch {
        return null;
      }
    });
  }

  const identities = [];
  const seen = new Set();
  for (const probe of probes) {
    const value = probe();
    if (!value) continue;
    const identity = crypto.createHash("sha256").update(`stable:${platform}:${value}`).digest();
    const hex = identity.toString("hex");
    if (!seen.has(hex)) {
      seen.add(hex);
      identities.push(identity);
    }
  }
  identities.push(deriveLegacyMachineIdentity());
  return identities;
}

function wrappingKey(salt, identity) {
  return crypto.createHash("sha256").update(V2_MAGIC).update(salt).update(identity).digest();
}

function unwrapV2(keyData, dbPath) {
  if (!keyData.subarray(0, V2_MAGIC.length).equals(V2_MAGIC)) {
    throw new Error("This is not a Keyclasp v2 key file.");
  }
  const expected = V2_MAGIC.length + SALT_LENGTH + KEY_LENGTH;
  if (keyData.length !== expected) throw new Error("Key file is corrupted or incomplete.");
  const salt = keyData.subarray(V2_MAGIC.length, V2_MAGIC.length + SALT_LENGTH);
  const wrapped = keyData.subarray(V2_MAGIC.length + SALT_LENGTH);
  let lastError = "Could not unwrap this key file on this machine.";
  for (const identity of deriveStableMachineIdentities()) {
    const dek = xorWithKey(wrapped, wrappingKey(salt, identity));
    try {
      authenticateDek(dbPath, dek);
      return { dek, salt };
    } catch (err) {
      lastError = err.message;
    }
  }
  throw new Error(lastError);
}

function authenticateDek(dbPath, dek) {
  if (!fs.existsSync(dbPath)) throw new Error("vault.db is missing.");
  const db = new Database(dbPath, { readonly: true, fileMustExist: true });
  try {
    const row = db.prepare("SELECT encrypted_value, iv, auth_tag FROM secrets LIMIT 1").get();
    if (!row) throw new Error("Vault has no secrets to authenticate the key. Refusing to migrate an empty vault.");
    const decipher = crypto.createDecipheriv("aes-256-gcm", dek, row.iv, { authTagLength: AUTH_TAG_LENGTH });
    decipher.setAuthTag(row.auth_tag);
    decipher.update(row.encrypted_value);
    decipher.final();
  } finally {
    db.close();
  }
}

function writeV3(keyPath, dek, mode, passphrase) {
  const salt = crypto.randomBytes(SALT_LENGTH);
  const iterations = Buffer.alloc(4);
  iterations.writeUInt32BE(PBKDF2_ITERATIONS);
  const modeByte = mode === "passphrase" ? MODE_PASSPHRASE : MODE_MACHINE;
  const aad = Buffer.concat([V3_MAGIC, Buffer.from([modeByte, KDF_PBKDF2]), iterations, salt]);
  const kek = mode === "passphrase"
    ? crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha256")
    : crypto.createHash("sha256").update(V3_MAGIC).update(salt).update(deriveStableMachineIdentities()[0]).digest();
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv("aes-256-gcm", kek, iv, { authTagLength: AUTH_TAG_LENGTH });
  cipher.setAAD(aad);
  const wrapped = Buffer.concat([cipher.update(dek), cipher.final()]);
  const payload = Buffer.concat([V3_MAGIC, Buffer.from([modeByte, KDF_PBKDF2]), iterations, salt, iv, cipher.getAuthTag(), wrapped]);
  const backup = nextBackup(keyPath);
  fs.copyFileSync(keyPath, backup);
  fs.chmodSync(backup, 0o600);
  const tmp = `${keyPath}.${process.pid}.${Date.now()}.tmp`;
  fs.writeFileSync(tmp, payload, { mode: 0o600 });
  fs.renameSync(tmp, keyPath);
  fs.chmodSync(keyPath, 0o600);
  return backup;
}

function nextBackup(keyPath) {
  for (let index = 1; ; index++) {
    const backupPath = `${keyPath}.${index}.bak`;
    if (!fs.existsSync(backupPath)) return backupPath;
  }
}

function prompt(question) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  return new Promise((resolve) => {
    rl.question(question, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

function promptSecret(question) {
  return new Promise((resolve) => {
    process.stdout.write(question);
    let value = "";
    const onData = (char) => {
      const str = char.toString();
      switch (str) {
        case "\n":
        case "\r":
          process.stdin.removeListener("data", onData);
          process.stdin.pause();
          process.stdout.write("\n");
          resolve(value);
          break;
        case "\u0003":
          process.stdin.removeListener("data", onData);
          process.stdout.write("\n");
          process.exit(1);
          break;
        case "\u007f":
          if (value.length > 0) value = value.slice(0, -1);
          break;
        default:
          if (str >= " ") {
            value += str;
            process.stdout.write("*");
          }
          break;
      }
    };
    process.stdin.setRawMode?.(true);
    process.stdin.resume();
    process.stdin.on("data", onData);
  });
}

function parseArgs(argv) {
  const parsed = { yes: false, passphraseFile: undefined, machine: false };
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--yes") parsed.yes = true;
    else if (argv[i] === "--machine") parsed.machine = true;
    else if (argv[i] === "--passphrase-file") {
      parsed.passphraseFile = argv[i + 1];
      i += 1;
    }
  }
  return parsed;
}

async function main() {
  const flags = parseArgs(process.argv.slice(2));
  const noninteractive = flags.yes && (flags.machine || flags.passphraseFile);
  if (!noninteractive && !process.stdin.isTTY) {
    console.error("This migrate script is operator-only and requires a TTY.");
    process.exit(1);
  }

  const home = vaultHome();
  const keyPath = path.join(home, ".keyclasp.key");
  const dbPath = path.join(home, "vault.db");
  if (!fs.existsSync(keyPath)) {
    console.error(`No key file at ${keyPath}`);
    process.exit(1);
  }

  const keyData = fs.readFileSync(keyPath);
  if (keyData.subarray(0, V3_MAGIC.length).equals(V3_MAGIC)) {
    console.error("Key file is already the current format.");
    process.exit(1);
  }

  let dek;
  try {
    ({ dek } = unwrapV2(keyData, dbPath));
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }

  console.log(`Vault: ${home}`);
  console.log(`Key:   ${keyPath}`);
  let passphrase = "";
  if (flags.machine) {
    passphrase = "";
  } else if (flags.passphraseFile) {
    passphrase = fs.readFileSync(flags.passphraseFile, "utf8").replace(/\n$/, "");
  }
  if (!noninteractive) {
    passphrase = await promptSecret("New wrap passphrase (empty = machine-only): ");
    if (passphrase) {
      const again = await promptSecret("Confirm passphrase: ");
      if (again !== passphrase) {
        console.error("Passphrases did not match.");
        process.exit(1);
      }
    }
    const confirm = await prompt(`Write ${passphrase ? "passphrase" : "machine"} wrap? Type yes to continue: `);
    if (confirm !== "yes") {
      console.error("Aborted.");
      process.exit(1);
    }
  }
  const mode = passphrase ? "passphrase" : "machine";

  const backup = writeV3(keyPath, dek, mode, passphrase);
  console.log(`Migrated. Backup: ${backup}`);
  console.log("After you confirm the new vault opens, shred the .bak file — it is still the old XOR wrap.");
}

main().catch((err) => {
  console.error(err.message);
  process.exit(1);
});
