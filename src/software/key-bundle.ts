import crypto from "node:crypto";

const MAGIC = Buffer.from("keyclasp:v5\n", "utf8");
const FORMAT = 5;
const KEY_LENGTH = 32;
const SALT_LENGTH = 32;
const IV_LENGTH = 12;
const AUTH_TAG_LENGTH = 16;
const PBKDF2_ITERATIONS = 600_000;
const MACHINE_KDF = "sha256-machine-identity";
const INTERACTIVE_KDF = "pbkdf2-sha256";
const WRAP_ALGORITHM = "aes-256-gcm";
const MACHINE_KEK_DOMAIN = Buffer.concat([
  Buffer.from("keyclasp:key-bundle:v5:machine-kek", "utf8"),
  Buffer.from([0]),
]);
const WRAP_AAD_DOMAIN = "keyclasp:key-bundle:v5:wrap-aad";

export interface KeyEnvelopeDescriptor {
  mode: "machine" | "passphrase";
  keyClass: "machine" | "interactive";
  kdf: "sha256-machine-identity" | "pbkdf2-sha256";
  iterations: number;
  salt: Buffer;
  iv: Buffer;
  authTag: Buffer;
  wrappedKey: Buffer;
}

export interface KeyBundleDescriptor {
  format: 5;
  state: "active";
  vaultId: Buffer;
  generation: number;
  machine: KeyEnvelopeDescriptor;
  interactive?: KeyEnvelopeDescriptor;
}

export interface CreatedKeyBundleDescriptor {
  bundle: KeyBundleDescriptor;
  machineKey: Buffer;
  interactiveKey?: Buffer;
}

export interface CreateKeyBundleDescriptor {
  vaultId: Buffer;
  generation: number;
  machineIdentity: Buffer;
  interactivePassphrase?: string;
  randomBytes?: (length: number) => Buffer;
}

export interface CreateKeyBundleFromKeysDescriptor {
  vaultId: Buffer;
  generation: number;
  machineIdentity: Buffer;
  machineKey: Buffer;
  interactiveKey?: Buffer;
  interactivePassphrase?: string;
  randomBytes?: (length: number) => Buffer;
}

export interface RewrapInteractiveDescriptor {
  currentPassphrase: string;
  newPassphrase: string;
  machineIdentity: Buffer;
  machineKey: Buffer;
  randomBytes?: (length: number) => Buffer;
}

export interface EnrollInteractiveDescriptor {
  newPassphrase: string;
  machineIdentity: Buffer;
  machineKey: Buffer;
  randomBytes?: (length: number) => Buffer;
}

type SerializedEnvelope = {
  mode: string;
  key_class: string;
  kdf: string;
  iterations: number;
  salt: string;
  iv: string;
  auth_tag: string;
  wrapped_key: string;
};

type SerializedBundle = {
  format: number;
  state: string;
  vault_id: string;
  generation: number;
  machine: SerializedEnvelope;
  interactive?: SerializedEnvelope;
};

function assertExactKeys(value: object, expected: readonly string[], label: string): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new Error(`Keyclasp v5 ${label} has an invalid schema.`);
  }
}

function assertBuffer(value: Buffer, length: number, label: string): void {
  if (!Buffer.isBuffer(value) || value.length !== length) {
    throw new Error(`Keyclasp v5 ${label} must be ${length} bytes.`);
  }
}

function assertGeneration(generation: number): void {
  if (!Number.isSafeInteger(generation) || generation < 1) {
    throw new Error("Keyclasp v5 key-bundle generation must be a positive safe integer.");
  }
}

function randomBuffer(randomBytes: (length: number) => Buffer, length: number, label: string): Buffer {
  const value = randomBytes(length);
  assertBuffer(value, length, label);
  return Buffer.from(value);
}

function strictBase64(value: unknown, length: number, label: string): Buffer {
  if (typeof value !== "string" || value.length === 0 || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error(`Keyclasp v5 ${label} is not canonical base64.`);
  }
  const decoded = Buffer.from(value, "base64");
  if (decoded.length !== length || decoded.toString("base64") !== value) {
    throw new Error(`Keyclasp v5 ${label} has an invalid length or encoding.`);
  }
  return decoded;
}

function serializedEnvelope(envelope: KeyEnvelopeDescriptor): SerializedEnvelope {
  return {
    mode: envelope.mode,
    key_class: envelope.keyClass,
    kdf: envelope.kdf,
    iterations: envelope.iterations,
    salt: envelope.salt.toString("base64"),
    iv: envelope.iv.toString("base64"),
    auth_tag: envelope.authTag.toString("base64"),
    wrapped_key: envelope.wrappedKey.toString("base64"),
  };
}

function validateEnvelope(envelope: KeyEnvelopeDescriptor, keyClass: "machine" | "interactive"): void {
  const machine = keyClass === "machine";
  if (envelope.keyClass !== keyClass || envelope.mode !== (machine ? "machine" : "passphrase") ||
      envelope.kdf !== (machine ? MACHINE_KDF : INTERACTIVE_KDF) ||
      envelope.iterations !== (machine ? 0 : PBKDF2_ITERATIONS)) {
    throw new Error(`Keyclasp v5 ${keyClass} envelope metadata is invalid.`);
  }
  assertBuffer(envelope.salt, SALT_LENGTH, `${keyClass} salt`);
  assertBuffer(envelope.iv, IV_LENGTH, `${keyClass} IV`);
  assertBuffer(envelope.authTag, AUTH_TAG_LENGTH, `${keyClass} authentication tag`);
  assertBuffer(envelope.wrappedKey, KEY_LENGTH, `${keyClass} wrapped key`);
}

function validateBundle(bundle: KeyBundleDescriptor): void {
  if (bundle.format !== FORMAT || bundle.state !== "active") {
    throw new Error("Keyclasp v5 key-bundle format or state is invalid.");
  }
  assertBuffer(bundle.vaultId, 16, "vault ID");
  assertGeneration(bundle.generation);
  validateEnvelope(bundle.machine, "machine");
  if (bundle.interactive) validateEnvelope(bundle.interactive, "interactive");
}

function classInventory(bundle: Pick<KeyBundleDescriptor, "interactive">): readonly string[] {
  return bundle.interactive ? ["machine", "interactive"] : ["machine"];
}

function wrapAad(
  bundle: Pick<KeyBundleDescriptor, "format" | "state" | "vaultId" | "generation" | "interactive">,
  envelope: Pick<KeyEnvelopeDescriptor, "mode" | "keyClass" | "kdf" | "iterations" | "salt">,
): Buffer {
  return Buffer.from(JSON.stringify({
    domain: WRAP_AAD_DOMAIN,
    format: bundle.format,
    vault_id: bundle.vaultId.toString("base64"),
    generation: bundle.generation,
    state: bundle.state,
    classes: classInventory(bundle),
    mode: envelope.mode,
    key_class: envelope.keyClass,
    kdf: envelope.kdf,
    iterations: envelope.iterations,
    salt: envelope.salt.toString("base64"),
  }), "utf8");
}

function machineKek(salt: Buffer, machineIdentity: Buffer): Buffer {
  if (!Buffer.isBuffer(machineIdentity) || machineIdentity.length === 0) {
    throw new Error("Keyclasp v5 machine identity must be non-empty bytes.");
  }
  return crypto.createHash("sha256")
    .update(MACHINE_KEK_DOMAIN)
    .update(salt)
    .update(machineIdentity)
    .digest();
}

function interactiveKek(salt: Buffer, passphrase: string): Buffer {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new Error("Keyclasp v5 interactive passphrase must be non-empty.");
  }
  return crypto.pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, KEY_LENGTH, "sha256");
}

function wrapKey(key: Buffer, kek: Buffer, iv: Buffer, aad: Buffer): Pick<KeyEnvelopeDescriptor, "authTag" | "wrappedKey"> {
  assertBuffer(key, KEY_LENGTH, "data key");
  const cipher = crypto.createCipheriv(WRAP_ALGORITHM, kek, iv, { authTagLength: AUTH_TAG_LENGTH });
  cipher.setAAD(aad);
  const wrappedKey = Buffer.concat([cipher.update(key), cipher.final()]);
  return { authTag: cipher.getAuthTag(), wrappedKey };
}

function unwrapKey(envelope: KeyEnvelopeDescriptor, kek: Buffer, aad: Buffer): Buffer {
  const decipher = crypto.createDecipheriv(WRAP_ALGORITHM, kek, envelope.iv, { authTagLength: AUTH_TAG_LENGTH });
  decipher.setAAD(aad);
  decipher.setAuthTag(envelope.authTag);
  const key = Buffer.concat([decipher.update(envelope.wrappedKey), decipher.final()]);
  assertBuffer(key, KEY_LENGTH, "unwrapped data key");
  return key;
}

function wrapBundle(
  vaultId: Buffer,
  generation: number,
  machineKey: Buffer,
  machineIdentity: Buffer,
  interactive: { key: Buffer; passphrase: string } | undefined,
  randomBytes: (length: number) => Buffer,
): KeyBundleDescriptor {
  const machine: KeyEnvelopeDescriptor = {
    mode: "machine", keyClass: "machine", kdf: MACHINE_KDF, iterations: 0,
    salt: randomBuffer(randomBytes, SALT_LENGTH, "machine salt"),
    iv: randomBuffer(randomBytes, IV_LENGTH, "machine IV"),
    authTag: Buffer.alloc(AUTH_TAG_LENGTH), wrappedKey: Buffer.alloc(KEY_LENGTH),
  };
  const interactiveEnvelope: KeyEnvelopeDescriptor | undefined = interactive ? {
    mode: "passphrase", keyClass: "interactive", kdf: INTERACTIVE_KDF, iterations: PBKDF2_ITERATIONS,
    salt: randomBuffer(randomBytes, SALT_LENGTH, "interactive salt"),
    iv: randomBuffer(randomBytes, IV_LENGTH, "interactive IV"),
    authTag: Buffer.alloc(AUTH_TAG_LENGTH), wrappedKey: Buffer.alloc(KEY_LENGTH),
  } : undefined;
  const bundle: KeyBundleDescriptor = {
    format: FORMAT,
    state: "active",
    vaultId: Buffer.from(vaultId),
    generation,
    machine,
    ...(interactiveEnvelope ? { interactive: interactiveEnvelope } : {}),
  };
  Object.assign(machine, wrapKey(machineKey, machineKek(machine.salt, machineIdentity), machine.iv, wrapAad(bundle, machine)));
  if (interactiveEnvelope && interactive) {
    Object.assign(interactiveEnvelope, wrapKey(
      interactive.key,
      interactiveKek(interactiveEnvelope.salt, interactive.passphrase),
      interactiveEnvelope.iv,
      wrapAad(bundle, interactiveEnvelope),
    ));
  }
  return bundle;
}

export function create(options: CreateKeyBundleDescriptor): CreatedKeyBundleDescriptor {
  assertBuffer(options.vaultId, 16, "vault ID");
  assertGeneration(options.generation);
  if (!Buffer.isBuffer(options.machineIdentity) || options.machineIdentity.length === 0) {
    throw new Error("Keyclasp v5 machine identity must be non-empty bytes.");
  }
  const hasInteractive = options.interactivePassphrase !== undefined;
  if (hasInteractive && options.interactivePassphrase!.length === 0) {
    throw new Error("Keyclasp v5 interactive passphrase must be non-empty.");
  }
  const randomBytes = options.randomBytes ?? crypto.randomBytes;
  const machineKey = randomBuffer(randomBytes, KEY_LENGTH, "machine data key");
  const interactiveKey = hasInteractive ? randomBuffer(randomBytes, KEY_LENGTH, "interactive data key") : undefined;
  if (interactiveKey?.equals(machineKey)) {
    throw new Error("Keyclasp v5 machine and interactive data keys must be independent.");
  }
  const bundle = wrapBundle(
    options.vaultId,
    options.generation,
    machineKey,
    options.machineIdentity,
    interactiveKey ? { key: interactiveKey, passphrase: options.interactivePassphrase! } : undefined,
    randomBytes,
  );
  return { bundle, machineKey, ...(interactiveKey ? { interactiveKey } : {}) };
}

export function createFromKeys(options: CreateKeyBundleFromKeysDescriptor): KeyBundleDescriptor {
  assertBuffer(options.machineKey, KEY_LENGTH, "machine data key");
  if ((options.interactiveKey === undefined) !== (options.interactivePassphrase === undefined)) {
    throw new Error("Keyclasp v5 interactive key and passphrase must be provided together.");
  }
  if (options.interactiveKey) {
    assertBuffer(options.interactiveKey, KEY_LENGTH, "interactive data key");
    if (options.interactiveKey.equals(options.machineKey)) throw new Error("Keyclasp v5 machine and interactive data keys must be independent.");
  }
  return wrapBundle(
    options.vaultId,
    options.generation,
    options.machineKey,
    options.machineIdentity,
    options.interactiveKey && options.interactivePassphrase
      ? { key: options.interactiveKey, passphrase: options.interactivePassphrase }
      : undefined,
    options.randomBytes ?? crypto.randomBytes,
  );
}

export function serialize(bundle: KeyBundleDescriptor): Buffer {
  validateBundle(bundle);
  const document: SerializedBundle = {
    format: bundle.format,
    state: bundle.state,
    vault_id: bundle.vaultId.toString("base64"),
    generation: bundle.generation,
    machine: serializedEnvelope(bundle.machine),
    ...(bundle.interactive ? { interactive: serializedEnvelope(bundle.interactive) } : {}),
  };
  return Buffer.concat([MAGIC, Buffer.from(`${JSON.stringify(document)}\n`, "utf8")]);
}

function parseEnvelope(value: unknown, keyClass: "machine" | "interactive"): KeyEnvelopeDescriptor {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Error(`Keyclasp v5 ${keyClass} envelope is invalid.`);
  }
  assertExactKeys(value, ["mode", "key_class", "kdf", "iterations", "salt", "iv", "auth_tag", "wrapped_key"], `${keyClass} envelope`);
  const source = value as Record<string, unknown>;
  const machine = keyClass === "machine";
  if (source.mode !== (machine ? "machine" : "passphrase") || source.key_class !== keyClass ||
      source.kdf !== (machine ? MACHINE_KDF : INTERACTIVE_KDF) ||
      source.iterations !== (machine ? 0 : PBKDF2_ITERATIONS)) {
    throw new Error(`Keyclasp v5 ${keyClass} envelope metadata is invalid.`);
  }
  return {
    mode: source.mode,
    keyClass: source.key_class,
    kdf: source.kdf,
    iterations: source.iterations,
    salt: strictBase64(source.salt, SALT_LENGTH, `${keyClass} salt`),
    iv: strictBase64(source.iv, IV_LENGTH, `${keyClass} IV`),
    authTag: strictBase64(source.auth_tag, AUTH_TAG_LENGTH, `${keyClass} authentication tag`),
    wrappedKey: strictBase64(source.wrapped_key, KEY_LENGTH, `${keyClass} wrapped key`),
  } as KeyEnvelopeDescriptor;
}

export function parse(encoded: Buffer): KeyBundleDescriptor {
  if (!Buffer.isBuffer(encoded) || !encoded.subarray(0, MAGIC.length).equals(MAGIC)) {
    throw new Error("Keyclasp key file uses an unsupported key-bundle format.");
  }
  let raw: unknown;
  try {
    const json = encoded.subarray(MAGIC.length).toString("utf8");
    if (!json.endsWith("\n") || json.slice(0, -1).includes("\n")) throw new Error();
    raw = JSON.parse(json.slice(0, -1));
  } catch {
    throw new Error("Keyclasp v5 key bundle is corrupt or non-canonical.");
  }
  if (typeof raw !== "object" || raw === null || Array.isArray(raw)) {
    throw new Error("Keyclasp v5 key bundle is invalid.");
  }
  const source = raw as Record<string, unknown>;
  const expectedKeys = source.interactive === undefined
    ? ["format", "state", "vault_id", "generation", "machine"]
    : ["format", "state", "vault_id", "generation", "machine", "interactive"];
  assertExactKeys(source, expectedKeys, "key bundle");
  if (source.format !== FORMAT || source.state !== "active" || !Number.isSafeInteger(source.generation) || (source.generation as number) < 1) {
    throw new Error("Keyclasp v5 key-bundle metadata is invalid.");
  }
  const bundle: KeyBundleDescriptor = {
    format: FORMAT,
    state: "active",
    vaultId: strictBase64(source.vault_id, 16, "vault ID"),
    generation: source.generation as number,
    machine: parseEnvelope(source.machine, "machine"),
    ...(source.interactive === undefined ? {} : { interactive: parseEnvelope(source.interactive, "interactive") }),
  };
  if (!serialize(bundle).equals(encoded)) {
    throw new Error("Keyclasp v5 key bundle is not canonically encoded.");
  }
  return bundle;
}

export function unwrapMachine(bundle: KeyBundleDescriptor, machineIdentity: Buffer): Buffer {
  validateBundle(bundle);
  return unwrapKey(bundle.machine, machineKek(bundle.machine.salt, machineIdentity), wrapAad(bundle, bundle.machine));
}

export function unwrapInteractive(bundle: KeyBundleDescriptor, passphrase: string): Buffer {
  validateBundle(bundle);
  if (!bundle.interactive) throw new Error("Keyclasp v5 key bundle has no interactive key.");
  return unwrapKey(
    bundle.interactive,
    interactiveKek(bundle.interactive.salt, passphrase),
    wrapAad(bundle, bundle.interactive),
  );
}

export function rewrapInteractive(
  bundle: KeyBundleDescriptor,
  options: RewrapInteractiveDescriptor,
): { bundle: KeyBundleDescriptor; interactiveKey: Buffer } {
  validateBundle(bundle);
  assertBuffer(options.machineKey, KEY_LENGTH, "machine data key");
  const interactiveKey = unwrapInteractive(bundle, options.currentPassphrase);
  if (!options.newPassphrase) throw new Error("Keyclasp v5 interactive passphrase must be non-empty.");
  return {
    bundle: rebuildBundle(bundle, options.machineKey, interactiveKey, options.machineIdentity, options.newPassphrase, options.randomBytes),
    interactiveKey,
  };
}

export function enrollInteractive(
  bundle: KeyBundleDescriptor,
  options: EnrollInteractiveDescriptor,
): { bundle: KeyBundleDescriptor; interactiveKey: Buffer } {
  validateBundle(bundle);
  if (bundle.interactive) throw new Error("Keyclasp v5 interactive custody is already enrolled.");
  if (!options.newPassphrase) throw new Error("Keyclasp v5 interactive passphrase must be non-empty.");
  const randomBytes = options.randomBytes ?? crypto.randomBytes;
  assertBuffer(options.machineKey, KEY_LENGTH, "machine data key");
  let interactiveKey = randomBuffer(randomBytes, KEY_LENGTH, "interactive data key");
  if (interactiveKey.equals(options.machineKey)) interactiveKey = randomBuffer(randomBytes, KEY_LENGTH, "independent interactive data key");
  if (interactiveKey.equals(options.machineKey)) throw new Error("Keyclasp v5 machine and interactive data keys must be independent.");
  return {
    bundle: rebuildBundle(bundle, options.machineKey, interactiveKey, options.machineIdentity, options.newPassphrase, randomBytes),
    interactiveKey,
  };
}

function rebuildBundle(
  previous: KeyBundleDescriptor,
  machineKey: Buffer,
  interactiveKey: Buffer,
  machineIdentity: Buffer,
  passphrase: string,
  providedRandomBytes?: (length: number) => Buffer,
): KeyBundleDescriptor {
  return wrapBundle(
    previous.vaultId,
    previous.generation + 1,
    machineKey,
    machineIdentity,
    { key: interactiveKey, passphrase },
    providedRandomBytes ?? crypto.randomBytes,
  );
}
