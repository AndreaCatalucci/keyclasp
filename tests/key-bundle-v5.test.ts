import { describe, expect, it } from "vitest";
import {
  create,
  enrollInteractive,
  parse,
  rewrapInteractive,
  rotateMachine,
  serialize,
  unwrapInteractive,
  unwrapMachine,
} from "../src/software/key-bundle.js";

function deterministicRandom(start = 1): (length: number) => Buffer {
  let next = start;
  return (length) => {
    const result = Buffer.alloc(length);
    for (let index = 0; index < length; index += 1) result[index] = next++ & 0xff;
    return result;
  };
}

function rewrite(encoded: Buffer, mutate: (document: any) => void): Buffer {
  const magic = Buffer.from("keyclasp:v5\n");
  const document = JSON.parse(encoded.subarray(magic.length).toString("utf8"));
  mutate(document);
  return Buffer.concat([magic, Buffer.from(`${JSON.stringify(document)}\n`)]);
}

describe("v5 key bundle", () => {
  const vaultId = Buffer.from("00112233445566778899aabbccddeeff", "hex");
  const machineIdentity = Buffer.from("machine-identity-for-tests");

  it("freezes the canonical dual-key encoding", () => {
    const created = create({
      vaultId,
      generation: 7,
      machineIdentity,
      interactivePassphrase: "correct horse battery staple",
      randomBytes: deterministicRandom(),
    });
    const encoded = serialize(created.bundle);

    expect(encoded.toString("utf8")).toBe('keyclasp:v5\n{"format":5,"state":"active","vault_id":"ABEiM0RVZneImaq7zN3u/w==","generation":7,"machine":{"mode":"machine","key_class":"machine","kdf":"sha256-machine-identity","iterations":0,"salt":"QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVpbXF1eX2A=","iv":"YWJjZGVmZ2hpamts","auth_tag":"A79D+7WuKu9AWaPXpv1H6A==","wrapped_key":"P7XVy+KWaP6bDoKpbP4N9hBp0FWJTOhbxJDumskHXyo="},"interactive":{"mode":"passphrase","key_class":"interactive","kdf":"pbkdf2-sha256","iterations":600000,"salt":"bW5vcHFyc3R1dnd4eXp7fH1+f4CBgoOEhYaHiImKi4w=","iv":"jY6PkJGSk5SVlpeY","auth_tag":"EIe1qzXNwyA5PB7CQ7Fmtw==","wrapped_key":"G4LinHGpzul6t5WnstU3C9KiZYEOldc0ilUTgkSpHzE="}}\n');
    expect(parse(encoded)).toEqual(created.bundle);
    expect(unwrapMachine(parse(encoded), machineIdentity)).toEqual(created.machineKey);
    expect(unwrapInteractive(parse(encoded), "correct horse battery staple")).toEqual(created.interactiveKey);
    expect(created.machineKey).not.toEqual(created.interactiveKey);
  });

  it("supports a strict machine-only bundle", () => {
    const created = create({ vaultId, generation: 1, machineIdentity, randomBytes: deterministicRandom(19) });
    const parsed = parse(serialize(created.bundle));
    expect(parsed.interactive).toBeUndefined();
    expect(unwrapMachine(parsed, machineIdentity)).toEqual(created.machineKey);
    expect(() => unwrapInteractive(parsed, "anything")).toThrow(/no interactive key/i);
  });

  it("rejects empty passphrases and non-independent generated keys", () => {
    expect(() => create({
      vaultId,
      generation: 1,
      machineIdentity,
      interactivePassphrase: "",
    })).toThrow(/non-empty/i);
    expect(() => create({
      vaultId,
      generation: 1,
      machineIdentity,
      interactivePassphrase: "passphrase",
      randomBytes: (length) => Buffer.alloc(length, 9),
    })).toThrow(/independent/i);
  });

  it("binds bundle and envelope metadata into each wrap", () => {
    const created = create({
      vaultId,
      generation: 4,
      machineIdentity,
      interactivePassphrase: "passphrase",
      randomBytes: deterministicRandom(31),
    });
    const encoded = serialize(created.bundle);
    const mutations: Array<(document: any) => void> = [
      (document) => { document.generation = 5; },
      (document) => { document.vault_id = Buffer.alloc(16, 8).toString("base64"); },
      (document) => { delete document.interactive; },
      (document) => { document.machine.salt = Buffer.alloc(32, 7).toString("base64"); },
    ];
    for (const mutate of mutations) {
      const changed = parse(rewrite(encoded, mutate));
      expect(() => unwrapMachine(changed, machineIdentity)).toThrow();
    }
    const interactiveMutations: Array<(document: any) => void> = [
      (document) => { document.generation = 5; },
      (document) => { document.vault_id = Buffer.alloc(16, 8).toString("base64"); },
      (document) => { document.interactive.salt = Buffer.alloc(32, 7).toString("base64"); },
      (document) => { document.machine.key_class = "interactive"; },
    ];
    for (const mutate of interactiveMutations) {
      expect(() => {
        const changed = parse(rewrite(encoded, mutate));
        unwrapInteractive(changed, "passphrase");
      }).toThrow();
    }
  });

  it("rejects deletion, reclassification, unknown fields, malformed base64, and trailing data", () => {
    const created = create({
      vaultId,
      generation: 2,
      machineIdentity,
      interactivePassphrase: "passphrase",
      randomBytes: deterministicRandom(67),
    });
    const encoded = serialize(created.bundle);
    expect(() => parse(rewrite(encoded, (document) => { document.machine.key_class = "interactive"; }))).toThrow(/metadata/i);
    expect(() => parse(rewrite(encoded, (document) => { document.extra = true; }))).toThrow(/schema/i);
    expect(() => parse(rewrite(encoded, (document) => { document.machine.iv = "not base64"; }))).toThrow(/base64/i);
    expect(() => parse(Buffer.concat([encoded, Buffer.from("trailing")]))).toThrow(/corrupt|canonical/i);
    expect(() => parse(Buffer.from(encoded.toString("utf8").replace("keyclasp:v5", "keyclasp:v4")))).toThrow(/unsupported/i);
  });

  it("keeps machine and interactive unwrap paths cryptographically separate", () => {
    const created = create({
      vaultId,
      generation: 9,
      machineIdentity,
      interactivePassphrase: "interactive-only",
      randomBytes: deterministicRandom(101),
    });
    expect(() => unwrapMachine(created.bundle, Buffer.from("another-machine"))).toThrow();
    expect(() => unwrapInteractive(created.bundle, machineIdentity.toString("utf8"))).toThrow();
    expect(() => unwrapInteractive(created.bundle, "wrong-passphrase")).toThrow();
  });

  it("rotates only the interactive wrap while preserving both data keys", () => {
    const created = create({
      vaultId,
      generation: 3,
      machineIdentity,
      interactivePassphrase: "old-passphrase",
      randomBytes: deterministicRandom(141),
    });
    const rotated = rewrapInteractive(created.bundle, {
      currentPassphrase: "old-passphrase",
      newPassphrase: "new-passphrase",
      machineIdentity,
      machineKey: created.machineKey,
      randomBytes: deterministicRandom(211),
    });

    expect(serialize(rotated.bundle)).not.toEqual(serialize(created.bundle));
    expect(rotated.bundle.generation).toBe(created.bundle.generation + 1);
    expect(rotated.interactiveKey).toEqual(created.interactiveKey);
    expect(unwrapMachine(rotated.bundle, machineIdentity)).toEqual(created.machineKey);
    expect(unwrapInteractive(rotated.bundle, "new-passphrase")).toEqual(created.interactiveKey);
    expect(() => unwrapInteractive(rotated.bundle, "old-passphrase")).toThrow();
  });

  it("rewraps the validated machine key when the preferred machine identity changes", () => {
    const created = create({
      vaultId,
      generation: 1,
      machineIdentity,
      interactivePassphrase: "old-passphrase",
      randomBytes: deterministicRandom(177),
    });
    const nextIdentity = Buffer.from("new-preferred-machine-identity");
    const rotated = rewrapInteractive(created.bundle, {
      currentPassphrase: "old-passphrase",
      newPassphrase: "new-passphrase",
      machineIdentity: nextIdentity,
      machineKey: created.machineKey,
      randomBytes: deterministicRandom(201),
    });

    expect(unwrapMachine(rotated.bundle, nextIdentity)).toEqual(created.machineKey);
    expect(() => unwrapMachine(rotated.bundle, machineIdentity)).toThrow();
    expect(unwrapInteractive(rotated.bundle, "new-passphrase")).toEqual(created.interactiveKey);
  });

  it("enrolls a fresh independent interactive key and advances the authenticated generation", () => {
    const created = create({ vaultId, generation: 1, machineIdentity, randomBytes: deterministicRandom(17) });
    const enrolled = enrollInteractive(created.bundle, {
      newPassphrase: "new-passphrase",
      machineIdentity,
      machineKey: created.machineKey,
      randomBytes: deterministicRandom(81),
    });
    expect(enrolled.bundle.generation).toBe(2);
    expect(unwrapMachine(enrolled.bundle, machineIdentity)).toEqual(created.machineKey);
    expect(unwrapInteractive(enrolled.bundle, "new-passphrase")).toEqual(enrolled.interactiveKey);
    expect(enrolled.interactiveKey).not.toEqual(created.machineKey);
  });

  it("retires the machine key while preserving the interactive key under a new generation", () => {
    const created = create({
      vaultId,
      generation: 5,
      machineIdentity,
      interactivePassphrase: "interactive-passphrase",
      randomBytes: deterministicRandom(23),
    });
    const rotated = rotateMachine(created.bundle, {
      interactivePassphrase: "interactive-passphrase",
      machineIdentity,
      machineKey: created.machineKey,
      interactiveKey: created.interactiveKey!,
      randomBytes: deterministicRandom(199),
    });
    expect(rotated.bundle.generation).toBe(6);
    expect(rotated.machineKey).not.toEqual(created.machineKey);
    expect(unwrapMachine(rotated.bundle, machineIdentity)).toEqual(rotated.machineKey);
    expect(unwrapInteractive(rotated.bundle, "interactive-passphrase")).toEqual(created.interactiveKey);
  });
});
