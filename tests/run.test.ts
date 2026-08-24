import { beforeEach, describe, expect, it, vi } from "vitest";
import { requireBiometricAuthentication } from "../src/biometric.js";
import {
  buildRunEnvironment,
  checkUnsafeCommand,
  createSecretRedactor,
  parseRunArgs,
  runCommandWithSecrets,
} from "../src/run.js";

vi.mock("../src/biometric.js", () => ({
  requireBiometricAuthentication: vi.fn(),
}));

const biometricMock = vi.mocked(requireBiometricAuthentication);
const approveOperator = () => ({ method: "touch-id" } as const);

beforeEach(() => {
  biometricMock.mockReset();
});

describe("run argument parsing", () => {
  it("removes separators and preserves a safe command", () => {
    expect(parseRunArgs(["--", "npm", "test"])).toEqual({
      allowUnsafe: false,
      envSpecs: [],
      commandArgs: ["npm", "test"],
    });
  });

  it("consumes --allow-unsafe before the child command", () => {
    expect(parseRunArgs(["--allow-unsafe", "--", "env"])).toEqual({
      allowUnsafe: true,
      envSpecs: [],
      commandArgs: ["env"],
    });
  });

  it("preserves child arguments after the separator", () => {
    expect(parseRunArgs(["--", "node", "--allow-unsafe"])).toEqual({
      allowUnsafe: false,
      envSpecs: [],
      commandArgs: ["node", "--allow-unsafe"],
    });
  });

  it("parses repeatable env mappings before the child command", () => {
    expect(parseRunArgs(["--env", "HELLO:WORLD", "--env=FOO", "--", "npm", "start"])).toEqual({
      allowUnsafe: false,
      envSpecs: [
        { sourceName: "HELLO", targetName: "WORLD" },
        { sourceName: "FOO", targetName: "FOO" },
      ],
      commandArgs: ["npm", "start"],
    });
  });

  it("treats --env after the command starts as a child argument", () => {
    expect(parseRunArgs(["node", "--env", "HELLO:WORLD"])).toEqual({
      allowUnsafe: false,
      envSpecs: [],
      commandArgs: ["node", "--env", "HELLO:WORLD"],
    });
  });

  it("parses scoped Keyclasp options before the child command", () => {
    expect(parseRunArgs([
      "--project", "myapp", "-E", "prod", "--env", "HELLO:WORLD", "--", "npm", "test",
    ])).toEqual({
      allowUnsafe: false,
      envSpecs: [{ sourceName: "HELLO", targetName: "WORLD" }],
      commandArgs: ["npm", "test"],
      project: "myapp",
      environment: "prod",
    });
  });

  it("preserves scope-like child arguments when no separator is used", () => {
    expect(parseRunArgs(["node", "server.js", "-p", "3000", "--environment", "child-value"])).toEqual({
      allowUnsafe: false,
      envSpecs: [],
      commandArgs: ["node", "server.js", "-p", "3000", "--environment", "child-value"],
    });
  });

  it("rejects malformed env mappings", () => {
    expect(() => parseRunArgs(["--env"])).toThrow(/Missing value/);
    expect(() => parseRunArgs(["--env", ":WORLD"])).toThrow(/Invalid source/);
    expect(() => parseRunArgs(["--env", "HELLO:"])).toThrow(/Invalid target/);
    expect(() => parseRunArgs(["--env", "HELLO:BAD-NAME"])).toThrow(/Invalid target/);
  });

  it("parses project and environment before the child command", () => {
    expect(parseRunArgs([
      "--project",
      "footnote",
      "--environment",
      "prod",
      "--env",
      "API_KEY",
      "--",
      "node",
    ])).toEqual({
      allowUnsafe: false,
      project: "footnote",
      environment: "prod",
      envSpecs: [{ sourceName: "API_KEY", targetName: "API_KEY" }],
      commandArgs: ["node"],
    });
  });

  it("supports short and equals scope flags while preserving child scope flags", () => {
    expect(parseRunArgs([
      "-p",
      "footnote",
      "--environment=prod",
      "--",
      "node",
      "--project",
      "child-project",
    ])).toEqual({
      allowUnsafe: false,
      project: "footnote",
      environment: "prod",
      envSpecs: [],
      commandArgs: ["node", "--project", "child-project"],
    });
  });
});

describe("run preflight", () => {
  it("blocks obvious environment dump commands", () => {
    expect(checkUnsafeCommand(["env"])?.reason).toContain("env");
    expect(checkUnsafeCommand(["printenv"])?.reason).toContain("printenv");
    expect(checkUnsafeCommand(["/usr/bin/env"])?.reason).toContain("env");
  });

  it("blocks simple shell forms that dump environment variables", () => {
    expect(checkUnsafeCommand(["bash", "-c", "env | sort"])?.reason).toContain("bash");
    expect(checkUnsafeCommand(["sh", "-c", "printenv KEY"])?.reason).toContain("sh");
    expect(checkUnsafeCommand(["zsh", "-lc", "export"])?.reason).toContain("zsh");
    expect(checkUnsafeCommand(["bash", "-exc", "env"])?.reason).toContain("bash");
  });

  it("allows ordinary commands", () => {
    expect(checkUnsafeCommand(["node", "-e", "console.log('ok')"])).toBeNull();
  });
});

describe("run environment preparation", () => {
  it("injects valid secrets and tracks only non-empty leak values", () => {
    const result = buildRunEnvironment({
      baseEnv: { EXISTING: "1" },
      secretNames: ["API_KEY", "EMPTY_SECRET", "SHORT_SECRET"],
      resolveSecret: (name) => {
        if (name === "API_KEY") return "sk-test-secret";
        if (name === "EMPTY_SECRET") return "";
        if (name === "SHORT_SECRET") return "a";
        return "ignored";
      },
    });

    expect(result.env.API_KEY).toBe("sk-test-secret");
    expect(result.env.EMPTY_SECRET).toBe("");
    expect(result.env.SHORT_SECRET).toBe("a");
    expect(result.leakValues).toEqual(["sk-test-secret"]);
  });

  it("rejects an incomplete whole-scope environment instead of injecting a subset", () => {
    const resolveSecret = vi.fn((name: string) => name === "GOOD" ? "good-value" : "before\0after");
    expect(() => buildRunEnvironment({
      baseEnv: {},
      secretNames: ["GOOD", "INVALID"],
      resolveSecret,
    })).toThrow(/null byte/);
    expect(resolveSecret).toHaveBeenCalledTimes(2);
  });

  it("injects explicit env mappings from source names to target names", () => {
    const result = buildRunEnvironment({
      baseEnv: {},
      secretNames: ["HELLO", "IGNORED_BY_EXPLICIT_SPECS"],
      envSpecs: [{ sourceName: "HELLO", targetName: "WORLD" }],
      resolveSecret: (name) => (name === "HELLO" ? "mapped-secret" : null),
    });

    expect(result.env.WORLD).toBe("mapped-secret");
    expect(result.env.HELLO).toBeUndefined();
    expect(result.env.IGNORED_BY_EXPLICIT_SPECS).toBeUndefined();
    expect(result.leakValues).toEqual(["mapped-secret"]);
  });

  it("injects persistent alias names when included in the default secret set", () => {
    const result = buildRunEnvironment({
      baseEnv: {},
      secretNames: ["HELLO", "WORLD"],
      resolveSecret: (name) => {
        if (name === "HELLO") return "canonical-secret";
        if (name === "WORLD") return "canonical-secret";
        return null;
      },
    });

    expect(result.env.HELLO).toBe("canonical-secret");
    expect(result.env.WORLD).toBe("canonical-secret");
    expect(result.leakValues).toEqual(["canonical-secret"]);
  });

  it("fails explicit env mappings with duplicate targets or missing sources", () => {
    const resolveSecret = vi.fn(() => "value");
    expect(() => buildRunEnvironment({
      baseEnv: {},
      secretNames: ["ONE", "TWO"],
      envSpecs: [
        { sourceName: "ONE", targetName: "WORLD" },
        { sourceName: "TWO", targetName: "WORLD" },
      ],
      resolveSecret,
    })).toThrow(/Duplicate target environment name/);
    expect(resolveSecret).not.toHaveBeenCalled();

    resolveSecret.mockClear();
    expect(() => buildRunEnvironment({
      baseEnv: {},
      secretNames: ["HELLO"],
      envSpecs: [{ sourceName: "MISSING", targetName: "WORLD" }],
      resolveSecret,
    })).toThrow(/Secret "MISSING" not found/);
    expect(resolveSecret).not.toHaveBeenCalled();
  });
});

describe("secret redaction", () => {
  it("redacts a secret in one chunk", () => {
    const redactor = createSecretRedactor(["sk-test-secret"]);
    const written = redactor.write("before sk-test-secret after");
    const final = redactor.end();

    expect(written.leaked || final.leaked).toBe(true);
    expect(written.output + final.output).toBe("before [KEYCLASP_REDACTED] after");
  });

  it("does not flush a split secret before it can be detected", () => {
    const redactor = createSecretRedactor(["sk-test-secret"]);
    const first = redactor.write("prefix sk-test");
    const second = redactor.write("-secret suffix");
    const final = redactor.end();

    expect(first.output).not.toContain("sk-test");
    expect(first.leaked).toBe(false);
    expect(first.output + second.output + final.output).toBe("prefix [KEYCLASP_REDACTED] suffix");
    expect(second.leaked).toBe(true);
  });

  it("does not withhold ordinary interactive prompts", () => {
    const redactor = createSecretRedactor(["sk-test-secret-with-long-value"]);
    const written = redactor.write("var.region\n  Enter a value: ");

    expect(written.leaked).toBe(false);
    expect(written.output).toBe("var.region\n  Enter a value: ");
  });

  it("does not treat sandbox-looking values as leaks unless they are tracked", () => {
    const redactor = createSecretRedactor(["sk-real-secret"]);
    const written = redactor.write("KEYCLASP_SANDBOX_deadbeef");
    const final = redactor.end();

    expect(written.leaked || final.leaked).toBe(false);
    expect(written.output + final.output).toBe("KEYCLASP_SANDBOX_deadbeef");
  });

  it("keeps carry state after one leak to catch a second split secret", () => {
    const redactor = createSecretRedactor(["first-secret", "second-secret"]);
    const first = redactor.write("before first-secret then second");
    const second = redactor.write("-secret after");
    const final = redactor.end();
    const output = first.output + second.output + final.output;

    expect(first.leaked || second.leaked || final.leaked).toBe(true);
    expect(output).toBe("before [KEYCLASP_REDACTED] then [KEYCLASP_REDACTED] after");
    expect(output).not.toContain("first-secret");
    expect(output).not.toContain("second-secret");
  });
});

describe("guarded command execution", () => {
  it.each(["cancelled", "unavailable"])("fails closed before unlock when required authorization is %s", async (failure) => {
    const ensureUnlocked = vi.fn(async () => undefined);
    const resolveSecret = vi.fn(() => "secret-value");
    const result = await runCommandWithSecrets({
      args: ["--env", "API_KEY", "--", process.execPath, "-e", "process.exit(0)"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret,
      ensureUnlocked,
      authorizationRequired: true,
      authorize: () => { throw new Error(`Touch ID ${failure}.`); },
      stdout: () => {},
      stderr: () => {},
    });
    expect(result).toEqual({ kind: "blocked", exitCode: 2 });
    expect(ensureUnlocked).not.toHaveBeenCalled();
    expect(resolveSecret).not.toHaveBeenCalled();
  });

  it("keeps passphrase unlock failure after successful required authorization", async () => {
    const events: string[] = [];
    const resolveSecret = vi.fn(() => "secret-value");
    const result = await runCommandWithSecrets({
      args: ["--env", "API_KEY", "--", process.execPath, "-e", "process.exit(0)"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret,
      authorizationRequired: true,
      authorize: () => { events.push("authorize"); return approveOperator(); },
      ensureUnlocked: async () => { events.push("unlock"); throw new Error("Vault passphrase is incorrect."); },
      stdout: () => {},
      stderr: () => {},
    });
    expect(result).toEqual({ kind: "error", exitCode: 1 });
    expect(events).toEqual(["authorize", "unlock"]);
    expect(resolveSecret).not.toHaveBeenCalled();
  });

  it("does not let --allow-unsafe bypass strict authorization", async () => {
    const ensureUnlocked = vi.fn(async () => undefined);
    const result = await runCommandWithSecrets({
      args: ["--allow-unsafe", "--env", "API_KEY", "--", process.execPath, "-e", "process.exit(0)"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "secret-value",
      ensureUnlocked,
      authorizationRequired: true,
      authorize: () => { throw new Error("Touch ID cancelled."); },
      stdout: () => {},
      stderr: () => {},
    });
    expect(result).toEqual({ kind: "blocked", exitCode: 2 });
    expect(ensureUnlocked).not.toHaveBeenCalled();
  });

  it("requires biometrics before resolving a whole-scope injection", async () => {
    const events: string[] = [];
    const resolvedNames: string[] = [];
    biometricMock.mockImplementationOnce(() => { events.push("biometric"); });
    const result = await runCommandWithSecrets({
      args: [process.execPath, "-e", "process.exit(0)"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: (name) => {
        events.push("resolve");
        resolvedNames.push(name);
        return "sk-test-secret";
      },
      ensureUnlocked: async () => { events.push("unlock"); },
      authorize: () => { biometricMock("whole-scope test"); return approveOperator(); },
      stdout: () => {},
      stderr: () => {},
    });

    expect(result.kind).toBe("exit");
    expect(biometricMock).toHaveBeenCalledOnce();
    expect(resolvedNames).toEqual(["API_KEY"]);
    expect(events).toEqual(["biometric", "unlock", "resolve"]);
  });

  it("does not resolve any secret when whole-scope biometric authentication fails", async () => {
    biometricMock.mockImplementationOnce(() => {
      throw new Error("Biometric authentication failed or was cancelled.");
    });
    const resolveSecret = vi.fn(() => "sk-test-secret");
    const ensureUnlocked = vi.fn(async () => undefined);
    let stderr = "";

    const result = await runCommandWithSecrets({
      args: [process.execPath, "-e", "process.exit(0)"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret,
      ensureUnlocked,
      authorize: () => { biometricMock("whole-scope test"); return approveOperator(); },
      stdout: () => {},
      stderr: (chunk) => { stderr += chunk; },
    });

    expect(result.kind).toBe("blocked");
    expect(result.exitCode).toBe(2);
    expect(resolveSecret).not.toHaveBeenCalled();
    expect(ensureUnlocked).not.toHaveBeenCalled();
    expect(stderr).toContain("Biometric authentication failed or was cancelled.");
  });

  it("rejects an invalid complete selection before unlock, decryption, or child launch", async () => {
    const ensureUnlocked = vi.fn(async () => undefined);
    const resolveSecret = vi.fn(() => "secret-value");
    let stdout = "";

    const result = await runCommandWithSecrets({
      args: [
        "--env", "FIRST:DUPLICATE",
        "--env", "SECOND:DUPLICATE",
        "--", process.execPath, "-e", "process.stdout.write('launched')",
      ],
      baseEnv: {},
      secretNames: ["FIRST", "SECOND"],
      resolveSecret,
      ensureUnlocked,
      stdout: (chunk) => { stdout += chunk; },
      stderr: () => {},
    });

    expect(result).toEqual({ kind: "error", exitCode: 1 });
    expect(ensureUnlocked).not.toHaveBeenCalled();
    expect(resolveSecret).not.toHaveBeenCalled();
    expect(stdout).toBe("");
  });

  it("keeps explicit least-privilege injection non-interactive", async () => {
    const result = await runCommandWithSecrets({
      args: ["--env", "API_KEY", "--", process.execPath, "-e", "process.exit(0)"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "sk-test-secret",
      stdout: () => {},
      stderr: () => {},
    });

    expect(result.kind).toBe("exit");
    expect(biometricMock).not.toHaveBeenCalled();
  });

  it("rejects a malformed whole-scope name before auth, unlock, decryption, or child launch", async () => {
    let stdout = "";
    const ensureUnlocked = vi.fn(async () => undefined);
    const resolveSecret = vi.fn((name: string) => (name === "API_KEY" ? "ok" : "hyphen-value"));
    const result = await runCommandWithSecrets({
      args: [process.execPath, "-e", "process.stdout.write(process.env.API_KEY === 'ok' && process.env['MY-API-KEY'] === undefined ? 'ok' : 'bad')"],
      baseEnv: {},
      secretNames: ["API_KEY", "MY-API-KEY"],
      resolveSecret,
      ensureUnlocked,
      stdout: (chunk) => { stdout += chunk; },
      stderr: () => {},
    });

    expect(result).toEqual({ kind: "error", exitCode: 1 });
    expect(stdout).toBe("");
    expect(biometricMock).not.toHaveBeenCalled();
    expect(ensureUnlocked).not.toHaveBeenCalled();
    expect(resolveSecret).not.toHaveBeenCalled();
  });

  it("does not launch a whole-scope child when a listed secret disappears", async () => {
    let stdout = "";
    const decrypt = vi.fn((name: string) => `${name}-value`);
    const resolveSecret = vi.fn(() => { throw new Error("individual resolution must not run"); });
    const result = await runCommandWithSecrets({
      args: [process.execPath, "-e", "process.stdout.write('launched')"],
      baseEnv: {},
      secretNames: ["FIRST", "SECOND"],
      resolveSecret,
      resolveSecrets: (names) => {
        const existing = new Set(["FIRST"]);
        for (const name of names) {
          if (!existing.has(name)) throw new Error(`Secret "${name}" disappeared before it could be injected.`);
        }
        return new Map(names.map((name) => [name, decrypt(name)]));
      },
      ensureUnlocked: async () => undefined,
      authorize: () => { biometricMock("whole-scope test"); return approveOperator(); },
      stdout: (chunk) => { stdout += chunk; },
      stderr: () => {},
    });

    expect(result).toEqual({ kind: "error", exitCode: 1 });
    expect(stdout).toBe("");
    expect(biometricMock).toHaveBeenCalledOnce();
    expect(resolveSecret).not.toHaveBeenCalled();
    expect(decrypt).not.toHaveBeenCalled();
  });

  it("reports a child executable that cannot be started", async () => {
    let stderr = "";
    const result = await runCommandWithSecrets({
      args: ["--env", "API_KEY", "--", "keyclasp-command-that-does-not-exist"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "sk-test-secret",
      authorize: approveOperator,
      stdout: () => {},
      stderr: (chunk) => { stderr += chunk; },
    });

    expect(result.kind).toBe("error");
    expect(result.exitCode).toBe(1);
    expect(stderr).toBe("Failed to start child command (ENOENT).\n");
  });

  it("reports raw spawn failures without reflecting terminal control characters", async () => {
    let stderr = "";
    const result = await runCommandWithSecrets({
      args: ["--env", "API_KEY", "--", "missing\n\u001b[31m-command"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "sk-test-secret",
      stdout: () => {},
      stderr: (chunk) => { stderr += chunk; },
    });

    expect(result.kind).toBe("error");
    expect(stderr).toBe("Failed to start child command (ENOENT).\n");
    expect(stderr).not.toContain("sk-test-secret");
    expect(stderr).not.toContain("\u001b");
  });

  it("reports spawn failures when unsafe mode is explicitly enabled", async () => {
    let stderr = "";
    const result = await runCommandWithSecrets({
      args: ["--allow-unsafe", "--env", "API_KEY", "--", "keyclasp-command-that-does-not-exist"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "sk-test-secret",
      stdout: () => {},
      stderr: (chunk) => { stderr += chunk; },
    });

    expect(result.kind).toBe("error");
    expect(stderr).toContain("WARNING:");
    expect(stderr).toContain("Failed to start child command (ENOENT).");
  });

  it("blocks unsafe commands before spawn unless overridden", async () => {
    const resolvedNames: string[] = [];
    let blockedStderr = "";
    const blocked = await runCommandWithSecrets({
      args: ["env", "sk-test-secret"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      envSpecs: [{ sourceName: "API_KEY", targetName: "ALIAS_KEY" }],
      resolveSecret: (name) => {
        resolvedNames.push(name);
        return "sk-test-secret";
      },
      stdout: () => {},
      stderr: (chunk) => { blockedStderr += chunk; },
    });

    let allowedStderr = "";
    const allowed = await runCommandWithSecrets({
      args: ["--allow-unsafe", "env", "-i", process.execPath, "-e", "process.exit(7)"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "sk-test-secret",
      authorize: approveOperator,
      stdout: () => {},
      stderr: (chunk) => { allowedStderr += chunk; },
    });

    expect(blocked.kind).toBe("blocked");
    expect(blocked.exitCode).toBe(2);
    expect(resolvedNames).toEqual([]);
    expect(blockedStderr).toContain("BLOCKED:");
    expect(blockedStderr).toContain("keyclasp run --allow-unsafe -- <command...>");
    expect(blockedStderr).not.toContain("sk-test-secret");

    let shellBlockedStderr = "";
    const shellBlocked = await runCommandWithSecrets({
      args: ["sh", "-c", "env sk-test-secret"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "sk-test-secret",
      stdout: () => {},
      stderr: (chunk) => { shellBlockedStderr += chunk; },
    });

    expect(shellBlocked.kind).toBe("blocked");
    expect(shellBlockedStderr).toContain("BLOCKED:");
    expect(shellBlockedStderr).not.toContain("sk-test-secret");

    expect(allowed.kind).toBe("exit");
    expect(allowed.exitCode).toBe(7);
    expect(allowedStderr).toContain("WARNING:");
  });

  it("injects an explicit env mapping into the child process", async () => {
    let stdout = "";
    const result = await runCommandWithSecrets({
      args: [
        "--env",
        "HELLO:WORLD",
        "--",
        process.execPath,
        "-e",
        "console.log(process.env.WORLD === 'mapped-secret' ? 'ok' : 'missing');",
      ],
      baseEnv: {},
      secretNames: ["HELLO"],
      resolveSecret: (name) => (name === "HELLO" ? "mapped-secret" : null),
      stdout: (chunk) => { stdout += chunk; },
      stderr: () => {},
    });

    expect(result.kind).toBe("exit");
    expect(result.exitCode).toBe(0);
    expect(stdout).toBe("ok\n");
  });

  it("passes clean output and child exit code through", async () => {
    let stdout = "";
    const result = await runCommandWithSecrets({
      args: [process.execPath, "-e", "console.log(process.env.API_KEY ? 'ok' : 'missing'); process.exit(3)"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "sk-test-secret",
      authorize: approveOperator,
      stdout: (chunk) => { stdout += chunk; },
      stderr: () => {},
    });

    expect(result.kind).toBe("exit");
    expect(result.exitCode).toBe(3);
    expect(stdout).toBe("ok\n");
  });

  it("does not treat short injected values as output leaks", async () => {
    let stdout = "";
    const result = await runCommandWithSecrets({
      args: [process.execPath, "-e", "console.log('Initializing available terraform packages')"],
      baseEnv: {},
      secretNames: ["LETTER"],
      resolveSecret: () => "a",
      authorize: approveOperator,
      stdout: (chunk) => { stdout += chunk; },
      stderr: () => {},
    });

    expect(result.kind).toBe("exit");
    expect(result.exitCode).toBe(0);
    expect(stdout).toBe("Initializing available terraform packages\n");
    expect(stdout).not.toContain("[KEYCLASP_REDACTED]");
  });

  it("redacts stdout leaks and returns nonzero", async () => {
    let stdout = "";
    let stderr = "";
    const result = await runCommandWithSecrets({
      args: [process.execPath, "-e", "console.log(process.env.API_KEY); setInterval(() => {}, 1000)"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "sk-test-secret",
      authorize: approveOperator,
      stdout: (chunk) => { stdout += chunk; },
      stderr: (chunk) => { stderr += chunk; },
    });

    expect(result.kind).toBe("leak");
    expect(result.exitCode).toBe(2);
    expect(stdout).toContain("[KEYCLASP_REDACTED]");
    expect(stdout).not.toContain("sk-test-secret");
    expect(stderr).toContain("terminated");
  });

  it("redacts stderr leaks split across chunks", async () => {
    let stderr = "";
    const result = await runCommandWithSecrets({
      args: [
        process.execPath,
        "-e",
        "process.stderr.write('before sk-test'); setTimeout(() => process.stderr.write('-secret after'), 10); setInterval(() => {}, 1000)",
      ],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "sk-test-secret",
      authorize: approveOperator,
      stdout: () => {},
      stderr: (chunk) => { stderr += chunk; },
    });

    expect(result.kind).toBe("leak");
    expect(stderr).toContain("before ");
    expect(stderr).toContain("[KEYCLASP_REDACTED] after");
    expect(stderr).not.toContain("sk-test-secret");
  });

  it("redacts unicode secrets split across buffer boundaries", async () => {
    let stdout = "";
    const result = await runCommandWithSecrets({
      args: [
        process.execPath,
        "-e",
        [
          "const value = Buffer.from(process.env.API_KEY, 'utf8');",
          "process.stdout.write(Buffer.concat([Buffer.from('before '), value.subarray(0, 4)]));",
          "setTimeout(() => process.stdout.write(Buffer.concat([value.subarray(4), Buffer.from(' after')])), 10);",
          "setInterval(() => {}, 1000);",
        ].join(" "),
      ],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "sk-😀-secret",
      authorize: approveOperator,
      stdout: (chunk) => { stdout += chunk; },
      stderr: () => {},
    });

    expect(result.kind).toBe("leak");
    expect(stdout).toContain("before [KEYCLASP_REDACTED] after");
    expect(stdout).not.toContain("sk-😀-secret");
  });

  it("forces termination when a leaking child ignores SIGTERM", async () => {
    const result = await runCommandWithSecrets({
      args: [
        process.execPath,
        "-e",
        "process.on('SIGTERM', () => {}); console.log(process.env.API_KEY); setInterval(() => {}, 1000)",
      ],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "sk-test-secret",
      authorize: approveOperator,
      stdout: () => {},
      stderr: () => {},
    });

    expect(result.kind).toBe("leak");
    expect(result.exitCode).toBe(2);
  });

  it("preserves child signal exit codes for clean guarded commands", async () => {
    const result = await runCommandWithSecrets({
      args: [process.execPath, "-e", "process.kill(process.pid, 'SIGTERM')"],
      baseEnv: {},
      secretNames: [],
      resolveSecret: () => null,
      authorize: approveOperator,
      stdout: () => {},
      stderr: () => {},
    });

    expect(result.kind).toBe("exit");
    expect(result.exitCode).toBe(143);
  });
});
