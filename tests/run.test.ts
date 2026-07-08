import { describe, expect, it } from "vitest";
import {
  buildRunEnvironment,
  checkUnsafeCommand,
  createSecretRedactor,
  parseRunArgs,
  runCommandWithSecrets,
} from "../src/run.js";

describe("run argument parsing", () => {
  it("removes separators and preserves a safe command", () => {
    expect(parseRunArgs(["--", "npm", "test"])).toEqual({
      allowUnsafe: false,
      commandArgs: ["npm", "test"],
    });
  });

  it("consumes --allow-unsafe before the child command", () => {
    expect(parseRunArgs(["--allow-unsafe", "--", "env"])).toEqual({
      allowUnsafe: true,
      commandArgs: ["env"],
    });
  });

  it("preserves child arguments after the separator", () => {
    expect(parseRunArgs(["--", "node", "--allow-unsafe"])).toEqual({
      allowUnsafe: false,
      commandArgs: ["node", "--allow-unsafe"],
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
      secretNames: ["API_KEY", "EMPTY_SECRET", "NULL_VAL", "NULL\0NAME"],
      resolveSecret: (name) => {
        if (name === "API_KEY") return "sk-test-secret";
        if (name === "EMPTY_SECRET") return "";
        if (name === "NULL_VAL") return "before\0after";
        return "ignored";
      },
    });

    expect(result.env.API_KEY).toBe("sk-test-secret");
    expect(result.env.EMPTY_SECRET).toBe("");
    expect(result.env.NULL_VAL).toBeUndefined();
    expect(result.env["NULL\0NAME"]).toBeUndefined();
    expect(result.leakValues).toEqual(["sk-test-secret"]);
  });
});

describe("secret redaction", () => {
  it("redacts a secret in one chunk", () => {
    const redactor = createSecretRedactor(["sk-test-secret"]);
    const written = redactor.write("before sk-test-secret after");
    const final = redactor.end();

    expect(written.leaked || final.leaked).toBe(true);
    expect(written.output + final.output).toBe("before [KEYBLIND_REDACTED] after");
  });

  it("does not flush a split secret before it can be detected", () => {
    const redactor = createSecretRedactor(["sk-test-secret"]);
    const first = redactor.write("prefix sk-test");
    const second = redactor.write("-secret suffix");
    const final = redactor.end();

    expect(first.output).not.toContain("sk-test");
    expect(first.leaked).toBe(false);
    expect(first.output + second.output + final.output).toBe("prefix [KEYBLIND_REDACTED] suffix");
    expect(second.leaked).toBe(true);
  });

  it("does not treat sandbox-looking values as leaks unless they are tracked", () => {
    const redactor = createSecretRedactor(["sk-real-secret"]);
    const written = redactor.write("KEYBLIND_SANDBOX_deadbeef");
    const final = redactor.end();

    expect(written.leaked || final.leaked).toBe(false);
    expect(written.output + final.output).toBe("KEYBLIND_SANDBOX_deadbeef");
  });

  it("keeps carry state after one leak to catch a second split secret", () => {
    const redactor = createSecretRedactor(["first-secret", "second-secret"]);
    const first = redactor.write("before first-secret then second");
    const second = redactor.write("-secret after");
    const final = redactor.end();
    const output = first.output + second.output + final.output;

    expect(first.leaked || second.leaked || final.leaked).toBe(true);
    expect(output).toBe("before [KEYBLIND_REDACTED] then [KEYBLIND_REDACTED] after");
    expect(output).not.toContain("first-secret");
    expect(output).not.toContain("second-secret");
  });
});

describe("guarded command execution", () => {
  it("blocks unsafe commands before spawn unless overridden", async () => {
    const resolvedNames: string[] = [];
    let blockedStderr = "";
    const blocked = await runCommandWithSecrets({
      args: ["env", "sk-test-secret"],
      baseEnv: {},
      secretNames: ["API_KEY"],
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
      stdout: () => {},
      stderr: (chunk) => { allowedStderr += chunk; },
    });

    expect(blocked.kind).toBe("blocked");
    expect(blocked.exitCode).toBe(2);
    expect(resolvedNames).toEqual([]);
    expect(blockedStderr).toContain("BLOCKED:");
    expect(blockedStderr).toContain("keyblind run --allow-unsafe -- <command...>");
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

  it("passes clean output and child exit code through", async () => {
    let stdout = "";
    const result = await runCommandWithSecrets({
      args: [process.execPath, "-e", "console.log(process.env.API_KEY ? 'ok' : 'missing'); process.exit(3)"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "sk-test-secret",
      stdout: (chunk) => { stdout += chunk; },
      stderr: () => {},
    });

    expect(result.kind).toBe("exit");
    expect(result.exitCode).toBe(3);
    expect(stdout).toBe("ok\n");
  });

  it("redacts stdout leaks and returns nonzero", async () => {
    let stdout = "";
    let stderr = "";
    const result = await runCommandWithSecrets({
      args: [process.execPath, "-e", "console.log(process.env.API_KEY); setInterval(() => {}, 1000)"],
      baseEnv: {},
      secretNames: ["API_KEY"],
      resolveSecret: () => "sk-test-secret",
      stdout: (chunk) => { stdout += chunk; },
      stderr: (chunk) => { stderr += chunk; },
    });

    expect(result.kind).toBe("leak");
    expect(result.exitCode).toBe(2);
    expect(stdout).toContain("[KEYBLIND_REDACTED]");
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
      stdout: () => {},
      stderr: (chunk) => { stderr += chunk; },
    });

    expect(result.kind).toBe("leak");
    expect(stderr).toContain("before ");
    expect(stderr).toContain("[KEYBLIND_REDACTED] after");
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
      stdout: (chunk) => { stdout += chunk; },
      stderr: () => {},
    });

    expect(result.kind).toBe("leak");
    expect(stdout).toContain("before [KEYBLIND_REDACTED] after");
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
      stdout: () => {},
      stderr: () => {},
    });

    expect(result.kind).toBe("exit");
    expect(result.exitCode).toBe(143);
  });
});
