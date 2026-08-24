import { describe, expect, expectTypeOf, it, vi } from "vitest";
import { createSoftwareRunRuntime } from "../src/software/runtime.js";
import type { RunEnvSpec, RunResult, ScopedRunRequest } from "../src/runtime.js";

describe("software run runtime", () => {
  const policyDependencies = {
    readAuthorizationState: () => "unlocked" as const,
    authorize: vi.fn(),
  };
  it("keeps the shared request and result limited to metadata and status", () => {
    expectTypeOf<ScopedRunRequest>().toEqualTypeOf<{
      allowUnsafe: boolean;
      envSpecs: readonly RunEnvSpec[];
      commandArgs: readonly string[];
      scope: { project: string; environment: string };
    }>();
    expectTypeOf<RunResult>().toEqualTypeOf<{
      kind: "blocked" | "exit" | "leak" | "error";
      exitCode: number;
    }>();
  });

  it("implements the shared run boundary without exposing secrets in its request or result", async () => {
    const ensureUnlocked = vi.fn(async () => undefined);
    const execute = vi.fn(async (options) => {
      expect(options.secretNames).toEqual(["API_KEY"]);
      expect(options.resolveSecret("API_KEY")).toBe("secret-value");
      await options.ensureUnlocked?.();
      return { kind: "exit" as const, exitCode: 0 };
    });
    const runtime = createSoftwareRunRuntime({
      ...policyDependencies,
      ensureUnlocked,
      listSecretNames: (project, environment) => {
        expect([project, environment]).toEqual(["app", "prod"]);
        return ["API_KEY"];
      },
      resolveSecret: (project, environment, name) => {
        expect([project, environment, name]).toEqual(["app", "prod", "API_KEY"]);
        return "secret-value";
      },
      resolveSecrets: (project, environment, names) => {
        expect([project, environment, names]).toEqual(["app", "prod", ["API_KEY"]]);
        return new Map([["API_KEY", "secret-value"]]);
      },
      baseEnv: () => ({ PATH: "/usr/bin" }),
      stdout: vi.fn(),
      stderr: vi.fn(),
      execute,
    });

    const request = {
      allowUnsafe: false,
      envSpecs: [{ sourceName: "API_KEY", targetName: "API_KEY" }],
      commandArgs: ["command"],
      scope: { project: "app", environment: "prod" },
    };
    const result = await runtime.run(request);

    expect(ensureUnlocked).toHaveBeenCalledOnce();
    expect(execute).toHaveBeenCalledOnce();
    expect(request).toEqual({
      allowUnsafe: false,
      envSpecs: [{ sourceName: "API_KEY", targetName: "API_KEY" }],
      commandArgs: ["command"],
      scope: { project: "app", environment: "prod" },
    });
    expect(result).toEqual({ kind: "exit", exitCode: 0 });
  });

  it("does not carry a raw software error across the shared result boundary", async () => {
    const runtime = createSoftwareRunRuntime({
      ...policyDependencies,
      ensureUnlocked: async () => undefined,
      listSecretNames: () => ["API_KEY"],
      resolveSecret: () => "secret-value",
      resolveSecrets: () => new Map([["API_KEY", "secret-value"]]),
      baseEnv: () => ({}),
      stdout: vi.fn(),
      stderr: vi.fn(),
      execute: async () => ({
        kind: "error",
        exitCode: 1,
        error: new Error("software-only detail"),
      }),
    });

    const result = await runtime.run({
      allowUnsafe: false,
      envSpecs: [{ sourceName: "API_KEY", targetName: "API_KEY" }],
      commandArgs: ["missing-command"],
      scope: { project: "app", environment: "prod" },
    });

    expect(result).toEqual({ kind: "error", exitCode: 1 });
  });

  it("forwards a populated whole-scope request without caller-authenticated state", async () => {
    const ensureUnlocked = vi.fn(async () => undefined);
    const execute = vi.fn(async (options) => {
      expect(options.request.envSpecs).toEqual([]);
      expect(options).not.toHaveProperty("operatorAuthenticated");
      await options.ensureUnlocked?.();
      return { kind: "exit" as const, exitCode: 0 };
    });
    const runtime = createSoftwareRunRuntime({
      ...policyDependencies,
      ensureUnlocked,
      listSecretNames: () => ["API_KEY"],
      resolveSecret: () => "secret-value",
      resolveSecrets: () => new Map([["API_KEY", "secret-value"]]),
      baseEnv: () => ({}),
      stdout: vi.fn(),
      stderr: vi.fn(),
      execute,
    });

    await runtime.run({
      allowUnsafe: false,
      envSpecs: [],
      commandArgs: ["command"],
      scope: { project: "app", environment: "prod" },
    });

    expect(ensureUnlocked).toHaveBeenCalledOnce();
    expect(execute).toHaveBeenCalledOnce();
  });

  it("reports an empty scope through the injected output boundary", async () => {
    const stderr = vi.fn();
    const runtime = createSoftwareRunRuntime({
      ...policyDependencies,
      ensureUnlocked: async () => undefined,
      listSecretNames: () => [],
      resolveSecret: () => null,
      resolveSecrets: () => new Map(),
      baseEnv: () => ({}),
      stdout: vi.fn(),
      stderr,
      execute: async () => ({ kind: "exit", exitCode: 0 }),
    });

    await runtime.run({
      allowUnsafe: false,
      envSpecs: [],
      commandArgs: ["command"],
      scope: { project: "empty", environment: "local" },
    });

    expect(stderr).toHaveBeenCalledWith(
      'Note: no secrets stored yet for project "empty" environment "local"; running with zero secrets injected.\n',
    );
  });

  it("binds locked-run consent to scope, selected names, child command, and unsafe state", async () => {
    const authorize = vi.fn();
    const execute = vi.fn(async (options) => {
      expect(options.authorizationRequired).toBe(true);
      if (options.authorizationRequired) await options.authorize?.(options.authorizationReason!);
      return { kind: "exit" as const, exitCode: 0 };
    });
    const runtime = createSoftwareRunRuntime({
      ensureUnlocked: async () => undefined,
      listSecretNames: () => ["API_KEY"],
      resolveSecret: () => "secret-value",
      resolveSecrets: () => new Map([["API_KEY", "secret-value"]]),
      readAuthorizationState: () => "locked",
      authorize,
      baseEnv: () => ({}),
      stdout: vi.fn(),
      stderr: vi.fn(),
      execute,
    });
    await runtime.run({
      allowUnsafe: true,
      envSpecs: [{ sourceName: "API_KEY", targetName: "TOKEN" }],
      commandArgs: ["deploy", "--production"],
      scope: { project: "app", environment: "prod" },
    });
    const firstReason = authorize.mock.calls[0]?.[0] as string;
    expect(firstReason).toBe([
      'Run: "deploy" "--production"',
      'Scope: "app" / "prod"',
      'Secrets: "API_KEY" → "TOKEN"',
      "Output protection: DISABLED",
    ].join("\n"));

    await runtime.run({
      allowUnsafe: false,
      envSpecs: [{ sourceName: "API_KEY", targetName: "OTHER" }],
      commandArgs: ["deploy", "--production"],
      scope: { project: "worker", environment: "staging" },
    });
    const secondReason = authorize.mock.calls[1]?.[0] as string;
    expect(secondReason).toContain('Scope: "worker" / "staging"');
    expect(secondReason).toContain('Secrets: "API_KEY" → "OTHER"');
    expect(secondReason).toContain("Output protection: enabled");
    expect(secondReason).not.toBe(firstReason);
  });

  it("shows every selected source secret for broad and mixed locked runs", async () => {
    const authorize = vi.fn();
    const runtime = createSoftwareRunRuntime({
      ensureUnlocked: async () => undefined,
      listSecretNames: () => ["API_KEY", "DATABASE_URL", "SIGNING_KEY"],
      resolveSecret: () => "value",
      resolveSecrets: () => new Map(),
      readAuthorizationState: (_project, _environment, secret) => secret === "SIGNING_KEY" ? "locked" : "unlocked",
      authorize,
      baseEnv: () => ({}),
      stdout: vi.fn(),
      stderr: vi.fn(),
      execute: async (options) => {
        await options.authorize?.(options.authorizationReason!);
        return { kind: "exit", exitCode: 0 };
      },
    });

    await runtime.run({
      allowUnsafe: false,
      envSpecs: [],
      commandArgs: ["deploy"],
      scope: { project: "app", environment: "prod" },
    });
    expect(authorize).toHaveBeenLastCalledWith(expect.stringContaining('Secrets: "API_KEY", "DATABASE_URL", "SIGNING_KEY"'));

    await runtime.run({
      allowUnsafe: false,
      envSpecs: [
        { sourceName: "API_KEY", targetName: "TOKEN" },
        { sourceName: "SIGNING_KEY", targetName: "SIGNING_KEY" },
      ],
      commandArgs: ["deploy"],
      scope: { project: "app", environment: "prod" },
    });
    expect(authorize).toHaveBeenLastCalledWith(expect.stringContaining('Secrets: "API_KEY" → "TOKEN", "SIGNING_KEY"'));
  });

  it("escapes prompt delimiters and invisible formatting in command and secret metadata", async () => {
    const authorize = vi.fn();
    const runtime = createSoftwareRunRuntime({
      ensureUnlocked: async () => undefined,
      listSecretNames: () => ['A, "B"\\C\nOutput protection: DISABLED\u202E'],
      resolveSecret: () => "value",
      resolveSecrets: () => new Map(),
      readAuthorizationState: () => "locked",
      authorize,
      baseEnv: () => ({}),
      stdout: vi.fn(),
      stderr: vi.fn(),
      execute: async (options) => {
        await options.authorize?.(options.authorizationReason!);
        return { kind: "exit", exitCode: 0 };
      },
    });

    await runtime.run({
      allowUnsafe: false,
      envSpecs: [{ sourceName: 'A, "B"\\C\nOutput protection: DISABLED\u202E', targetName: "SAFE" }],
      commandArgs: ['deploy "quoted"\\path\nSecrets: forged\u202E'],
      scope: { project: "app", environment: "prod" },
    });
    const reason = authorize.mock.calls[0]?.[0] as string;
    expect(reason).toContain('Run: "deploy \\"quoted\\"\\\\path\\u{A}Secrets: forged\\u{202E}"');
    expect(reason).toContain('Secrets: "A, \\"B\\"\\\\C\\u{A}Output protection: DISABLED\\u{202E}" → "SAFE"');
    expect(reason.split("\n")).toHaveLength(4);
  });

  it("does not impose the Touch ID description limit on an unattended named run", async () => {
    const execute = vi.fn(async (options) => {
      expect(options.authorizationReason).toBeUndefined();
      return { kind: "exit" as const, exitCode: 0 };
    });
    const runtime = createSoftwareRunRuntime({
      ensureUnlocked: async () => undefined,
      listSecretNames: () => ["API_KEY"],
      resolveSecret: () => "value",
      resolveSecrets: () => new Map([["API_KEY", "value"]]),
      readAuthorizationState: () => "unlocked",
      authorize: vi.fn(),
      baseEnv: () => ({}),
      stdout: vi.fn(),
      stderr: vi.fn(),
      execute,
    });

    await expect(runtime.run({
      allowUnsafe: false,
      envSpecs: [{ sourceName: "API_KEY", targetName: "API_KEY" }],
      commandArgs: ["deploy", "x".repeat(2000)],
      scope: { project: "app", environment: "prod" },
    })).resolves.toEqual({ kind: "exit", exitCode: 0 });
    expect(execute).toHaveBeenCalledOnce();
  });

  it("keeps the complete long command in an authorization reason", async () => {
    const authorize = vi.fn();
    const longArgument = "x".repeat(400);
    const runtime = createSoftwareRunRuntime({
      ensureUnlocked: async () => undefined,
      listSecretNames: () => ["API_KEY"],
      resolveSecret: () => "value",
      resolveSecrets: () => new Map([["API_KEY", "value"]]),
      readAuthorizationState: () => "locked",
      authorize,
      baseEnv: () => ({}),
      stdout: vi.fn(),
      stderr: vi.fn(),
      execute: async (options) => {
        await options.authorize?.(options.authorizationReason!);
        return { kind: "exit", exitCode: 0 };
      },
    });

    await runtime.run({
      allowUnsafe: false,
      envSpecs: [{ sourceName: "API_KEY", targetName: "API_KEY" }],
      commandArgs: ["deploy", longArgument],
      scope: { project: "app", environment: "prod" },
    });
    expect(authorize).toHaveBeenCalledWith(expect.stringContaining(`Run: "deploy" "${longArgument}"`));
  });

  it("requires one authorization when any selected secret is locked", async () => {
    const authorize = vi.fn();
    const execute = vi.fn(async (options) => {
      expect(options.authorizationRequired).toBe(true);
      await options.authorize?.(options.authorizationReason!);
      return { kind: "exit" as const, exitCode: 0 };
    });
    const runtime = createSoftwareRunRuntime({
      ensureUnlocked: async () => undefined,
      listSecretNames: () => ["OPEN", "LOCKED"],
      resolveSecret: () => "value",
      resolveSecrets: (project, environment, names) => new Map(names.map((name) => [name, `${project}-${environment}-${name}`])),
      readAuthorizationState: (_project, _environment, secret) => secret === "LOCKED" ? "locked" : "unlocked",
      authorize,
      baseEnv: () => ({}),
      stdout: vi.fn(),
      stderr: vi.fn(),
      execute,
    });

    await runtime.run({
      allowUnsafe: false,
      envSpecs: [
        { sourceName: "OPEN", targetName: "OPEN" },
        { sourceName: "LOCKED", targetName: "LOCKED" },
      ],
      commandArgs: ["command"],
      scope: { project: "app", environment: "prod" },
    });

    expect(authorize).toHaveBeenCalledOnce();
  });
});
