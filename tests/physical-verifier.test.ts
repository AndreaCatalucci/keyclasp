import { describe, expect, it } from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
// The verifier is an intentionally standalone JavaScript operator script.
// @ts-expect-error No declaration file is needed for this internal script.
import { assertCancelledLockedRun, createTranscriptRecorder, evidenceSummary, spawnWithLiveTranscript } from "../scripts/verify-slice2-touch-id.mjs";

describe("Slice 3 physical-verifier result classification", () => {
  it("streams an interactive prompt before the child exits while retaining transcript output", async () => {
    let resolvePrompt!: () => void;
    const promptSeen = new Promise<void>((resolve) => { resolvePrompt = resolve; });
    let displayed = "";
    const stdoutSink = {
      write(chunk: string) {
        displayed += chunk;
        if (displayed.includes("Enter vault passphrase: ")) resolvePrompt();
        return true;
      },
    };
    let settled = false;
    const running = spawnWithLiveTranscript(process.execPath, [
      "-e",
      "process.stdout.write('Enter vault passphrase: '); setTimeout(() => process.exit(0), 100);",
    ], { stdoutSink, stderrSink: { write: () => true } }).finally(() => { settled = true; });

    await promptSeen;
    expect(settled).toBe(false);
    const result = await running;
    expect(result.status).toBe(0);
    expect(result.stdout).toBe("Enter vault passphrase: ");
    expect(displayed).toBe(result.stdout);
  });

  it("accepts only status 2 with the exact cancellation BLOCKED output", () => {
    expect(() => assertCancelledLockedRun({
      status: 2,
      stdout: "",
      stderr: "BLOCKED: Biometric authentication was cancelled by the operator.\n",
    })).not.toThrow();
  });

  it.each([
    ["approved authorization", { status: 0, stdout: "", stderr: "" }],
    ["helper failure", { status: 2, stdout: "", stderr: "BLOCKED: The macOS biometric authentication helper could not start.\n" }],
    ["lifecycle lock failure", { status: 1, stdout: "", stderr: "database is locked\n" }],
    ["syntax failure", { status: 1, stdout: "", stderr: "Usage: keyclasp run [options]\n" }],
    ["unavailable biometrics", { status: 2, stdout: "", stderr: "BLOCKED: Touch ID is unavailable or not enrolled.\n" }],
    ["authentication denial", { status: 2, stdout: "", stderr: "BLOCKED: Biometric authentication failed.\n" }],
    ["ordinary status-2 error", { status: 2, stdout: "", stderr: "ordinary error\n" }],
    ["extra output", { status: 2, stdout: "unexpected\n", stderr: "BLOCKED: Biometric authentication was cancelled by the operator.\n" }],
    ["extra blank stderr", { status: 2, stdout: "", stderr: "BLOCKED: Biometric authentication was cancelled by the operator.\n\n" }],
    ["spawn failure", { status: null, stdout: "", stderr: "", error: new Error("spawn failed") }],
  ])("rejects %s", (_label, result) => {
    expect(() => assertCancelledLockedRun(result)).toThrow();
  });

  it("records every interaction and final result in an owner-only transcript", () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), "keyclasp-physical-transcript-"));
    const now = () => new Date("2026-08-24T06:00:00.000Z");
    try {
      const transcript = createTranscriptRecorder(root, now);
      transcript.note("1/3 Approve Touch ID to lock the scope.");
      transcript.record("scope-lock", { status: 0, signal: null, stdout: "locked\n", stderr: "" });
      transcript.note("2/3 Click Cancel.");
      transcript.record("locked-run-cancel", { status: 2, signal: null, stdout: "", stderr: `${CANCELLED_FOR_TEST}\n` });
      transcript.note("3/3 Approve Touch ID to unlock the scope.");
      transcript.record("scope-unlock", { status: 0, signal: null, stdout: "unlocked\n", stderr: "" });
      transcript.finish("PASS");

      const content = fs.readFileSync(transcript.path, "utf8");
      expect(fs.statSync(transcript.path).mode & 0o777).toBe(0o600);
      expect(content).toContain("started_at=2026-08-24T06:00:00.000Z");
      expect(content).toContain("[scope-lock]\nstatus=0");
      expect(content).toContain(`[locked-run-cancel]\nstatus=2\nsignal=null\nerror=\nstdout:\n\nstderr:\n${CANCELLED_FOR_TEST}`);
      expect(content).toContain("[scope-unlock]\nstatus=0");
      expect(content).toContain("\nPASS\nfinished_at=2026-08-24T06:00:00.000Z\n");
      expect(evidenceSummary(root, transcript.path)).toEqual([`Evidence: ${root}`, `Transcript: ${transcript.path}`]);

      const failedRoot = fs.mkdtempSync(path.join(root, "failed-"));
      const failed = createTranscriptRecorder(failedRoot, now);
      failed.record("locked-run-cancel", { status: 1, signal: null, stdout: "", stderr: "ordinary error\n" });
      failed.finish("FAIL: cancellation evidence was invalid");
      expect(fs.readFileSync(failed.path, "utf8")).toContain("\nFAIL: cancellation evidence was invalid\nfinished_at=");
    } finally {
      fs.rmSync(root, { recursive: true, force: true });
    }
  });
});

const CANCELLED_FOR_TEST = "BLOCKED: Biometric authentication was cancelled by the operator.";
