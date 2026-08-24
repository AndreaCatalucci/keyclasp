import { describe, expect, it } from "vitest";
import {
  classifyHardwareStatus,
  defaultBrokerPath,
  inspectHardwareMode,
  parseBrokerStatus,
  type BrokerStatus,
} from "../src/hardware/status.js";
import path from "node:path";

const STATUS_TEXT = [
  "protocol_version=1",
  "adapter=keyclasp_macos_v1",
  "reported_backend=secure_enclave",
  "hardware_presence_available=true",
  "touch_id_available=true",
  "code_identity=ad_hoc",
  "required_access_policy=biometric_current_set",
  "current_set_policy_available=true",
  "lifecycle_operations=disabled",
  "enrollment_state=unavailable",
  "",
].join("\n");

const STATUS: BrokerStatus = parseBrokerStatus(STATUS_TEXT);

describe("status-only broker protocol", () => {
  it("resolves the default core outside the compiled dist directory", () => {
    expect(defaultBrokerPath()).toBe(
      path.join(process.cwd(), "native/keyclasp-core/dist/keyclasp-core-spike"),
    );
  });

  it("accepts the exact versioned status response", () => {
    expect(STATUS).toEqual({
      protocolVersion: 1,
      adapter: "keyclasp_macos_v1",
      backend: "secure_enclave",
      hardwarePresence: true,
      touchIdAvailable: true,
      codeIdentity: "ad_hoc",
      requiredAccessPolicy: "biometric_current_set",
      currentSetPolicyAvailable: true,
      lifecycleOperations: "disabled",
      enrollmentState: "unavailable",
    });
  });

  it.each([
    STATUS_TEXT.replace("protocol_version=1", "protocol_version=2"),
    STATUS_TEXT.replace("adapter=keyclasp_macos_v1\n", ""),
    STATUS_TEXT + "unknown=value\n",
    STATUS_TEXT.replace("touch_id_available=true", "touch_id_available=yes"),
    STATUS_TEXT.replace("code_identity=ad_hoc", "code_identity=developer_id\ncode_identity=ad_hoc"),
  ])("rejects malformed or incompatible responses", (output) => {
    expect(() => parseBrokerStatus(output)).toThrow();
  });

  it("distinguishes damaged enrollment and recovery-required identity changes", () => {
    expect(classifyHardwareStatus({ ...STATUS, enrollmentState: "damaged" })).toMatchObject({
      enrollment: "damaged",
      recovery: "required",
      hardwareMode: "disabled",
    });
    expect(classifyHardwareStatus({ ...STATUS, enrollmentState: "identity_changed" })).toMatchObject({
      enrollment: "identity_changed",
      recovery: "required",
      hardwareMode: "disabled",
    });
  });

  it("distinguishes unsupported hardware and missing Touch ID", () => {
    expect(classifyHardwareStatus({ ...STATUS, hardwarePresence: false })).toMatchObject({
      hardware: "unsupported",
      hardwareMode: "disabled",
    });
    expect(classifyHardwareStatus({ ...STATUS, touchIdAvailable: false })).toMatchObject({
      hardware: "available",
      touchId: "missing",
      hardwareMode: "disabled",
    });
    expect(classifyHardwareStatus({ ...STATUS, backend: "unsupported" })).toMatchObject({
      hardware: "unsupported",
      hardwareMode: "disabled",
    });
  });

  it("distinguishes Gatekeeper blocking without executing a child", () => {
    let receivedArguments: readonly string[] = [];
    const report = inspectHardwareMode({
      platform: "darwin",
      run: (_binaryPath, arguments_) => {
        receivedArguments = arguments_;
        return {
        status: null,
        stdout: "",
        stderr: "",
        error: Object.assign(new Error("blocked"), { code: "EACCES" }),
        };
      },
    });
    expect(receivedArguments).toEqual(["status"]);
    expect(report.core).toBe("gatekeeper_blocked");
    expect(report.hardwareMode).toBe("disabled");
  });

  it("fails closed on protocol mismatch", () => {
    const report = inspectHardwareMode({
      platform: "darwin",
      run: (_binaryPath, arguments_) => {
        expect(arguments_).toEqual(["status"]);
        return { status: 0, stdout: "protocol_version=99\n", stderr: "" };
      },
    });
    expect(report.core).toBe("protocol_mismatch");
    expect(report.hardwareMode).toBe("disabled");
  });
});
