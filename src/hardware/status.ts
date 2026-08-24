import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import path from "node:path";

export const BROKER_PROTOCOL_VERSION = 1;

const STATUS_FIELDS = [
  "protocol_version",
  "adapter",
  "reported_backend",
  "hardware_presence_available",
  "touch_id_available",
  "code_identity",
  "required_access_policy",
  "current_set_policy_available",
  "lifecycle_operations",
  "enrollment_state",
] as const;

type StatusField = (typeof STATUS_FIELDS)[number];
type EnrollmentState = "unavailable" | "not_enrolled" | "healthy" | "damaged" | "identity_changed";

export interface BrokerStatus {
  protocolVersion: number;
  adapter: "keyclasp_macos_v1";
  backend: "secure_enclave" | "unsupported";
  hardwarePresence: boolean;
  touchIdAvailable: boolean;
  codeIdentity: "development" | "unsigned" | "ad_hoc" | "developer_id" | "unknown";
  requiredAccessPolicy: "biometric_current_set";
  currentSetPolicyAvailable: boolean;
  lifecycleOperations: "disabled";
  enrollmentState: EnrollmentState;
}

export interface HardwareDoctorReport {
  core: "available" | "missing" | "gatekeeper_blocked" | "failed" | "protocol_mismatch";
  hardware: "available" | "unsupported" | "unknown";
  touchId: "available" | "missing" | "unknown";
  enrollment: Exclude<EnrollmentState, "unavailable"> | "unknown";
  recovery: "required" | "not_required" | "unknown";
  hardwareMode: "ready" | "disabled";
  detail: string;
}

interface RunnerResult {
  status: number | null;
  stdout: string;
  stderr: string;
  error?: NodeJS.ErrnoException;
}

export interface HardwareDoctorOptions {
  binaryPath?: string;
  platform?: NodeJS.Platform;
  run?: (binaryPath: string, arguments_: readonly string[]) => RunnerResult;
}

export function defaultBrokerPath(): string {
  const moduleDirectory = path.dirname(fileURLToPath(import.meta.url));
  return path.resolve(moduleDirectory, "../../native/keyclasp-core/dist/keyclasp-core-spike");
}

export function parseBrokerStatus(output: string): BrokerStatus {
  const values = new Map<StatusField, string>();
  const allowed = new Set<string>(STATUS_FIELDS);

  for (const line of output.split("\n")) {
    if (line.length === 0) continue;
    const separator = line.indexOf("=");
    if (separator <= 0) throw new Error("Malformed core status response.");
    const key = line.slice(0, separator);
    const value = line.slice(separator + 1);
    if (!allowed.has(key) || values.has(key as StatusField)) {
      throw new Error("Unexpected or duplicate core status field.");
    }
    values.set(key as StatusField, value);
  }

  for (const field of STATUS_FIELDS) {
    if (!values.has(field)) throw new Error("Incomplete core status response.");
  }

  const exact = <T extends string>(field: StatusField, permitted: readonly T[]): T => {
    const value = values.get(field)!;
    if (!permitted.includes(value as T)) throw new Error(`Invalid core status field: ${field}.`);
    return value as T;
  };
  const bool = (field: StatusField): boolean => exact(field, ["true", "false"] as const) === "true";
  const protocolVersion = Number(exact("protocol_version", [String(BROKER_PROTOCOL_VERSION)]));

  return {
    protocolVersion,
    adapter: exact("adapter", ["keyclasp_macos_v1"] as const),
    backend: exact("reported_backend", ["secure_enclave", "unsupported"] as const),
    hardwarePresence: bool("hardware_presence_available"),
    touchIdAvailable: bool("touch_id_available"),
    codeIdentity: exact("code_identity", ["development", "unsigned", "ad_hoc", "developer_id", "unknown"] as const),
    requiredAccessPolicy: exact("required_access_policy", ["biometric_current_set"] as const),
    currentSetPolicyAvailable: bool("current_set_policy_available"),
    lifecycleOperations: exact("lifecycle_operations", ["disabled"] as const),
    enrollmentState: exact(
      "enrollment_state",
      ["unavailable", "not_enrolled", "healthy", "damaged", "identity_changed"] as const,
    ),
  };
}

export function classifyHardwareStatus(status: BrokerStatus): HardwareDoctorReport {
  const enrollment = status.enrollmentState === "unavailable" ? "unknown" : status.enrollmentState;
  if (status.backend === "unsupported" || !status.hardwarePresence) {
    return {
      core: "available",
      hardware: "unsupported",
      touchId: status.touchIdAvailable ? "available" : "missing",
      enrollment,
      recovery: "unknown",
      hardwareMode: "disabled",
      detail: "Secure Enclave hardware mode is unavailable; passphrase and machine modes remain available.",
    };
  }
  if (!status.touchIdAvailable) {
    return {
      core: "available",
      hardware: "available",
      touchId: "missing",
      enrollment,
      recovery: "unknown",
      hardwareMode: "disabled",
      detail: "Touch ID is unavailable or has no usable biometric enrollment.",
    };
  }
  if (status.enrollmentState === "damaged") {
    return {
      core: "available",
      hardware: "available",
      touchId: "available",
      enrollment: "damaged",
      recovery: "required",
      hardwareMode: "disabled",
      detail: "Hardware enrollment is damaged; recover before creating or invalidating any key.",
    };
  }
  if (status.enrollmentState === "identity_changed") {
    return {
      core: "available",
      hardware: "available",
      touchId: "available",
      enrollment: "identity_changed",
      recovery: "required",
      hardwareMode: "disabled",
      detail: "The core identity changed; recovery and re-enrollment are required.",
    };
  }

  return {
    core: "available",
    hardware: "available",
    touchId: "available",
    enrollment,
    recovery: status.enrollmentState === "healthy" ? "not_required" : "unknown",
    hardwareMode: "disabled",
    detail: "The reviewed core is status-only; hardware enrollment remains disabled until recovery and qualification pass.",
  };
}

export function inspectHardwareMode(options: HardwareDoctorOptions = {}): HardwareDoctorReport {
  if ((options.platform ?? process.platform) !== "darwin") {
    return unavailableReport("missing", "Hardware mode is supported only on macOS.", "unsupported");
  }

  const binaryPath = options.binaryPath ?? defaultBrokerPath();
  const run = options.run ?? runStatus;
  const result = run(binaryPath, ["status"]);
  if (result.error) {
    if (result.error.code === "EACCES" || result.error.code === "EPERM") {
      return unavailableReport(
        "gatekeeper_blocked",
        "macOS blocked the native core. Approve this exact artifact in System Settings > Privacy & Security > Open Anyway.",
      );
    }
    if (result.error.code === "ENOENT") {
      return unavailableReport("missing", "The native macOS core is not installed.");
    }
    return unavailableReport("failed", "The native macOS core could not be inspected.");
  }
  if (result.status !== 0) {
    return unavailableReport("failed", "The native macOS core rejected the status request.");
  }

  try {
    return classifyHardwareStatus(parseBrokerStatus(result.stdout));
  } catch {
    return unavailableReport("protocol_mismatch", "The native core returned an incompatible status protocol.");
  }
}

export function formatHardwareDoctor(report: HardwareDoctorReport): string {
  return [
    `core=${report.core}`,
    `hardware=${report.hardware}`,
    `touch_id=${report.touchId}`,
    `enrollment=${report.enrollment}`,
    `recovery=${report.recovery}`,
    `hardware_mode=${report.hardwareMode}`,
    `detail=${report.detail}`,
  ].join("\n");
}

function runStatus(binaryPath: string, arguments_: readonly string[]): RunnerResult {
  return spawnSync(binaryPath, arguments_, {
    encoding: "utf8",
    env: { PATH: "/usr/bin:/bin" },
    timeout: 5_000,
    maxBuffer: 64 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

function unavailableReport(
  core: HardwareDoctorReport["core"],
  detail: string,
  hardware: HardwareDoctorReport["hardware"] = "unknown",
): HardwareDoctorReport {
  return {
    core,
    hardware,
    touchId: "unknown",
    enrollment: "unknown",
    recovery: "unknown",
    hardwareMode: "disabled",
    detail,
  };
}
