export const SUPPORTED_SOFTWARE_PLATFORMS = ["darwin", "linux"] as const;
export const SUPPORTED_SOFTWARE_TARGETS = ["darwin-arm64", "linux-arm64", "linux-x64"] as const;

export type SupportedSoftwarePlatform = (typeof SUPPORTED_SOFTWARE_PLATFORMS)[number];

export const WINDOWS_UNSUPPORTED_MESSAGE =
  "Keyclasp software vaults are unsupported on Windows because this beta cannot verify owner-only Windows ACLs or operator authorization. No vault state was created or changed.";
export const MUSL_UNSUPPORTED_MESSAGE =
  "Keyclasp software vaults are unsupported on musl Linux in this beta. No vault state was created or changed.";

function currentLinuxLibc(): "glibc" | "other" {
  const report = process.report.getReport() as { header?: { glibcVersionRuntime?: string } };
  return report.header?.glibcVersionRuntime ? "glibc" : "other";
}

export function assertSoftwarePlatformSupported(
  platform: NodeJS.Platform = process.platform,
  linuxLibc: "glibc" | "other" = platform === "linux" ? currentLinuxLibc() : "glibc",
  architecture: string = process.arch,
): asserts platform is SupportedSoftwarePlatform {
  if (platform === "win32") throw new Error(WINDOWS_UNSUPPORTED_MESSAGE);
  if (!(SUPPORTED_SOFTWARE_PLATFORMS as readonly NodeJS.Platform[]).includes(platform)) {
    throw new Error(`Keyclasp software vaults are unsupported on ${platform}. Supported platforms: macOS and Linux. No vault state was created or changed.`);
  }
  if (platform === "linux" && linuxLibc !== "glibc") throw new Error(MUSL_UNSUPPORTED_MESSAGE);
  const target = `${platform}-${architecture}`;
  if (!(SUPPORTED_SOFTWARE_TARGETS as readonly string[]).includes(target)) {
    throw new Error(`Keyclasp software vaults are unsupported on ${target}. Supported targets: macOS arm64 and glibc Linux arm64 or x64. No vault state was created or changed.`);
  }
}
