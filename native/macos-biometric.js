// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Keyblind

ObjC.import("Foundation");
ObjC.import("LocalAuthentication");

function run(arguments) {
  const reason = arguments[0] || "Authorize sensitive Keyclasp access";
  const policy = $.LAPolicyDeviceOwnerAuthenticationWithBiometrics;
  const context = $.LAContext.alloc.init;
  context.localizedFallbackTitle = "";
  context.localizedCancelTitle = "Cancel";
  context.touchIDAuthenticationAllowableReuseDuration = 0;

  const availabilityError = Ref();
  if (!context.canEvaluatePolicyError(policy, availabilityError)) {
    throw new Error("Touch ID is unavailable or not enrolled.");
  }

  let finished = false;
  let authenticated = false;
  context.evaluatePolicyLocalizedReasonReply(policy, reason, (success) => {
    authenticated = Boolean(success);
    finished = true;
  });

  while (!finished) {
    $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.1));
  }

  if (!authenticated) {
    throw new Error("Biometric authentication failed or was cancelled.");
  }
}
