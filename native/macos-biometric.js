// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Keyclasp

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
  let evaluationErrorCode = null;
  context.evaluatePolicyLocalizedReasonReply(policy, reason, (success, error) => {
    authenticated = Boolean(success);
    if (error) evaluationErrorCode = Number(error.code);
    finished = true;
  });

  while (!finished) {
    $.NSRunLoop.currentRunLoop.runUntilDate($.NSDate.dateWithTimeIntervalSinceNow(0.1));
  }

  if (!authenticated) {
    if (evaluationErrorCode === -2) {
      throw new Error("KEYCLASP_BIOMETRIC_USER_CANCELLED");
    }
    if (evaluationErrorCode === -6 || evaluationErrorCode === -7 || evaluationErrorCode === -8) {
      throw new Error("KEYCLASP_BIOMETRIC_UNAVAILABLE");
    }
    throw new Error("KEYCLASP_BIOMETRIC_DENIED");
  }
}
