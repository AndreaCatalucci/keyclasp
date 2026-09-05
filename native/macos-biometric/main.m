// SPDX-License-Identifier: MIT
// Copyright (c) 2026 Keyclasp

#import <Foundation/Foundation.h>
#import <AppKit/AppKit.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>

static const NSUInteger KeyclaspMaximumReasonBytes = 1024;

typedef NS_ENUM(int, KeyclaspBiometricExitCode) {
  KeyclaspBiometricSuccess = 0,
  KeyclaspBiometricCancelled = 2,
  KeyclaspBiometricUnavailable = 3,
  KeyclaspBiometricDenied = 4,
  KeyclaspBiometricTimedOut = 5,
  KeyclaspBiometricInvalidInput = 64,
};

static BOOL KeyclaspReasonIsValid(NSString *reason) {
  if (reason.length == 0 || [reason dataUsingEncoding:NSUTF8StringEncoding].length > KeyclaspMaximumReasonBytes) {
    return NO;
  }

  for (NSUInteger index = 0; index < reason.length; index += 1) {
    const unichar character = [reason characterAtIndex:index];
    if ([[NSCharacterSet controlCharacterSet] characterIsMember:character] && character != '\n') {
      return NO;
    }
  }
  NSArray<NSString *> *lines = [reason componentsSeparatedByString:@"\n"];
  if (lines.count != 1 && (lines.count != 4 ||
      ![lines[0] hasPrefix:@"Run: "] ||
      ![lines[1] hasPrefix:@"Scope: "] ||
      ![lines[2] hasPrefix:@"Secrets: "] ||
      ![lines[3] hasPrefix:@"Output protection: "])) {
    return NO;
  }
  NSRegularExpression *ambiguousFormatting = [NSRegularExpression
    regularExpressionWithPattern:@"[\\p{Cf}\\p{Zl}\\p{Zp}]"
    options:0
    error:nil];
  return [ambiguousFormatting firstMatchInString:reason
                                         options:0
                                           range:NSMakeRange(0, reason.length)] == nil;
}

static int KeyclaspExitCodeForError(NSError *error) {
  if (error == nil) return KeyclaspBiometricDenied;

  switch (error.code) {
    case LAErrorUserCancel:
      return KeyclaspBiometricCancelled;
    case LAErrorBiometryNotAvailable:
    case LAErrorBiometryNotEnrolled:
    case LAErrorBiometryLockout:
      return KeyclaspBiometricUnavailable;
    default:
      return KeyclaspBiometricDenied;
  }
}

int main(int argc, const char *argv[]) {
  @autoreleasepool {
    (void)argv;
    if (argc != 1) return KeyclaspBiometricInvalidInput;

    NSData *reasonData = [[NSFileHandle fileHandleWithStandardInput] readDataToEndOfFile];
    if (reasonData.length == 0 || reasonData.length > KeyclaspMaximumReasonBytes) {
      return KeyclaspBiometricInvalidInput;
    }
    NSString *reason = [[NSString alloc] initWithData:reasonData encoding:NSUTF8StringEncoding];
    if (reason == nil || !KeyclaspReasonIsValid(reason)) return KeyclaspBiometricInvalidInput;

    [NSApplication sharedApplication];
    [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];
    [NSApp activateIgnoringOtherApps:YES];

    LAContext *context = [[LAContext alloc] init];
    context.localizedFallbackTitle = @"";
    context.localizedCancelTitle = @"Cancel";
    context.touchIDAuthenticationAllowableReuseDuration = 0;

    NSError *availabilityError = nil;
    if (![context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                              error:&availabilityError]) {
      return KeyclaspBiometricUnavailable;
    }

    dispatch_semaphore_t completion = dispatch_semaphore_create(0);
    __block int result = KeyclaspBiometricDenied;
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:reason
                      reply:^(BOOL success, NSError *error) {
      result = success ? KeyclaspBiometricSuccess : KeyclaspExitCodeForError(error);
      dispatch_semaphore_signal(completion);
    }];
    const dispatch_time_t deadline = dispatch_time(DISPATCH_TIME_NOW, 55 * NSEC_PER_SEC);
    if (dispatch_semaphore_wait(completion, deadline) != 0) {
      [context invalidate];
      return KeyclaspBiometricTimedOut;
    }
    return result;
  }
}
