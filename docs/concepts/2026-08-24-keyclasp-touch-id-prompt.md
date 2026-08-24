# Keyclasp-owned Touch ID prompt

## User outcome

Touch ID dialogs identify **Keyclasp**, explain the operation, and show the command and selected secret names for a run. The prompt receives names and command metadata only, never secret values or vault keys.

## Previous state

`native/macos-biometric.js` calls LocalAuthentication through `/usr/bin/osascript`. macOS therefore identifies the requesting application as `osascript`, even though Keyclasp supplies the localized reason.

Apple documents two relevant behaviors:

- macOS displays the app name in the authentication-dialog title; the localized reason should describe the action and should not repeat the app name;
- runnable bundles identify themselves through an `Info.plist`, including `CFBundleName`, `CFBundleDisplayName`, and `CFBundleIdentifier`.

## Prototypes

### Keep `osascript`

Keyclasp can improve the reason string, but it cannot make an Apple-owned process identify itself as Keyclasp. Rejected because it cannot satisfy the requested title.

### Standalone native executable

A small executable can own `LAContext`, but a bare command-line process has no reliable app-bundle display identity. Rejected because the title behavior would remain implicit.

### Bundled Keyclasp helper app

A no-Dock UI-agent `Keyclasp.app` owns `LAContext`. Its `Info.plist` names the bundle **Keyclasp**, and its short-lived executable registers an accessory `NSApplication`, activates it, reads one bounded reason from standard input, and returns only a classified status. `LSUIElement` permits LocalAuthentication UI; `LSBackgroundOnly` is forbidden because macOS cancels that request with `LAErrorSystemCancel`. A disposable arm64 Objective-C prototype compiled, passed ad-hoc signature verification, and completed a real LocalAuthentication request.

This is the implemented design. Objective-C keeps the helper independent of the Swift compiler/runtime version mismatch encountered by the disposable Swift prototype. The packaged bundle is arm64-only, ad-hoc signed as `dev.keyclasp.biometric`, and invoked through its inner executable.

## Prompt contract

For a run, the reason contains:

1. the command, including arguments while the bounded display remains readable;
2. the explicit project/environment scope;
3. every selected source secret name, including all names for a broad run;
4. whether output protection is enabled.

Formatting is deterministic and bounded. User-controlled fields are quoted, delimiters are escaped, and invisible formatting characters are rendered visibly. The complete command and secret-name mappings are never silently omitted. If the complete disclosure cannot fit the helper's maximum input, Keyclasp fails closed before requesting Touch ID.

Non-run operations retain their existing precise reason, such as the lock selector, backup, restore, or revealed secret.

## Security boundary

- The helper receives no secret value, passphrase, data key, vault path supplied as a dedicated field, or generic operation request. Disclosed commands and arguments may contain paths.
- Node encodes the operation metadata and passes it over standard input. The native helper alone validates its structure, UTF-8 encoding, and size before LocalAuthentication.
- The helper accepts no arguments, reads exactly one reason from a closed standard-input pipe, rejects malformed or oversized input, disables biometric fallback, permits no authentication reuse, and returns stable exit codes for success, cancellation, unavailable biometry, denial, and invalid input.
- Keyclasp invokes the executable inside the reviewed bundle directly. It does not use `open`, AppleScript, a daemon, or a shell.
- The Touch ID helper supports macOS arm64 only. Linux keeps its passphrase flow; unsupported targets fail before helper launch.

## Delivery consequence

The helper changed the packaged biometric path, making rc4 historical. rc5 exposed the invalid `LSBackgroundOnly` lifecycle during physical verification and is also historical. rc6 uses the reviewed accessory-app lifecycle and passed the full exact-artifact matrix plus physical macOS Touch ID verification. Publication remains a separate protected checkpoint.
