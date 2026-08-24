import CryptoKit
import Foundation
import LocalAuthentication
import Security

private let signingValid: Int32 = 1 << 0
private let signingUnsigned: Int32 = 1 << 1
private let signingAdHoc: Int32 = 1 << 2
private let signingDeveloperID: Int32 = 1 << 3
private let signatureAdHoc: UInt32 = 0x0002

@_silgen_name("keyclasp_dynamic_code_status")
private func keyclaspDynamicCodeStatus(
    _ status: UnsafeMutablePointer<UInt32>
) -> Int32

@_cdecl("keyclasp_hardware_presence")
public func keyclaspHardwarePresence() -> Int32 {
    SecureEnclave.isAvailable ? 1 : 0
}

@_cdecl("keyclasp_touch_id_available")
public func keyclaspTouchIDAvailable() -> Int32 {
    let context = LAContext()
    var error: NSError?
    guard context.canEvaluatePolicy(
        .deviceOwnerAuthenticationWithBiometrics,
        error: &error
    ) else {
        return 0
    }
    return context.biometryType == .touchID ? 1 : 0
}

@_cdecl("keyclasp_current_set_policy_available")
public func keyclaspCurrentSetPolicyAvailable() -> Int32 {
    var error: Unmanaged<CFError>?
    let access = SecAccessControlCreateWithFlags(
        nil,
        kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        [.privateKeyUsage, .biometryCurrentSet],
        &error
    )
    return access == nil ? 0 : 1
}

@_cdecl("keyclasp_code_signing_facts")
public func keyclaspCodeSigningFacts() -> Int32 {
    var runningCode: SecCode?
    let copyStatus = SecCodeCopySelf([], &runningCode)
    guard copyStatus == errSecSuccess, let runningCode else {
        return copyStatus == errSecCSUnsigned ? signingUnsigned : 0
    }

    let strictValidation = SecCSFlags(rawValue: kSecCSStrictValidate)
    let validity = SecCodeCheckValidity(runningCode, strictValidation, nil)
    guard validity == errSecSuccess else {
        return validity == errSecCSUnsigned ? signingUnsigned : 0
    }

    var facts = signingValid
    var flags: UInt32 = 0
    if keyclaspDynamicCodeStatus(&flags) == 0, flags & signatureAdHoc != 0 {
        facts |= signingAdHoc
    }

    var developerIDRequirement: SecRequirement?
    let requirementText =
        "anchor apple generic and certificate leaf[field.1.2.840.113635.100.6.1.13] exists"
        as CFString
    let requirementStatus = SecRequirementCreateWithString(
        requirementText,
        [],
        &developerIDRequirement
    )
    guard requirementStatus == errSecSuccess, let developerIDRequirement else {
        return facts
    }

    if SecCodeCheckValidity(runningCode, strictValidation, developerIDRequirement)
        == errSecSuccess {
        facts |= signingDeveloperID
    }
    return facts
}
