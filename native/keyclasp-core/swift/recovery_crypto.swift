import CryptoKit
import Foundation

private let recoveryKeyLength = 32
private let recoveryNonceLength = 12
private let recoveryTagLength = 16

@_cdecl("keyclasp_aes_gcm_seal")
public func keyclaspAESGCMSeal(
    key: UnsafePointer<UInt8>?,
    keyLength: Int,
    nonce: UnsafePointer<UInt8>?,
    nonceLength: Int,
    authenticatedData: UnsafePointer<UInt8>?,
    authenticatedDataLength: Int,
    plaintext: UnsafePointer<UInt8>?,
    plaintextLength: Int,
    ciphertext: UnsafeMutablePointer<UInt8>?,
    ciphertextCapacity: Int,
    tag: UnsafeMutablePointer<UInt8>?,
    tagCapacity: Int
) -> Int32 {
    guard let key, keyLength == recoveryKeyLength,
          let nonce, nonceLength == recoveryNonceLength,
          let authenticatedData, authenticatedDataLength > 0,
          let plaintext, plaintextLength == recoveryKeyLength,
          let ciphertext, ciphertextCapacity == plaintextLength,
          let tag, tagCapacity == recoveryTagLength else {
        return 0
    }

    var keyData = Data(bytes: key, count: keyLength)
    var plaintextData = Data(bytes: plaintext, count: plaintextLength)
    defer {
        keyData.resetBytes(in: 0..<keyData.count)
        plaintextData.resetBytes(in: 0..<plaintextData.count)
    }
    do {
        let sealed = try AES.GCM.seal(
            plaintextData,
            using: SymmetricKey(data: keyData),
            nonce: try AES.GCM.Nonce(data: Data(bytes: nonce, count: nonceLength)),
            authenticating: Data(bytes: authenticatedData, count: authenticatedDataLength)
        )
        guard sealed.ciphertext.count == ciphertextCapacity,
              sealed.tag.count == tagCapacity else {
            return 0
        }
        sealed.ciphertext.copyBytes(to: ciphertext, count: ciphertextCapacity)
        sealed.tag.copyBytes(to: tag, count: tagCapacity)
        return 1
    } catch {
        return 0
    }
}

@_cdecl("keyclasp_aes_gcm_open")
public func keyclaspAESGCMOpen(
    key: UnsafePointer<UInt8>?,
    keyLength: Int,
    nonce: UnsafePointer<UInt8>?,
    nonceLength: Int,
    authenticatedData: UnsafePointer<UInt8>?,
    authenticatedDataLength: Int,
    ciphertext: UnsafePointer<UInt8>?,
    ciphertextLength: Int,
    tag: UnsafePointer<UInt8>?,
    tagLength: Int,
    plaintext: UnsafeMutablePointer<UInt8>?,
    plaintextCapacity: Int
) -> Int32 {
    guard let key, keyLength == recoveryKeyLength,
          let nonce, nonceLength == recoveryNonceLength,
          let authenticatedData, authenticatedDataLength > 0,
          let ciphertext, ciphertextLength == recoveryKeyLength,
          let tag, tagLength == recoveryTagLength,
          let plaintext, plaintextCapacity == ciphertextLength else {
        return 0
    }

    var keyData = Data(bytes: key, count: keyLength)
    defer {
        keyData.resetBytes(in: 0..<keyData.count)
    }
    do {
        let box = try AES.GCM.SealedBox(
            nonce: AES.GCM.Nonce(data: Data(bytes: nonce, count: nonceLength)),
            ciphertext: Data(bytes: ciphertext, count: ciphertextLength),
            tag: Data(bytes: tag, count: tagLength)
        )
        var opened = try AES.GCM.open(
            box,
            using: SymmetricKey(data: keyData),
            authenticating: Data(bytes: authenticatedData, count: authenticatedDataLength)
        )
        defer {
            opened.resetBytes(in: 0..<opened.count)
        }
        guard opened.count == plaintextCapacity else {
            return 0
        }
        opened.copyBytes(to: plaintext, count: plaintextCapacity)
        return 1
    } catch {
        return 0
    }
}
