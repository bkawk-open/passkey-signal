import Foundation
import CryptoKit

enum CryptoError: Error, LocalizedError {
    case invalidData
    case decryptionFailed
    case encryptionFailed

    var errorDescription: String? {
        switch self {
        case .invalidData: return "Invalid cryptographic data"
        case .decryptionFailed: return "Decryption failed"
        case .encryptionFailed: return "Encryption failed"
        }
    }
}

class CryptoService {
    static let shared = CryptoService()

    // Must match web exactly
    private let hkdfSalt = "passkey-ios-device-enrol-v1"
    private let hkdfInfo = "aes-gcm-256"

    // MARK: - ECDH + HKDF → AES-GCM Key

    func deriveAESKey(sharedSecret: SharedSecret) -> SymmetricKey {
        let salt = Data(hkdfSalt.utf8)
        let info = Data(hkdfInfo.utf8)

        return sharedSecret.hkdfDerivedSymmetricKey(
            using: SHA256.self,
            salt: salt,
            sharedInfo: info,
            outputByteCount: 32
        )
    }

    // MARK: - Decrypt Master Key (from ECDH exchange)

    func decryptMasterKey(encryptedB64: String, sharedSecret: SharedSecret) throws -> Data {
        guard let combined = base64urlDecode(encryptedB64) else {
            throw CryptoError.invalidData
        }
        guard combined.count > 12 else {
            throw CryptoError.invalidData
        }

        let iv = combined.prefix(12)
        let ciphertext = combined.dropFirst(12)

        let aesKey = deriveAESKey(sharedSecret: sharedSecret)
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealedBox = try AES.GCM.SealedBox(combined: nonce + ciphertext)
        let decrypted = try AES.GCM.open(sealedBox, using: aesKey)

        return decrypted
    }

    // MARK: - Encrypt/Decrypt Notes (AES-GCM with master key)

    func encryptNote(plaintext: String, masterKey: Data) throws -> (ciphertext: String, iv: String) {
        let key = SymmetricKey(data: masterKey)
        let iv = AES.GCM.Nonce()
        let plainData = Data(plaintext.utf8)

        let sealedBox = try AES.GCM.seal(plainData, using: key, nonce: iv)

        // sealedBox.ciphertext + tag
        var combined = sealedBox.ciphertext
        combined.append(sealedBox.tag)

        return (
            ciphertext: base64urlEncode(combined),
            iv: base64urlEncode(Data(iv))
        )
    }

    func decryptNote(ciphertextB64: String, ivB64: String, masterKey: Data) throws -> String {
        guard let ciphertext = base64urlDecode(ciphertextB64),
              let iv = base64urlDecode(ivB64) else {
            throw CryptoError.invalidData
        }

        let key = SymmetricKey(data: masterKey)
        let nonce = try AES.GCM.Nonce(data: iv)
        let sealedBox = try AES.GCM.SealedBox(combined: nonce + ciphertext)
        let decrypted = try AES.GCM.open(sealedBox, using: key)

        guard let text = String(data: decrypted, encoding: .utf8) else {
            throw CryptoError.decryptionFailed
        }
        return text
    }

    // MARK: - Base64url

    func base64urlEncode(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    func base64urlDecode(_ string: String) -> Data? {
        var s = string
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        while s.count % 4 != 0 { s += "=" }
        return Data(base64Encoded: s)
    }
}
