import Foundation
import CryptoKit

enum SignalKeyError: Error, LocalizedError {
    case keyGenerationFailed
    case uploadFailed(String)

    var errorDescription: String? {
        switch self {
        case .keyGenerationFailed: return "Failed to generate Signal keys"
        case .uploadFailed(let msg): return "Signal key upload failed: \(msg)"
        }
    }
}

class SignalKeyService {
    static let shared = SignalKeyService()

    private let crypto = CryptoService.shared

    // MARK: - Generate and Upload Signal Keys

    func ensureSignalKeys(token: String, deviceId: String) async throws {
        let apiClient = APIClient.shared

        // Check if keys already uploaded for this device
        let countResp = try? await apiClient.signalKeyCount(token: token, credentialId: deviceId)
        if let count = countResp, count.hasIdentity {
            if count.count < 5 {
                try await replenishOTPKs(token: token, deviceId: deviceId, startId: count.nextKeyId)
            }
            return
        }

        // Generate identity key pair (Ed25519)
        let identityKey = Curve25519.Signing.PrivateKey()
        let identityPubB64 = crypto.base64urlEncode(Data(identityKey.publicKey.rawRepresentation))

        // Generate signed prekey (X25519)
        let signedPreKey = Curve25519.KeyAgreement.PrivateKey()
        let signedPreKeyPubData = Data(signedPreKey.publicKey.rawRepresentation)
        let signature = try identityKey.signature(for: signedPreKeyPubData)
        let signedPreKeyPub = crypto.base64urlEncode(signedPreKeyPubData)
        let signatureB64 = crypto.base64urlEncode(Data(signature))

        // Store identity private key in Keychain (device-only, not biometry-gated)
        try storeSignalKey(identityKey.rawRepresentation, tag: signalIdentityTag(deviceId))
        try storeSignalKey(signedPreKey.rawRepresentation, tag: signalSignedPreKeyTag(deviceId))

        // Generate 20 one-time prekeys (X25519)
        var otpks: [[String: Any]] = []
        for i in 1...20 {
            let otpk = Curve25519.KeyAgreement.PrivateKey()
            let pubB64 = crypto.base64urlEncode(Data(otpk.publicKey.rawRepresentation))

            // Store each OTPK private key
            try storeSignalKey(otpk.rawRepresentation, tag: signalOTPKTag(deviceId, keyId: i))

            otpks.append([
                "keyId": i,
                "publicKey": pubB64,
                "encryptedPrivateKey": "",
                "iv": "",
                "salt": "",
            ])
        }

        // Upload bundle
        let bundle: [String: Any] = [
            "credentialId": deviceId,
            "identityPublicKey": identityPubB64,
            "signedPreKey": [
                "keyId": 1,
                "publicKey": signedPreKeyPub,
                "signature": signatureB64,
                "encryptedPrivateKey": "",
                "iv": "",
                "salt": "",
            ],
            "oneTimePreKeys": otpks,
        ]

        try await apiClient.signalKeyUpload(token: token, bundle: bundle)
    }

    // MARK: - Replenish OTPKs

    private func replenishOTPKs(token: String, deviceId: String, startId: Int) async throws {
        var otpks: [[String: Any]] = []
        for i in 0..<20 {
            let keyId = startId + i
            let otpk = Curve25519.KeyAgreement.PrivateKey()
            let pubB64 = crypto.base64urlEncode(Data(otpk.publicKey.rawRepresentation))

            try storeSignalKey(otpk.rawRepresentation, tag: signalOTPKTag(deviceId, keyId: keyId))

            otpks.append([
                "keyId": keyId,
                "publicKey": pubB64,
                "encryptedPrivateKey": "",
                "iv": "",
                "salt": "",
            ])
        }

        try await APIClient.shared.signalKeyReplenish(token: token, payload: [
            "credentialId": deviceId,
            "oneTimePreKeys": otpks,
        ])
    }

    // MARK: - Keychain Storage

    private func signalIdentityTag(_ deviceId: String) -> String {
        "com.bkawk.signal.identity.\(deviceId)"
    }

    private func signalSignedPreKeyTag(_ deviceId: String) -> String {
        "com.bkawk.signal.spk.\(deviceId)"
    }

    private func signalOTPKTag(_ deviceId: String, keyId: Int) -> String {
        "com.bkawk.signal.otpk.\(deviceId).\(keyId)"
    }

    private func storeSignalKey(_ data: Data, tag: String) throws {
        let deleteQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tag,
        ]
        SecItemDelete(deleteQuery as CFDictionary)

        let addQuery: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tag,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(addQuery as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SignalKeyError.keyGenerationFailed
        }
    }
}
