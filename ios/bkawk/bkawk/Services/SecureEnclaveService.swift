import Foundation
import CryptoKit
import LocalAuthentication

enum SEError: Error, LocalizedError {
    case keyGenerationFailed
    case biometryFailed(Error)
    case keyNotFound
    case signingFailed(Error)
    case ecdhFailed

    var errorDescription: String? {
        switch self {
        case .keyGenerationFailed: return "Failed to generate Secure Enclave key"
        case .biometryFailed(let err): return "Biometry failed: \(err.localizedDescription)"
        case .keyNotFound: return "Secure Enclave key not found"
        case .signingFailed(let err): return "Signing failed: \(err.localizedDescription)"
        case .ecdhFailed: return "ECDH key agreement failed"
        }
    }
}

class SecureEnclaveService {
    static let shared = SecureEnclaveService()

    private let agreementKeyTag = "com.bkawk.device.agreement"
    private let signingKeyTag = "com.bkawk.device.signing"

    // MARK: - Key Generation

    func generateKeys(context: LAContext) throws -> (agreementPubKey: Data, signingPubKey: Data) {
        // Generate P256 KeyAgreement key (for ECDH)
        let agreementPrivKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            accessControl: makeBiometryAccessControl(),
            authenticationContext: context
        )

        // Generate P256 Signing key (for auth challenges)
        let signingPrivKey = try SecureEnclave.P256.Signing.PrivateKey(
            accessControl: makeBiometryAccessControl(),
            authenticationContext: context
        )

        // Store keys in keychain
        try storeKey(agreementPrivKey.dataRepresentation, tag: agreementKeyTag)
        try storeKey(signingPrivKey.dataRepresentation, tag: signingKeyTag)

        // Return uncompressed public keys (65 bytes: 04 || x || y)
        let agreePub = agreementPrivKey.publicKey.x963Representation
        let signPub = signingPrivKey.publicKey.x963Representation

        return (agreePub, signPub)
    }

    // MARK: - ECDH

    func performECDH(peerPublicKeyRaw: Data, context: LAContext) throws -> SharedSecret {
        guard let keyData = loadKey(tag: agreementKeyTag) else {
            throw SEError.keyNotFound
        }

        let privateKey = try SecureEnclave.P256.KeyAgreement.PrivateKey(
            dataRepresentation: keyData,
            authenticationContext: context
        )

        let peerPubKey = try P256.KeyAgreement.PublicKey(x963Representation: peerPublicKeyRaw)

        return try privateKey.sharedSecretFromKeyAgreement(with: peerPubKey)
    }

    // MARK: - Signing

    func signChallenge(_ challengeData: Data, context: LAContext) throws -> Data {
        guard let keyData = loadKey(tag: signingKeyTag) else {
            throw SEError.keyNotFound
        }

        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: keyData,
            authenticationContext: context
        )

        let hash = SHA256.hash(data: challengeData)
        let signature = try privateKey.signature(for: hash)
        return signature.derRepresentation
    }

    // MARK: - Public Key Access

    func getSigningPublicKey(context: LAContext) throws -> Data {
        guard let keyData = loadKey(tag: signingKeyTag) else {
            throw SEError.keyNotFound
        }

        let privateKey = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: keyData,
            authenticationContext: context
        )

        return privateKey.publicKey.x963Representation
    }

    // MARK: - Key Existence

    func hasKeys() -> Bool {
        return loadKey(tag: agreementKeyTag) != nil && loadKey(tag: signingKeyTag) != nil
    }

    func deleteKeys() {
        deleteKey(tag: agreementKeyTag)
        deleteKey(tag: signingKeyTag)
    }

    // MARK: - Keychain Helpers

    private func makeBiometryAccessControl() throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .biometryCurrentSet],
            &error
        ) else {
            throw SEError.keyGenerationFailed
        }
        return access
    }

    private func storeKey(_ data: Data, tag: String) throws {
        // Delete existing
        deleteKey(tag: tag)

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tag,
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw SEError.keyGenerationFailed
        }
    }

    private func loadKey(tag: String) -> Data? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tag,
            kSecReturnData as String: true,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    private func deleteKey(tag: String) {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: tag,
        ]
        SecItemDelete(query as CFDictionary)
    }
}
