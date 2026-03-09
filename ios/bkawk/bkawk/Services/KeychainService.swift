import Foundation
import Security
import LocalAuthentication

class KeychainService {
    static let shared = KeychainService()

    private let masterKeyService = "com.bkawk.masterKey"
    private let deviceIdService = "com.bkawk.deviceId"
    private let authTokenService = "com.bkawk.authToken"
    private let phoneService = "com.bkawk.phone"

    // MARK: - Master Key (Face ID protected)

    func storeMasterKey(_ key: Data) throws {
        try deleteItem(service: masterKeyService)

        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .biometryCurrentSet,
            &error
        ) else {
            throw KeychainError.accessControlFailed
        }

        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: masterKeyService,
            kSecValueData as String: key,
            kSecAttrAccessControl as String: access,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.storeFailed(status)
        }
    }

    func loadMasterKey(context: LAContext? = nil) -> Data? {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: masterKeyService,
            kSecReturnData as String: true,
        ]

        if let context = context {
            query[kSecUseAuthenticationContext as String] = context
        }

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess else { return nil }
        return result as? Data
    }

    // MARK: - Device ID

    func storeDeviceId(_ deviceId: String) throws {
        try storeString(deviceId, service: deviceIdService)
    }

    func loadDeviceId() -> String? {
        return loadString(service: deviceIdService)
    }

    // MARK: - Auth Token

    func storeAuthToken(_ token: String) throws {
        try storeString(token, service: authTokenService)
    }

    func loadAuthToken() -> String? {
        return loadString(service: authTokenService)
    }

    func deleteAuthToken() {
        try? deleteItem(service: authTokenService)
    }

    // MARK: - Phone

    func storePhone(_ phone: String) throws {
        try storeString(phone, service: phoneService)
    }

    func loadPhone() -> String? {
        return loadString(service: phoneService)
    }

    // MARK: - Clear All

    func clearAll() {
        try? deleteItem(service: masterKeyService)
        try? deleteItem(service: deviceIdService)
        try? deleteItem(service: authTokenService)
        try? deleteItem(service: phoneService)
        SecureEnclaveService.shared.deleteKeys()
    }

    // MARK: - Helpers

    private func storeString(_ value: String, service: String) throws {
        try deleteItem(service: service)
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecValueData as String: Data(value.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
        ]
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.storeFailed(status)
        }
    }

    private func loadString(service: String) -> String? {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecReturnData as String: true,
        ]
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        guard status == errSecSuccess, let data = result as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    private func deleteItem(service: String) throws {
        let query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }
}

enum KeychainError: Error, LocalizedError {
    case accessControlFailed
    case storeFailed(OSStatus)
    case deleteFailed(OSStatus)

    var errorDescription: String? {
        switch self {
        case .accessControlFailed: return "Failed to create access control"
        case .storeFailed(let s): return "Keychain store failed: \(s)"
        case .deleteFailed(let s): return "Keychain delete failed: \(s)"
        }
    }
}
