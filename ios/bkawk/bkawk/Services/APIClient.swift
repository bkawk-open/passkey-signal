import Foundation

enum APIError: Error, LocalizedError {
    case httpError(Int, String)
    case networkError(Error)
    case decodingError

    var errorDescription: String? {
        switch self {
        case .httpError(_, let msg): return msg
        case .networkError(let err): return err.localizedDescription
        case .decodingError: return "Failed to decode response"
        }
    }
}

// MARK: - Device Enrolment Types

struct RedeemRequest: Encodable, Sendable {
    let enrolToken: String
    let agreementPubKey: String
    let signingPubKey: String
    let deviceName: String
}

struct RedeemResponse: Decodable, Sendable {
    let enrolId: String
    let enrolSecret: String
    let phone: String
}

struct ReceiveResponse: Decodable, Sendable {
    let status: String
    let encryptedMasterKey: String?
    let webEphemeralPubKey: String?
}

struct CompleteRequest: Encodable, Sendable {
    let enrolId: String
    let deviceId: String
    let enrolSecret: String
}

struct CompleteResponse: Decodable, Sendable {
    let status: String
}

// MARK: - Device Auth Types

struct DeviceAuthRequest: Encodable, Sendable {
    let deviceId: String
}

struct DeviceAuthResponse: Decodable, Sendable {
    let challenge: String
    let challengeId: String
}

struct DeviceVerifyRequest: Encodable, Sendable {
    let challengeId: String
    let deviceId: String
    let signature: String
}

struct DeviceVerifyResponse: Decodable, Sendable {
    let token: String
    let phone: String
}

// MARK: - Device Management Types

struct DeleteDeviceRequest: Encodable, Sendable {
    let deviceId: String
}

struct DeleteDeviceResponse: Decodable, Sendable {
    let status: String
}

// MARK: - Notes Types

struct NoteResponse: Decodable, Sendable {
    let exists: Bool
    let ciphertext: String?
    let iv: String?
    let updatedAt: String?
}

struct PutNoteRequest: Encodable, Sendable {
    let ciphertext: String
    let iv: String
}

struct PutNoteResponse: Decodable, Sendable {
    let status: String
}

struct ErrorResponse: Decodable, Sendable {
    let error: String
}

// MARK: - Signal Key Types

struct SignalKeyCountResponse: Decodable, Sendable {
    let count: Int
    let nextKeyId: Int
    let hasIdentity: Bool
}

struct SignalKeyUploadResponse: Decodable, Sendable {
    let status: String
}

struct SignalKeyReplenishResponse: Decodable, Sendable {
    let status: String
}

// MARK: - API Client

final class APIClient {
    static let shared = APIClient()
    private let baseURL = "https://api.passkey-signal.bkawk.com"

    private let session: URLSession = {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 15
        config.timeoutIntervalForResource = 30
        return URLSession(configuration: config)
    }()

    private func request<T: Decodable>(
        method: String,
        path: String,
        body: (any Encodable)? = nil,
        token: String? = nil
    ) async throws -> T {
        guard let url = URL(string: baseURL + path) else {
            throw APIError.httpError(0, "Invalid URL")
        }

        var req = URLRequest(url: url)
        req.httpMethod = method
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        if let token = token {
            req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        }

        if let body = body {
            req.httpBody = try JSONEncoder().encode(body)
        }

        let (data, response) = try await session.data(for: req)

        guard let httpResp = response as? HTTPURLResponse else {
            throw APIError.networkError(URLError(.badServerResponse))
        }

        if httpResp.statusCode >= 400 {
            if let errResp = try? JSONDecoder().decode(ErrorResponse.self, from: data) {
                throw APIError.httpError(httpResp.statusCode, errResp.error)
            }
            throw APIError.httpError(httpResp.statusCode, "HTTP \(httpResp.statusCode)")
        }

        do {
            return try JSONDecoder().decode(T.self, from: data)
        } catch {
            throw APIError.decodingError
        }
    }

    // MARK: - Device Enrolment

    func redeemEnrolToken(
        enrolToken: String,
        agreementPubKey: String,
        signingPubKey: String,
        deviceName: String
    ) async throws -> RedeemResponse {
        try await request(
            method: "POST",
            path: "/device/enrol/redeem",
            body: RedeemRequest(
                enrolToken: enrolToken,
                agreementPubKey: agreementPubKey,
                signingPubKey: signingPubKey,
                deviceName: deviceName
            )
        )
    }

    func pollEnrolReceive(enrolId: String, enrolSecret: String) async throws -> ReceiveResponse {
        var components = URLComponents(string: baseURL + "/device/enrol/receive")!
        components.queryItems = [
            URLQueryItem(name: "enrolId", value: enrolId),
            URLQueryItem(name: "enrolSecret", value: enrolSecret),
        ]
        guard let url = components.url else {
            throw APIError.httpError(0, "Invalid URL")
        }

        var req = URLRequest(url: url)
        req.httpMethod = "GET"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")

        let (data, response) = try await session.data(for: req)
        guard let httpResp = response as? HTTPURLResponse else {
            throw APIError.networkError(URLError(.badServerResponse))
        }
        if httpResp.statusCode >= 400 {
            if let errResp = try? JSONDecoder().decode(ErrorResponse.self, from: data) {
                throw APIError.httpError(httpResp.statusCode, errResp.error)
            }
            throw APIError.httpError(httpResp.statusCode, "HTTP \(httpResp.statusCode)")
        }
        return try JSONDecoder().decode(ReceiveResponse.self, from: data)
    }

    func completeEnrolment(enrolId: String, deviceId: String, enrolSecret: String) async throws -> CompleteResponse {
        try await request(
            method: "POST",
            path: "/device/enrol/complete",
            body: CompleteRequest(enrolId: enrolId, deviceId: deviceId, enrolSecret: enrolSecret)
        )
    }

    // MARK: - Device Auth

    func deviceAuth(deviceId: String) async throws -> DeviceAuthResponse {
        try await request(
            method: "POST",
            path: "/device/auth",
            body: DeviceAuthRequest(deviceId: deviceId)
        )
    }

    func deviceVerify(challengeId: String, deviceId: String, signature: String) async throws -> DeviceVerifyResponse {
        try await request(
            method: "POST",
            path: "/device/verify",
            body: DeviceVerifyRequest(challengeId: challengeId, deviceId: deviceId, signature: signature)
        )
    }

    // MARK: - Device Management

    func deleteDevice(deviceId: String, token: String) async throws -> DeleteDeviceResponse {
        try await request(
            method: "DELETE",
            path: "/device",
            body: DeleteDeviceRequest(deviceId: deviceId),
            token: token
        )
    }

    // MARK: - Notes

    func getNote(token: String) async throws -> NoteResponse {
        try await request(method: "GET", path: "/note", token: token)
    }

    func putNote(token: String, ciphertext: String, iv: String) async throws -> PutNoteResponse {
        try await request(
            method: "PUT",
            path: "/note",
            body: PutNoteRequest(ciphertext: ciphertext, iv: iv),
            token: token
        )
    }

    // MARK: - Signal Keys

    func signalKeyCount(token: String, credentialId: String) async throws -> SignalKeyCountResponse {
        try await request(
            method: "GET",
            path: "/v1/signal/keys/count?credentialId=\(credentialId)",
            token: token
        )
    }

    func signalKeyUpload(token: String, bundle: [String: Any]) async throws {
        guard let url = URL(string: baseURL + "/v1/signal/keys/upload") else {
            throw APIError.httpError(0, "Invalid URL")
        }

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.httpBody = try JSONSerialization.data(withJSONObject: bundle)

        let (data, response) = try await session.data(for: req)
        guard let httpResp = response as? HTTPURLResponse else {
            throw APIError.networkError(URLError(.badServerResponse))
        }
        if httpResp.statusCode >= 400 {
            if let errResp = try? JSONDecoder().decode(ErrorResponse.self, from: data) {
                throw APIError.httpError(httpResp.statusCode, errResp.error)
            }
            throw APIError.httpError(httpResp.statusCode, "HTTP \(httpResp.statusCode)")
        }
    }

    func signalKeyReplenish(token: String, payload: [String: Any]) async throws {
        guard let url = URL(string: baseURL + "/v1/signal/keys/replenish") else {
            throw APIError.httpError(0, "Invalid URL")
        }

        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("Bearer \(token)", forHTTPHeaderField: "Authorization")
        req.httpBody = try JSONSerialization.data(withJSONObject: payload)

        let (data, response) = try await session.data(for: req)
        guard let httpResp = response as? HTTPURLResponse else {
            throw APIError.networkError(URLError(.badServerResponse))
        }
        if httpResp.statusCode >= 400 {
            if let errResp = try? JSONDecoder().decode(ErrorResponse.self, from: data) {
                throw APIError.httpError(httpResp.statusCode, errResp.error)
            }
            throw APIError.httpError(httpResp.statusCode, "HTTP \(httpResp.statusCode)")
        }
    }
}
