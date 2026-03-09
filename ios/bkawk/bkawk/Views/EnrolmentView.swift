import SwiftUI
import LocalAuthentication
import Security

struct EnrolmentView: View {
    let enrolToken: String
    let onComplete: () -> Void
    let onCancel: () -> Void

    private enum Step: Int, CaseIterable {
        case identity = 1
        case securingDevice
        case connectingAccount
        case receivingKey
        case storingCredentials
        case complete

        var label: String {
            switch self {
            case .identity: return "Verifying identity"
            case .securingDevice: return "Securing device"
            case .connectingAccount: return "Connecting account"
            case .receivingKey: return "Receiving encryption key"
            case .storingCredentials: return "Storing credentials"
            case .complete: return "Complete"
            }
        }

        var icon: String {
            switch self {
            case .identity: return "faceid"
            case .securingDevice: return "key.fill"
            case .connectingAccount: return "link"
            case .receivingKey: return "arrow.down.circle"
            case .storingCredentials: return "lock.shield"
            case .complete: return "checkmark.circle.fill"
            }
        }
    }

    @State private var currentStep: Step = .identity
    @State private var isProcessing = true
    @State private var errorMessage: String?
    @State private var elapsedSeconds = 0
    @State private var isCancelled = false

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                Button("Cancel") {
                    isCancelled = true
                    onCancel()
                }
                .foregroundColor(.blue)
                Spacer()
            }
            .padding(.horizontal)
            .padding(.top, 8)

            Spacer()

            VStack(spacing: 32) {
                ZStack {
                    Circle()
                        .fill(stepIconBackground)
                        .frame(width: 80, height: 80)

                    if currentStep == .complete {
                        Image(systemName: "checkmark.circle.fill")
                            .font(.system(size: 44))
                            .foregroundColor(.green)
                    } else if errorMessage != nil {
                        Image(systemName: "xmark.circle.fill")
                            .font(.system(size: 44))
                            .foregroundColor(.red)
                    } else {
                        Image(systemName: currentStep.icon)
                            .font(.system(size: 32))
                            .foregroundColor(.blue)
                    }
                }

                VStack(spacing: 8) {
                    if let error = errorMessage {
                        Text("Something went wrong")
                            .font(.title3.bold())
                        Text(friendlyError(error))
                            .font(.subheadline)
                            .foregroundColor(.secondary)
                            .multilineTextAlignment(.center)
                            .padding(.horizontal, 32)
                    } else if currentStep == .complete {
                        Text("Device linked")
                            .font(.title3.bold())
                            .foregroundColor(.green)
                    } else {
                        Text(currentStep.label)
                            .font(.title3.bold())

                        if currentStep == .receivingKey {
                            Text("Waiting for web session\u{2026} \(elapsedSeconds)s")
                                .font(.subheadline)
                                .foregroundColor(.secondary)
                                .monospacedDigit()
                        }
                    }
                }

                HStack(spacing: 8) {
                    ForEach(Step.allCases, id: \.rawValue) { step in
                        Circle()
                            .fill(dotColor(for: step))
                            .frame(width: 8, height: 8)
                    }
                }

                if errorMessage != nil {
                    VStack(spacing: 12) {
                        Button("Try Again") {
                            errorMessage = nil
                            isProcessing = true
                            currentStep = .identity
                        }
                        .buttonStyle(.borderedProminent)

                        Button("Cancel") {
                            isCancelled = true
                            onCancel()
                        }
                        .foregroundColor(.secondary)
                    }
                }
            }

            Spacer()
        }
        .task(id: isProcessing) {
            guard isProcessing else { return }
            await performEnrolment()
        }
    }

    private var stepIconBackground: Color {
        if errorMessage != nil { return Color.red.opacity(0.1) }
        if currentStep == .complete { return Color.green.opacity(0.1) }
        return Color.blue.opacity(0.1)
    }

    private func dotColor(for step: Step) -> Color {
        if errorMessage != nil && step.rawValue == currentStep.rawValue {
            return .red
        }
        if step.rawValue < currentStep.rawValue {
            return .green
        }
        if step.rawValue == currentStep.rawValue {
            return .blue
        }
        return Color(.systemGray4)
    }

    private func friendlyError(_ msg: String) -> String {
        let lower = msg.lowercased()
        if lower.contains("network") || lower.contains("offline") || lower.contains("connection") {
            return "Check your internet connection and try again."
        }
        if lower.contains("biometry") || lower.contains("biometric") || lower.contains("faceid") {
            return "Face ID was not recognized. Please try again."
        }
        if lower.contains("token") && (lower.contains("expired") || lower.contains("invalid")) {
            return "This QR code has expired. Scan a new one from your web session."
        }
        if lower.contains("timeout") || lower.contains("timed out") {
            return "The web session didn't respond in time. Please try again."
        }
        return msg
    }

    // MARK: - Enrolment Logic

    @MainActor
    private func performEnrolment() async {
        let se = SecureEnclaveService.shared
        let crypto = CryptoService.shared
        let keychain = KeychainService.shared
        let apiClient = APIClient.shared

        do {
            // Step 1: Face ID
            currentStep = .identity

            let context = LAContext()
            context.localizedReason = "Link this device to your account"

            var authError: NSError?
            guard context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &authError) else {
                throw SEError.biometryFailed(authError ?? NSError(domain: "", code: -1))
            }

            try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Link this device to your account"
            )

            try Task.checkCancellation()

            // Step 2: Key generation
            withAnimation { currentStep = .securingDevice }
            let (agreePubKey, signPubKey) = try se.generateKeys(context: context)

            let agreePubKeyB64 = crypto.base64urlEncode(agreePubKey)
            let signPubKeyB64 = crypto.base64urlEncode(signPubKey)
            let deviceName = UIDevice.current.name

            try Task.checkCancellation()

            // Step 3: Redeem token
            withAnimation { currentStep = .connectingAccount }
            let redeemResp = try await apiClient.redeemEnrolToken(
                enrolToken: enrolToken,
                agreementPubKey: agreePubKeyB64,
                signingPubKey: signPubKeyB64,
                deviceName: deviceName
            )

            let enrolId = redeemResp.enrolId
            let enrolSecret = redeemResp.enrolSecret

            try Task.checkCancellation()

            // Step 4: Poll — use async timer for elapsed seconds (no Foundation Timer)
            withAnimation { currentStep = .receivingKey }
            elapsedSeconds = 0

            var encMasterKey: String?
            var webEphPubKey: String?

            // Run elapsed counter and polling concurrently using a task group
            try await withThrowingTaskGroup(of: Void.self) { group in
                // Elapsed second counter
                group.addTask { @MainActor in
                    while !Task.isCancelled {
                        try await Task.sleep(nanoseconds: 1_000_000_000)
                        elapsedSeconds += 1
                    }
                }

                // Polling loop
                group.addTask { @MainActor in
                    for _ in 0..<90 {
                        try Task.checkCancellation()

                        let receiveResp = try await apiClient.pollEnrolReceive(enrolId: enrolId, enrolSecret: enrolSecret)

                        if receiveResp.status == "delivered" || receiveResp.status == "completed" {
                            encMasterKey = receiveResp.encryptedMasterKey
                            webEphPubKey = receiveResp.webEphemeralPubKey
                            return
                        }

                        try await Task.sleep(nanoseconds: 2_000_000_000)
                    }
                }

                // Wait for polling to finish, then cancel the timer
                // First completed task (polling) cancels the other (timer)
                try await group.next()
                group.cancelAll()
            }

            guard let encryptedMK = encMasterKey, let ephPubKeyB64 = webEphPubKey else {
                throw CryptoError.invalidData
            }

            try Task.checkCancellation()

            // Step 5: ECDH + decrypt + store
            withAnimation { currentStep = .storingCredentials }

            guard let ephPubKeyRaw = crypto.base64urlDecode(ephPubKeyB64) else {
                throw CryptoError.invalidData
            }

            let sharedSecret = try se.performECDH(peerPublicKeyRaw: ephPubKeyRaw, context: context)
            let masterKeyData = try crypto.decryptMasterKey(encryptedB64: encryptedMK, sharedSecret: sharedSecret)

            try keychain.storeMasterKey(masterKeyData)

            var randomBytes = [UInt8](repeating: 0, count: 32)
            _ = SecRandomCopyBytes(kSecRandomDefault, randomBytes.count, &randomBytes)
            let deviceId = randomBytes.map { String(format: "%02x", $0) }.joined()
            try keychain.storeDeviceId(deviceId)

            _ = try await apiClient.completeEnrolment(enrolId: enrolId, deviceId: deviceId, enrolSecret: enrolSecret)

            try Task.checkCancellation()

            // Step 6: Done — don't change isProcessing here as it would cancel this task
            withAnimation { currentStep = .complete }

            try await Task.sleep(nanoseconds: 1_200_000_000)
            onComplete()

        } catch is CancellationError {
            // View disappeared or user cancelled — nothing to do
        } catch {
            isProcessing = false
            errorMessage = error.localizedDescription
        }
    }
}
