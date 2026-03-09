import SwiftUI
import LocalAuthentication

enum AppState {
    case loading
    case needsEnrolment
    case enrolling(String)
    case authenticating
    case authSuccess(phone: String, token: String, masterKey: Data)
    case authenticated(phone: String, token: String, masterKey: Data)
    case deviceRemoved
    case error(String)
}

struct ContentView: View {
    @State private var appState: AppState = .loading
    @State private var authStep: String = "Signing in\u{2026}"

    var body: some View {
        Group {
            switch appState {
            case .loading:
                ProgressView("Loading\u{2026}")

            case .needsEnrolment:
                QRScannerView { token in
                    appState = .enrolling(token)
                }

            case .enrolling(let token):
                EnrolmentView(
                    enrolToken: token,
                    onComplete: {
                        Task {
                            try? await Task.sleep(nanoseconds: 2_000_000_000)
                            await authenticate()
                        }
                    },
                    onCancel: {
                        appState = .needsEnrolment
                    }
                )

            case .authenticating:
                VStack(spacing: 16) {
                    ProgressView()
                        .scaleEffect(1.5)
                    Text(authStep)
                        .font(.headline)
                        .foregroundColor(.primary)
                        .animation(.easeInOut(duration: 0.2), value: authStep)
                }

            case .authSuccess(let phone, let token, let masterKey):
                VStack(spacing: 16) {
                    Image(systemName: "checkmark.circle.fill")
                        .font(.system(size: 56))
                        .foregroundColor(.green)
                    Text("Signed in")
                        .font(.title3.bold())
                }
                .transition(.opacity)
                .onAppear {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 0.8) {
                        withAnimation {
                            appState = .authenticated(phone: phone, token: token, masterKey: masterKey)
                        }
                    }
                }

            case .authenticated(let phone, let token, let masterKey):
                NotesView(
                    phone: phone,
                    token: token,
                    masterKey: masterKey,
                    onDeregister: {
                        withAnimation { appState = .needsEnrolment }
                    }
                )
                .transition(.opacity)

            case .deviceRemoved:
                VStack(spacing: 20) {
                    Image(systemName: "link.badge.plus")
                        .font(.system(size: 48))
                        .foregroundColor(.orange)
                    Text("Device was removed")
                        .font(.title3.bold())
                    Text("This device is no longer linked to an account. Scan a new QR code to re-link.")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                }
                .onAppear {
                    DispatchQueue.main.asyncAfter(deadline: .now() + 2.5) {
                        withAnimation { appState = .needsEnrolment }
                    }
                }

            case .error(let message):
                VStack(spacing: 16) {
                    Image(systemName: "exclamationmark.triangle.fill")
                        .font(.system(size: 48))
                        .foregroundColor(.orange)
                    Text("Something went wrong")
                        .font(.title3.bold())
                    Text(message)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                        .padding(.horizontal, 32)
                    Button("Try Again") {
                        Task { await checkDeviceState() }
                    }
                    .buttonStyle(.borderedProminent)
                }
                .padding()
            }
        }
        .task {
            await checkDeviceState()
        }
    }

    @MainActor
    private func checkDeviceState() async {
        appState = .loading

        let keychain = KeychainService.shared

        guard let _ = keychain.loadDeviceId() else {
            appState = .needsEnrolment
            return
        }

        await authenticate()
    }

    @MainActor
    private func authenticate() async {
        appState = .authenticating
        authStep = "Verifying identity\u{2026}"

        let keychain = KeychainService.shared
        let se = SecureEnclaveService.shared
        let apiClient = APIClient.shared

        guard let deviceId = keychain.loadDeviceId() else {
            appState = .needsEnrolment
            return
        }

        do {
            let context = LAContext()
            context.localizedReason = "Sign in with Face ID"

            try await context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: "Sign in to your account"
            )

            guard let masterKey = keychain.loadMasterKey(context: context) else {
                appState = .error("Credentials not found. Please re-link this device.")
                return
            }

            authStep = "Connecting to server\u{2026}"

            let authResp = try await apiClient.deviceAuth(deviceId: deviceId)

            authStep = "Verifying device\u{2026}"

            let crypto = CryptoService.shared
            guard let challengeData = crypto.base64urlDecode(authResp.challenge) else {
                appState = .error("Received invalid data from server.")
                return
            }

            let signature = try se.signChallenge(challengeData, context: context)
            let signatureB64 = crypto.base64urlEncode(signature)

            let verifyResp = try await apiClient.deviceVerify(
                challengeId: authResp.challengeId,
                deviceId: deviceId,
                signature: signatureB64
            )

            try keychain.storeAuthToken(verifyResp.token)

            // Brief success state before showing notes
            withAnimation {
                appState = .authSuccess(
                    phone: verifyResp.phone,
                    token: verifyResp.token,
                    masterKey: masterKey
                )
            }

        } catch {
            let nsError = error as NSError
            if nsError.code == LAError.userCancel.rawValue ||
               nsError.code == LAError.appCancel.rawValue {
                appState = .error("Sign-in was cancelled.")
            } else if case APIError.httpError(let code, _) = error,
                      (code == 404 || code == 400) {
                // Device not recognized — show explanation then re-enrol
                keychain.clearAll()
                appState = .deviceRemoved
            } else if case APIError.networkError(_) = error {
                appState = .error("No internet connection. Check your network and try again.")
            } else {
                appState = .error(friendlyAuthError(error))
            }
        }
    }

    private func friendlyAuthError(_ error: Error) -> String {
        let msg = error.localizedDescription.lowercased()
        if msg.contains("network") || msg.contains("offline") || msg.contains("internet") {
            return "No internet connection. Check your network and try again."
        }
        if msg.contains("server") || msg.contains("500") {
            return "Server is temporarily unavailable. Please try again shortly."
        }
        if msg.contains("timeout") || msg.contains("timed out") {
            return "Connection timed out. Please try again."
        }
        return "An unexpected error occurred. Please try again."
    }
}

#Preview {
    ContentView()
}
