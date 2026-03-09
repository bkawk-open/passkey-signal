import SwiftUI

struct SettingsView: View {
    let onDeregister: () -> Void

    @State private var showingDeregisterAlert = false
    @State private var isDeregistering = false
    @State private var errorMessage: String?
    @State private var deviceId: String = KeychainService.shared.loadDeviceId() ?? "Unknown"

    var body: some View {
        List {
            Section("Device Info") {
                LabeledContent("Device ID", value: String(deviceId.prefix(8)) + "...")
                LabeledContent("Device Name", value: UIDevice.current.name)
            }

            Section {
                Button(role: .destructive) {
                    showingDeregisterAlert = true
                } label: {
                    if isDeregistering {
                        HStack(spacing: 8) {
                            ProgressView()
                            Text("Removing device\u{2026}")
                        }
                    } else {
                        Label("Deregister Device", systemImage: "trash")
                    }
                }
                .disabled(isDeregistering)
            }

            if let error = errorMessage {
                Section {
                    Text(error)
                        .font(.caption)
                        .foregroundColor(.red)
                }
            }
        }
        .navigationTitle("Settings")
        .alert("Deregister Device?", isPresented: $showingDeregisterAlert) {
            Button("Cancel", role: .cancel) {}
            Button("Deregister", role: .destructive) {
                Task { await deregister() }
            }
        } message: {
            Text("This will remove all credentials from this device. You'll need to scan a new QR code to re-link.")
        }
    }

    @MainActor
    private func deregister() async {
        let keychain = KeychainService.shared
        isDeregistering = true
        errorMessage = nil

        // Try to tell the server to delete the device
        if let deviceId = keychain.loadDeviceId(),
           let token = keychain.loadAuthToken() {
            do {
                _ = try await APIClient.shared.deleteDevice(deviceId: deviceId, token: token)
            } catch {
                // If server delete fails, still clear locally — the device
                // will be orphaned but won't cause problems
            }
        }

        keychain.clearAll()
        isDeregistering = false
        onDeregister()
    }
}
