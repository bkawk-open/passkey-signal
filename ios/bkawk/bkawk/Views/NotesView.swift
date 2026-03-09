import SwiftUI

struct NotesView: View {
    let phone: String
    let token: String
    let masterKey: Data
    let onDeregister: () -> Void

    @State private var noteText = ""
    @State private var status = ""
    @State private var isError = false
    @State private var isLoading = true
    @State private var isSaving = false

    var body: some View {
        NavigationView {
            VStack(spacing: 16) {
                HStack(spacing: 6) {
                    Image(systemName: "checkmark.seal.fill")
                        .font(.caption)
                        .foregroundColor(.green)
                    Text("Signed in as \(phone)")
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                }
                .padding(.top, 4)

                if isLoading {
                    Spacer()
                    ProgressView("Loading note...")
                    Spacer()
                } else {
                    TextEditor(text: $noteText)
                        .font(.body)
                        .padding(8)
                        .overlay(
                            RoundedRectangle(cornerRadius: 8)
                                .stroke(Color(.systemGray4), lineWidth: 1)
                        )
                        .frame(maxHeight: .infinity)

                    if !status.isEmpty {
                        HStack(spacing: 6) {
                            if isError {
                                Image(systemName: "exclamationmark.triangle.fill")
                                    .font(.caption)
                                    .foregroundColor(.red)
                            }
                            Text(status)
                                .font(.caption)
                                .foregroundColor(isError ? .red : .secondary)
                        }
                        .padding(.horizontal, 12)
                        .padding(.vertical, 6)
                        .background(isError ? Color.red.opacity(0.1) : Color.clear)
                        .cornerRadius(6)
                    }

                    Button(action: { Task { await saveNote() } }) {
                        if isSaving {
                            ProgressView()
                                .frame(maxWidth: .infinity)
                        } else {
                            Text("Save Note")
                                .frame(maxWidth: .infinity)
                        }
                    }
                    .buttonStyle(.borderedProminent)
                    .disabled(isSaving)
                }
            }
            .padding()
            .navigationTitle("Encrypted Notes")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarTrailing) {
                    NavigationLink(destination: SettingsView(onDeregister: onDeregister)) {
                        Image(systemName: "gear")
                    }
                }
            }
        }
        .task {
            await loadNote()
        }
    }

    @MainActor
    private func loadNote() async {
        let crypto = CryptoService.shared
        do {
            let resp = try await APIClient.shared.getNote(token: token)
            if resp.exists, let ct = resp.ciphertext, let iv = resp.iv {
                noteText = try crypto.decryptNote(ciphertextB64: ct, ivB64: iv, masterKey: masterKey)
                if let updatedAt = resp.updatedAt {
                    status = "Last saved: \(updatedAt)"
                    isError = false
                }
            }
            isLoading = false
        } catch {
            isLoading = false
            status = "Failed to load note"
            isError = true
        }
    }

    @MainActor
    private func saveNote() async {
        let crypto = CryptoService.shared
        isSaving = true
        isError = false
        do {
            let encrypted = try crypto.encryptNote(plaintext: noteText, masterKey: masterKey)
            _ = try await APIClient.shared.putNote(
                token: token,
                ciphertext: encrypted.ciphertext,
                iv: encrypted.iv
            )
            status = "Saved \(Date().formatted(date: .abbreviated, time: .shortened))"
            isError = false
        } catch {
            status = "Save failed. Check your connection and try again."
            isError = true
        }
        isSaving = false
    }
}
