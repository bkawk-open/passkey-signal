//
//  bkawkApp.swift
//  bkawk
//
//  Created by William Hill on 06/03/2026.
//

import SwiftUI

@main
struct bkawkApp: App {
    @Environment(\.scenePhase) private var scenePhase
    @State private var showPrivacyScreen = false

    var body: some Scene {
        WindowGroup {
            ZStack {
                ContentView()

                if showPrivacyScreen {
                    Color(.systemBackground)
                        .ignoresSafeArea()
                        .overlay(
                            Image(systemName: "lock.shield.fill")
                                .font(.system(size: 48))
                                .foregroundColor(.secondary)
                        )
                }
            }
            .onChange(of: scenePhase) { _, phase in
                showPrivacyScreen = (phase != .active)
            }
        }
    }
}
