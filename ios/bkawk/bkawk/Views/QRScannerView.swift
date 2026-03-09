import SwiftUI
import AVFoundation
import os

private let logger = Logger(subsystem: "com.bkawk", category: "QRScanner")

struct QRScannerView: View {
    let onScanned: (String) -> Void

    @State private var isShowingScanner = false
    @State private var permissionStatus: String = ""
    @State private var showInvalidQRAlert = false

    var body: some View {
        VStack(spacing: 24) {
            Image(systemName: "qrcode.viewfinder")
                .font(.system(size: 64))
                .foregroundColor(.blue)

            Text("Link to Account")
                .font(.title2.bold())

            Text("Scan the QR code shown on your authenticated web session to link this device.")
                .font(.body)
                .foregroundColor(.secondary)
                .multilineTextAlignment(.center)
                .padding(.horizontal)

            Button(action: {
                logger.info("Scan QR button tapped")
                requestCameraPermission()
            }) {
                Label("Scan QR Code", systemImage: "camera.fill")
                    .frame(maxWidth: .infinity)
                    .padding()
                    .background(Color.blue)
                    .foregroundColor(.white)
                    .cornerRadius(12)
            }
            .padding(.horizontal)
            .fullScreenCover(isPresented: $isShowingScanner) {
                ScannerOverlayView(
                    onCode: { code in
                        logger.info("QR code scanned successfully")
                        isShowingScanner = false
                        if let token = extractToken(from: code) {
                            onScanned(token)
                        } else {
                            logger.warning("QR code did not contain a valid token")
                            showInvalidQRAlert = true
                        }
                    },
                    onCancel: {
                        isShowingScanner = false
                    }
                )
            }

            if !permissionStatus.isEmpty {
                Text(permissionStatus)
                    .font(.caption)
                    .foregroundColor(.red)
                    .padding(.horizontal)
            }

            Spacer()
        }
        .padding(.top, 60)
        .alert("Invalid QR Code", isPresented: $showInvalidQRAlert) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("That QR code doesn't contain a valid link token. Make sure you're scanning the code from your web session.")
        }
        .onAppear {
            let status = AVCaptureDevice.authorizationStatus(for: .video)
            logger.info("Camera permission status on appear: \(String(describing: status.rawValue))")
        }
    }

    private func requestCameraPermission() {
        let status = AVCaptureDevice.authorizationStatus(for: .video)
        logger.info("Camera auth status: \(String(describing: status.rawValue))")

        switch status {
        case .authorized:
            logger.info("Camera authorized, showing scanner")
            isShowingScanner = true
        case .notDetermined:
            logger.info("Camera not determined, requesting access")
            AVCaptureDevice.requestAccess(for: .video) { granted in
                logger.info("Camera access granted: \(granted)")
                Task { @MainActor in
                    if granted {
                        isShowingScanner = true
                    } else {
                        permissionStatus = "Camera access denied. Enable in Settings > Privacy > Camera."
                    }
                }
            }
        case .denied:
            logger.warning("Camera access denied")
            permissionStatus = "Camera access denied. Enable in Settings > Privacy > Camera."
        case .restricted:
            logger.warning("Camera access restricted")
            permissionStatus = "Camera access is restricted on this device."
        @unknown default:
            logger.error("Unknown camera auth status: \(String(describing: status.rawValue))")
            permissionStatus = "Unable to access camera."
        }
    }

    private func extractToken(from url: String) -> String? {
        guard let components = URLComponents(string: url),
              let host = components.host,
              host == "passkey-ios.bkawk.com" || host.hasSuffix(".passkey-ios.bkawk.com"),
              let token = components.queryItems?.first(where: { $0.name == "token" })?.value else {
            return nil
        }
        return token
    }
}

// MARK: - Full-screen scanner with overlay

struct ScannerOverlayView: View {
    let onCode: (String) -> Void
    let onCancel: () -> Void

    private let cutoutSize: CGFloat = 250

    var body: some View {
        ZStack {
            // Camera feed
            CameraScannerView(onCode: onCode)
                .ignoresSafeArea()

            // Semi-transparent overlay with cutout
            GeometryReader { geo in
                let rect = CGRect(
                    x: (geo.size.width - cutoutSize) / 2,
                    y: (geo.size.height - cutoutSize) / 2 - 40,
                    width: cutoutSize,
                    height: cutoutSize
                )

                Canvas { ctx, size in
                    // Fill entire area
                    ctx.fill(
                        Path(CGRect(origin: .zero, size: size)),
                        with: .color(.black.opacity(0.55))
                    )
                    // Cut out the viewfinder
                    ctx.blendMode = .clear
                    ctx.fill(
                        Path(roundedRect: rect, cornerRadius: 16),
                        with: .color(.white)
                    )
                }
                .allowsHitTesting(false)

                // Viewfinder border
                RoundedRectangle(cornerRadius: 16)
                    .stroke(Color.white.opacity(0.8), lineWidth: 2)
                    .frame(width: cutoutSize, height: cutoutSize)
                    .position(x: rect.midX, y: rect.midY)
            }
            .ignoresSafeArea()

            // Instruction text and cancel button
            VStack {
                Spacer()
                    .frame(maxHeight: .infinity)

                // Below viewfinder
                Text("Point camera at QR code")
                    .font(.subheadline)
                    .foregroundColor(.white)
                    .padding(.top, 180)

                Spacer()

                Button(action: onCancel) {
                    Text("Cancel")
                        .font(.headline)
                        .foregroundColor(.white)
                        .frame(maxWidth: .infinity)
                        .padding()
                        .background(.ultraThinMaterial)
                        .cornerRadius(12)
                }
                .padding(.horizontal, 32)
                .padding(.bottom, 40)
            }
        }
    }
}

struct CameraScannerView: UIViewControllerRepresentable {
    let onCode: (String) -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        logger.info("Creating ScannerViewController")
        let vc = ScannerViewController()
        vc.onCode = onCode
        return vc
    }

    func updateUIViewController(_ uvc: ScannerViewController, context: Context) {}
}

class ScannerViewController: UIViewController, AVCaptureMetadataOutputObjectsDelegate {
    var onCode: ((String) -> Void)?
    private var captureSession: AVCaptureSession?
    private var hasScanned = false

    override func viewDidLoad() {
        super.viewDidLoad()
        logger.info("ScannerViewController viewDidLoad")
        view.backgroundColor = .black

        let session = AVCaptureSession()

        guard let device = AVCaptureDevice.default(for: .video) else {
            logger.error("No video capture device available")
            return
        }
        logger.info("Got capture device: \(device.localizedName)")

        guard let input = try? AVCaptureDeviceInput(device: device) else {
            logger.error("Failed to create AVCaptureDeviceInput")
            return
        }

        guard session.canAddInput(input) else {
            logger.error("Cannot add input to session")
            return
        }
        session.addInput(input)
        logger.info("Added camera input to session")

        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else {
            logger.error("Cannot add metadata output to session")
            return
        }
        session.addOutput(output)
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        logger.info("Added QR metadata output to session")

        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.frame = view.bounds
        preview.videoGravity = .resizeAspectFill
        view.layer.addSublayer(preview)

        captureSession = session
        logger.info("Starting capture session")
        let capturedSession = session
        Task.detached {
            capturedSession.startRunning()
        }
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        if let preview = view.layer.sublayers?.first(where: { $0 is AVCaptureVideoPreviewLayer }) {
            preview.frame = view.bounds
        }
    }

    nonisolated func metadataOutput(_ output: AVCaptureMetadataOutput, didOutput metadataObjects: [AVMetadataObject], from connection: AVCaptureConnection) {
        Task { @MainActor in
            guard !hasScanned,
                  let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
                  let code = obj.stringValue else { return }
            logger.info("QR metadata detected")
            hasScanned = true
            captureSession?.stopRunning()
            onCode?(code)
        }
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        logger.info("ScannerViewController viewWillDisappear")
        captureSession?.stopRunning()
        captureSession = nil
        onCode = nil
    }
}
