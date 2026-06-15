// AtenHost — minimal host application whose only jobs are to (1) activate
// the bundled NEFilterDataProvider system extension and (2) install the
// content-filter configuration so macOS starts routing flows to it.
//
// System extensions can only be activated from an app bundle via
// OSSystemExtensionRequest, and a content filter is only live once an
// NEFilterManager configuration is saved and enabled. This app does both, prints
// progress, and stays alive (the run loop) so the activation/approval callbacks
// can complete. Re-running it is idempotent.
//
// Usage:
//   open macos/build/AtenHost.app          # activate + enable filter
//   AtenHost --deactivate                   # tear down (best effort)

import AppKit
import NetworkExtension
import OSLog
import SystemExtensions

private let log = Logger(subsystem: "ai.aten.host", category: "host")

// Keep this in sync with the system extension's bundle identifier in project.yml.
private let extensionBundleID = "ai.aten.netext"

final class Controller: NSObject, OSSystemExtensionRequestDelegate {
    func activate() {
        log.info("requesting activation of \(extensionBundleID, privacy: .public)")
        let req = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionBundleID,
            queue: .main
        )
        req.delegate = self
        OSSystemExtensionManager.shared.submitRequest(req)
    }

    func deactivate() {
        let req = OSSystemExtensionRequest.deactivationRequest(
            forExtensionWithIdentifier: extensionBundleID,
            queue: .main
        )
        req.delegate = self
        OSSystemExtensionManager.shared.submitRequest(req)
    }

    // MARK: OSSystemExtensionRequestDelegate

    func request(
        _ request: OSSystemExtensionRequest,
        actionForReplacingExtension existing: OSSystemExtensionProperties,
        withExtension ext: OSSystemExtensionProperties
    ) -> OSSystemExtensionRequest.ReplacementAction {
        // Always take the freshly-built one (dev iteration).
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        print("⚠️  Approve the extension in System Settings ▸ General ▸ Login Items & Extensions.")
    }

    func request(_ request: OSSystemExtensionRequest, didFinishWithResult result: OSSystemExtensionRequest.Result) {
        print("✅ system extension request finished: \(result.rawValue)")
        enableContentFilter()
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        print("❌ system extension request failed: \(error.localizedDescription)")
        NSApp.terminate(nil)
    }

    /// Install + enable the content-filter configuration. Until this is saved
    /// and `isEnabled == true`, macOS does not route any flows to the provider.
    private func enableContentFilter() {
        let mgr = NEFilterManager.shared()
        mgr.loadFromPreferences { [weak self] loadErr in
            if let loadErr = loadErr {
                print("❌ loadFromPreferences: \(loadErr.localizedDescription)")
                NSApp.terminate(nil)
                return
            }
            if mgr.providerConfiguration == nil {
                let cfg = NEFilterProviderConfiguration()
                cfg.filterSockets = true
                cfg.filterPackets = false
                mgr.providerConfiguration = cfg
                mgr.localizedDescription = "ATEN"
            }
            mgr.isEnabled = true
            mgr.saveToPreferences { saveErr in
                if let saveErr = saveErr {
                    print("❌ saveToPreferences: \(saveErr.localizedDescription)")
                } else {
                    print("✅ content filter enabled — flows now routed to the extension")
                }
                self?.printStatus()
            }
        }
    }

    private func printStatus() {
        print("Filter enabled: \(NEFilterManager.shared().isEnabled)")
        print("Done. You can quit this app; the extension keeps running.")
    }
}

let controller = Controller()
let app = NSApplication.shared
app.setActivationPolicy(.accessory)

if CommandLine.arguments.contains("--deactivate") {
    controller.deactivate()
} else {
    controller.activate()
}

app.run()
