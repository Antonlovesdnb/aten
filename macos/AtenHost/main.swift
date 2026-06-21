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
//   open /Applications/AtenHost.app                     # activate + enable filter
//   open /Applications/AtenHost.app --args --diagnose   # print bundle layout first
//   open /Applications/AtenHost.app --args --diagnose-only # print bundle layout and exit
//   open /Applications/AtenHost.app --args --deactivate # tear down (best effort)

import AppKit
import Darwin
import NetworkExtension
import OSLog
import SystemExtensions

private let log = Logger(subsystem: "ai.aten.host", category: "host")

// Keep this in sync with the system extension's bundle identifier in project.yml.
private let extensionBundleID = "ai.aten.host.netext"

private func printBundleDiagnostics() {
    let bundle = Bundle.main
    let systemExtensionsURL = bundle.bundleURL
        .appendingPathComponent("Contents", isDirectory: true)
        .appendingPathComponent("Library", isDirectory: true)
        .appendingPathComponent("SystemExtensions", isDirectory: true)
    let expectedExtensionURL = systemExtensionsURL
        .appendingPathComponent("AtenNetExt.systemextension", isDirectory: true)

    print("Host bundle: \(bundle.bundlePath)")
    print("System extensions dir: \(systemExtensionsURL.path)")
    print("Expected extension exists: \(FileManager.default.fileExists(atPath: expectedExtensionURL.path))")
    if let entries = try? FileManager.default.contentsOfDirectory(atPath: systemExtensionsURL.path) {
        let embeddedExtensions = entries.sorted().joined(separator: ", ")
        print("Embedded system extensions: \(embeddedExtensions)")
    }
}

final class Controller: NSObject, OSSystemExtensionRequestDelegate {
    private var deactivating = false

    func activate() {
        deactivating = false
        log.info("requesting activation of \(extensionBundleID, privacy: .public)")
        let req = OSSystemExtensionRequest.activationRequest(
            forExtensionWithIdentifier: extensionBundleID,
            queue: .main
        )
        req.delegate = self
        OSSystemExtensionManager.shared.submitRequest(req)
    }

    func deactivate() {
        deactivating = true
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
        if deactivating {
            disableContentFilter()
        } else {
            enableContentFilter()
        }
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
            let cfg = mgr.providerConfiguration ?? NEFilterProviderConfiguration()
            cfg.filterSockets = true
            cfg.filterPackets = false
            mgr.providerConfiguration = cfg
            mgr.localizedDescription = "ATEN"
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

    private func disableContentFilter() {
        let mgr = NEFilterManager.shared()
        mgr.loadFromPreferences { [weak self] loadErr in
            if let loadErr = loadErr {
                print("❌ loadFromPreferences: \(loadErr.localizedDescription)")
                NSApp.terminate(nil)
                return
            }
            mgr.isEnabled = false
            mgr.saveToPreferences { saveErr in
                if let saveErr = saveErr {
                    print("❌ saveToPreferences: \(saveErr.localizedDescription)")
                } else {
                    print("✅ content filter disabled")
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

let arguments = CommandLine.arguments
let diagnoseOnly = arguments.contains("--diagnose-only")

if arguments.contains("--diagnose") || diagnoseOnly {
    printBundleDiagnostics()
}

if diagnoseOnly {
    exit(EXIT_SUCCESS)
}

let controller = Controller()
let app = NSApplication.shared
app.setActivationPolicy(.accessory)

if arguments.contains("--deactivate") {
    controller.deactivate()
} else {
    controller.activate()
}

app.run()
