// NEFilterDataProvider system extension — fishbowl-v2's macOS network-egress
// source.
//
// macOS EndpointSecurity has no TCP/IP connect event, so this content filter is
// how we observe outbound flows with a source PID. We are a *telemetry* filter,
// not an enforcement one: every flow is `.allow()`ed unconditionally. For each
// new socket flow we extract {pid, remote_ip, port, protocol} and ship it over
// a Unix-domain socket to the fishbowl collector, which owns the enrollment
// table and decides whether the flow is interesting (see
// crates/fishbowl-collector-macos/src/netflow_ipc.rs).
//
// Runs as a separate root process (the system extension), sandboxed. The only
// outbound IPC is the local UDS write.

import Foundation
import NetworkExtension
import OSLog

private let log = Logger(subsystem: "ai.fishbowl.netext", category: "filter")

/// Must match `FlowRecord` in netflow_ipc.rs and the socket path the collector
/// binds. Length-prefixed (u32 LE) JSON frames.
private let socketPath = "/var/run/fishbowl/netflow.sock"
private let wireVersion: UInt8 = 1

struct FlowRecord: Codable {
    let v: UInt8
    let pid: UInt32
    let remote_ip: String
    let port: UInt16
    let `protocol`: String
    let timestamp: String
}

final class FilterDataProvider: NEFilterDataProvider {
    private let writer = FlowWriter(path: socketPath)
    private let iso = ISO8601DateFormatter()

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        log.info("fishbowl filter started")
        completionHandler(nil)
    }

    override func stopFilter(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        log.info("fishbowl filter stopping: \(String(describing: reason), privacy: .public)")
        writer.close()
        completionHandler()
    }

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        if let socketFlow = flow as? NEFilterSocketFlow {
            report(socketFlow)
        }
        // Pure telemetry: never block. `.allow()` lets the flow proceed and
        // tells the system we don't need to see the rest of this flow's data.
        return .allow()
    }

    private func report(_ flow: NEFilterSocketFlow) {
        // remoteEndpoint is an NWHostEndpoint carrying host + port as strings.
        guard let remote = flow.remoteEndpoint as? NWHostEndpoint else { return }
        let host = remote.hostname
        let port = UInt16(remote.port) ?? 0
        // socketProtocol is an IPPROTO_* value.
        let proto = (flow.socketProtocol == IPPROTO_UDP) ? "udp" : "tcp"
        let pid = pidFromAuditToken(flow.sourceAppAuditToken)

        let rec = FlowRecord(
            v: wireVersion,
            pid: pid,
            remote_ip: host,
            port: port,
            protocol: proto,
            timestamp: iso.string(from: Date())
        )
        writer.send(rec)
    }

    /// Derive the source PID from the flow's audit token. `sourceAppAuditToken`
    /// is a `Data` wrapping an `audit_token_t`; `audit_token_to_pid` extracts
    /// the pid.
    private func pidFromAuditToken(_ tokenData: Data?) -> UInt32 {
        guard let data = tokenData, data.count == MemoryLayout<audit_token_t>.size else {
            return 0
        }
        var token = audit_token_t()
        _ = withUnsafeMutableBytes(of: &token) { dst in
            data.copyBytes(to: dst)
        }
        return UInt32(bitPattern: audit_token_to_pid(token))
    }
}

/// Minimal length-prefixed-JSON writer over a client Unix-domain socket. The
/// collector is the server (it binds and listens); we connect and hold the
/// connection, reconnecting lazily if the collector isn't up yet or the socket
/// drops.
final class FlowWriter {
    private let path: String
    private var fd: Int32 = -1
    private let queue = DispatchQueue(label: "ai.fishbowl.netext.writer")
    private let encoder = JSONEncoder()

    init(path: String) {
        self.path = path
    }

    func send(_ rec: FlowRecord) {
        queue.async { [weak self] in
            guard let self = self else { return }
            if self.fd < 0 {
                self.connect()
            }
            guard self.fd >= 0 else { return }
            guard let json = try? self.encoder.encode(rec) else { return }
            var len = UInt32(json.count).littleEndian
            var frame = Data(bytes: &len, count: 4)
            frame.append(json)
            if !self.writeAll(frame) {
                // Connection dropped — close and let the next send reconnect.
                self.close()
            }
        }
    }

    private func connect() {
        let s = socket(AF_UNIX, SOCK_STREAM, 0)
        guard s >= 0 else { return }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = path.utf8CString
        guard pathBytes.count <= MemoryLayout.size(ofValue: addr.sun_path) else {
            Darwin.close(s)
            return
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { ptr in
            ptr.withMemoryRebound(to: CChar.self, capacity: pathBytes.count) { dst in
                for (i, b) in pathBytes.enumerated() { dst[i] = b }
            }
        }
        let len = socklen_t(MemoryLayout<sockaddr_un>.size)
        let rc = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(s, $0, len)
            }
        }
        if rc != 0 {
            Darwin.close(s)
            return
        }
        fd = s
    }

    private func writeAll(_ data: Data) -> Bool {
        return data.withUnsafeBytes { (raw: UnsafeRawBufferPointer) -> Bool in
            var sent = 0
            let total = raw.count
            let base = raw.baseAddress!
            while sent < total {
                let n = Darwin.write(fd, base + sent, total - sent)
                if n <= 0 { return false }
                sent += n
            }
            return true
        }
    }

    func close() {
        if fd >= 0 {
            Darwin.close(fd)
            fd = -1
        }
    }
}
