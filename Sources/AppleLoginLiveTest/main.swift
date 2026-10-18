// Live test of Apple's SRP logins against a real Mac.
//
// Reads the host and login from environment variables, so the password never
// lands in a file, a shell history line or a log:
//   LIVE_HOST      host or address (required)
//   LIVE_PORT      default 5900
//   LIVE_TYPE      33 or 36 (default 33)
//   LIVE_USER      account name
//   LIVE_PASSWORD  its password
//   LIVE_SECONDS   how long to stay connected (default 10)
//
// Prints the connection states, the desktop size, how many framebuffer
// updates arrived, and what share of the picture is not black. Prints no
// credentials and no console user's name.
//
// ── Change log (newest first) ──────────────────────────────────────────────
//  v1.0  2026-10-18  New. Live check for types 33 and 36 and the encrypted
//                    session, against mm2018.
// ───────────────────────────────────────────────────────────────────────────

import Foundation
import RoyalVNCKit

let environment = ProcessInfo.processInfo.environment

guard let host = environment["LIVE_HOST"],
	  let user = environment["LIVE_USER"],
	  let password = environment["LIVE_PASSWORD"] else {
	print("Set LIVE_HOST, LIVE_USER and LIVE_PASSWORD.")
	exit(2)
}

let port = UInt16(environment["LIVE_PORT"] ?? "5900") ?? 5900
let type = UInt8(environment["LIVE_TYPE"] ?? "33") ?? 33
let seconds = Double(environment["LIVE_SECONDS"] ?? "10") ?? 10

final class Delegate: NSObject, VNCConnectionDelegate, @unchecked Sendable {
	let user: String
	let password: String

	init(user: String, password: String) {
		self.user = user
		self.password = password
	}

	var updates = 0
	var size = ""
	var failure: String?
	var connected = false
	var finished = false
	var framebuffer: VNCFramebuffer?
	let started = Date()

	func stamp() -> String { String(format: "%6.2fs", Date().timeIntervalSince(started)) }

	func connection(_ connection: VNCConnection, stateDidChange state: VNCConnection.ConnectionState) {
		print("\(stamp()) state: \(state.status)\(state.error.map { " error: \($0.localizedDescription)" } ?? "")")

		if state.status == .connected { connected = true }
		if state.status == .disconnected {
			failure = state.error?.localizedDescription
			finished = true
		}
	}

	func connection(_ connection: VNCConnection, credentialFor type: VNCAuthenticationType,
					completion: @escaping (VNCCredential?) -> Void) {
		completion(VNCUsernamePasswordCredential(username: user, password: password))
	}

	func connection(_ connection: VNCConnection, didCreateFramebuffer framebuffer: VNCFramebuffer) {
		self.framebuffer = framebuffer
		size = "\(framebuffer.size.width)x\(framebuffer.size.height)"
		print("\(stamp()) framebuffer \(size)")
	}

	func connection(_ connection: VNCConnection, didResizeFramebuffer framebuffer: VNCFramebuffer) {
		self.framebuffer = framebuffer
	}

	func connection(_ connection: VNCConnection, didUpdateFramebuffer framebuffer: VNCFramebuffer,
					x: UInt16, y: UInt16, width: UInt16, height: UInt16) {
		updates += 1
		if updates <= 3 { print("\(stamp()) update \(updates): \(width)x\(height) at \(x),\(y)") }
	}

	func connection(_ connection: VNCConnection, didUpdateCursor cursor: VNCCursor) {}
}

let settings = VNCConnection.Settings(isDebugLoggingEnabled: environment["LIVE_DEBUG"] != nil,
									  hostname: host, port: port, isShared: true,
									  isScalingEnabled: false, useDisplayLink: false,
									  inputMode: .none, isClipboardRedirectionEnabled: false,
									  colorDepth: .depth24Bit, frameEncodings: .default)
settings.preferredSecurityTypes = [type]

let delegate = Delegate(user: user, password: password)
let connection = VNCConnection(settings: settings)
connection.delegate = delegate

print("connecting to \(host):\(port) with type \(type) as \(user)")
connection.connect()

let deadline = Date().addingTimeInterval(30 + seconds)
var connectedAt: Date?

while Date() < deadline, !delegate.finished {
	if delegate.connected, connectedAt == nil { connectedAt = Date() }
	if let connectedAt, Date().timeIntervalSince(connectedAt) >= seconds { break }
	Thread.sleep(forTimeInterval: 0.2)
}

var litShare = 0.0
if let framebuffer = delegate.framebuffer {
	let bytes = framebuffer.surfaceAddress.assumingMemoryBound(to: UInt8.self)
	var lit = 0
	for index in stride(from: 0, to: framebuffer.surfaceByteCount, by: 4) where bytes[index] | bytes[index + 1] | bytes[index + 2] != 0 {
		lit += 1
	}
	litShare = Double(lit) / Double(max(1, framebuffer.surfaceByteCount / 4))
}

let ok = delegate.connected && delegate.updates > 0 && delegate.failure == nil
print("result: \(ok ? "OK" : "FAILED") connected=\(delegate.connected) size=\(delegate.size) updates=\(delegate.updates) lit=\(String(format: "%.1f", litShare * 100))%\(delegate.failure.map { " failure=\($0)" } ?? "")")

connection.disconnect()
exit(ok ? 0 : 1)
