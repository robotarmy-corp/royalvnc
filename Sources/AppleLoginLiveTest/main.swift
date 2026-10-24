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
//   LIVE_INPUT     if set, sends small pointer moves and a Shift tap every
//                  second, to check the Mac accepts encrypted input
//   LIVE_EXPECT    "fail" when a failed login is the expected result
//   LIVE_LOGOUT    if set, logs the account out: Shift-Command-Q after 2 s,
//                  Return after 5 s. Use only with throwaway accounts.
//   LIVE_CLICK     "x,y" in framebuffer pixels: one click after 2 s
//   LIVE_BUTTON    left (default), middle or right, for LIVE_CLICK
//   LIVE_CHOICE    turns on session selection, and is the answer to the question: cancel, share,
//                  own, or default (the library's pick). Default: default.
//   LIVE_SNAPSHOT  path of a PNG to write with the last frame, quarter size
//
// Prints the connection states, the desktop size, how many framebuffer
// updates arrived, and what share of the picture is not black. Prints no
// credentials and no console user's name.
//
// ── Change log (newest first) ──────────────────────────────────────────────
//  v1.7  2026-10-24  LIVE_BUTTON picks the button for LIVE_CLICK, to check
//                    right clicks in Apple sessions.
//  v1.6  2026-10-18  LIVE_CHOICE also turns on settings.appleSessionSelection.
//  v1.5  2026-10-18  LIVE_CHOICE answers a session-selection question and
//                    prints what the Mac offered. LIVE_DEBUG prints the
//                    library's own log to stdout.
//  v1.4  2026-10-18  LIVE_CLICK, to check pointer input on its own.
//  v1.3  2026-10-18  LIVE_LOGOUT, to clear a test account's session so the
//                    next login meets the session-selection block.
//  v1.2  2026-10-18  LIVE_SNAPSHOT writes the last frame as a PNG, to see
//                    which session a login landed in.
//  v1.1  2026-10-18  Any security type (2 and 30 too), optional input,
//                    expected-failure runs, login time and update rate.
//  v1.0  2026-10-18  New. Live check for types 33 and 36 and the encrypted
//                    session, against mm2018.
// ───────────────────────────────────────────────────────────────────────────

import Foundation
import RoyalVNCKit
#if canImport(ImageIO)
import CoreGraphics
import ImageIO
import UniformTypeIdentifiers
#endif

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
let sendInput = environment["LIVE_INPUT"] != nil
let logOut = environment["LIVE_LOGOUT"] != nil
var logoutStep = 0
let click = environment["LIVE_CLICK"].map { $0.split(separator: ",").compactMap { UInt16($0) } }
var clicked = false
let expectFailure = environment["LIVE_EXPECT"] == "fail"

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
	var connectedAt: Date?
	var finished = false
	var framebuffer: VNCFramebuffer?
	let started = Date()

	func stamp() -> String { String(format: "%6.2fs", Date().timeIntervalSince(started)) }

	func connection(_ connection: VNCConnection, stateDidChange state: VNCConnection.ConnectionState) {
		print("\(stamp()) state: \(state.status)\(state.error.map { " error: \($0.localizedDescription)" } ?? "")")

		if state.status == .connected {
			connected = true
			connectedAt = Date()
		}
		if state.status == .disconnected {
			failure = state.error?.localizedDescription
			finished = true
		}
	}

	func connection(_ connection: VNCConnection, credentialFor type: VNCAuthenticationType,
					completion: @escaping (VNCCredential?) -> Void) {
		if type.requiresUsername {
			completion(VNCUsernamePasswordCredential(username: user, password: password))
		} else {
			completion(VNCPasswordCredential(password: password))
		}
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
									  inputMode: .forwardKeyboardShortcutsEvenIfInUseLocally, isClipboardRedirectionEnabled: false,
									  colorDepth: .depth24Bit, frameEncodings: .default)
settings.preferredSecurityTypes = [type]
settings.appleSessionSelection = environment["LIVE_CHOICE"] != nil

let delegate = Delegate(user: user, password: password)
let connection = environment["LIVE_DEBUG"] != nil
	? VNCConnection(settings: settings, logger: VNCPrintLogger())
	: VNCConnection(settings: settings)

let choiceName = environment["LIVE_CHOICE"] ?? "default"
connection.sessionSelectionHandler = { request, completion in
	// The console user's name is personal data: print only its length.
	print("session selection: mask=\(request.mask) share=\(request.canShareConsole) own=\(request.canUseOwnSession) nameLength=\(request.consoleUserName.utf8.count) answer=\(choiceName)")
	switch choiceName {
		case "cancel": completion(.cancel)
		case "share": completion(.shareConsole)
		case "own": completion(.ownSession)
		default: completion(request.defaultChoice)
	}
}
connection.delegate = delegate

print("connecting to \(host):\(port) with type \(type) as \(user)")
connection.connect()

let deadline = Date().addingTimeInterval(30 + seconds)
var lastInput = Date()
var inputs = 0

while Date() < deadline, !delegate.finished {
	if let connectedAt = delegate.connectedAt {
		if Date().timeIntervalSince(connectedAt) >= seconds { break }

		let elapsed = Date().timeIntervalSince(connectedAt)

		if let click, click.count == 2, !clicked, elapsed >= 2 {
			clicked = true
			connection.mouseMove(x: click[0], y: click[1])
			let button: VNCMouseButton = environment["LIVE_BUTTON"] == "right" ? .right
				: environment["LIVE_BUTTON"] == "middle" ? .middle : .left
			connection.mouseButtonDown(button, x: click[0], y: click[1])
			connection.mouseButtonUp(button, x: click[0], y: click[1])
			print("clicked \(click[0]),\(click[1])")
		}

		if logOut, logoutStep == 0, elapsed >= 2 {
			logoutStep = 1
			connection.keyDown(.command)
			connection.keyDown(.shift)
			connection.keyDown(VNCKeyCode(0x71)) // q
			connection.keyUp(VNCKeyCode(0x71))
			connection.keyUp(.shift)
			connection.keyUp(.command)
			print("sent Shift-Command-Q")
		} else if logOut, logoutStep == 1, elapsed >= 5 {
			logoutStep = 2
			connection.keyDown(.return)
			connection.keyUp(.return)
			print("sent Return")
		}

		if sendInput, Date().timeIntervalSince(lastInput) >= 1 {
			lastInput = Date()
			inputs += 1
			// A few pixels near the middle, then back. No clicks.
			let x = UInt16(1000 + (inputs % 2) * 4), y = UInt16(800)
			connection.mouseMove(x: x, y: y)
			connection.keyDown(.shift)
			connection.keyUp(.shift)
		}
	}
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

#if canImport(ImageIO)
if let path = environment["LIVE_SNAPSHOT"], let image = delegate.framebuffer?.cgImage {
	let width = image.width / 4, height = image.height / 4
	if let context = CGContext(data: nil, width: width, height: height, bitsPerComponent: 8, bytesPerRow: 0,
							   space: CGColorSpaceCreateDeviceRGB(), bitmapInfo: CGImageAlphaInfo.noneSkipLast.rawValue) {
		context.interpolationQuality = .medium
		context.draw(image, in: CGRect(x: 0, y: 0, width: width, height: height))
		if let small = context.makeImage(),
		   let destination = CGImageDestinationCreateWithURL(URL(fileURLWithPath: path) as CFURL, UTType.png.identifier as CFString, 1, nil) {
			CGImageDestinationAddImage(destination, small, nil)
			CGImageDestinationFinalize(destination)
		}
	}
}
#endif

let loginTime = delegate.connectedAt.map { String(format: "%.2fs", $0.timeIntervalSince(delegate.started)) } ?? "-"
let succeeded = delegate.connected && delegate.updates > 0 && delegate.failure == nil
let ok = expectFailure ? (!delegate.connected && delegate.failure != nil) : succeeded
print("result: \(ok ? "OK" : "FAILED") type=\(type) connected=\(delegate.connected) login=\(loginTime) size=\(delegate.size) updates=\(delegate.updates) inputs=\(inputs) lit=\(String(format: "%.1f", litShare * 100))%\(delegate.failure.map { " failure=\($0)" } ?? "")")

connection.disconnect()
exit(ok ? 0 : 1)
