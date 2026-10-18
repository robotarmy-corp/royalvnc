// Tests for switching on Apple's encrypted session after login: the rekey,
// the session-selection replies, and the first encrypted record.
//
// A scripted Mac answers each client write with the bytes the spec gives.
// The Mac's answer to a session-selection reply is not in the spec, so the
// script sends a few arbitrary bytes there, which the client must skip.
//
// ── Change log (newest first) ──────────────────────────────────────────────
//  v1.0  2026-10-18  New. Plain rekey, share-console, own session, cancel.
// ───────────────────────────────────────────────────────────────────────────

import XCTest
import Dispatch
@testable import RoyalVNCKit
@_implementationOnly import CryptoSwift

/// A fake socket whose far end is a closure.
final class ScriptedSocket: NetworkConnection {
	var inbound: [UInt8] = []
	var written: [[UInt8]] = []
	var onWrite: (([UInt8]) throws -> Void)?

	init(settings: NetworkConnectionSettings) {}
	init() {}

	var status: NetworkConnectionStatus { .ready }
	var isReady: Bool { true }
	func setStatusUpdateHandler(_ statusUpdateHandler: NetworkConnectionStatusUpdateHandler?) {}
	func cancel() {}
	func start(queue: DispatchQueue) {}

	func read(minimumLength: Int, maximumLength: Int) async throws -> Data {
		guard inbound.count >= minimumLength, !inbound.isEmpty else { throw VNCError.connection(.closed) }
		let count = min(maximumLength, inbound.count)
		defer { inbound.removeFirst(count) }
		return Data(inbound.prefix(count))
	}

	func write(data: Data) async throws {
		written.append([UInt8](data))
		try onWrite?([UInt8](data))
	}
}

final class AppleSessionTests: XCTestCase {
	private let wrapKey = [UInt8](repeating: 0x5A, count: 16)
	private let sessionKey = [UInt8](0..<16)
	private let vector = [UInt8](200..<216)
	private let credential = VNCUsernamePasswordCredential(username: "mike", password: "secret")

	private func rekeyUpdate() throws -> [UInt8] {
		let ecb = try AES(key: wrapKey, blockMode: ECB(), padding: .noPadding)
		return [0, 0, 0, 1] + [UInt8](repeating: 0, count: 8) + [0, 0, 0x04, 0x4F]
			+ [0, 0, 0, 1] + (try ecb.encrypt(sessionKey)) + (try ecb.encrypt(vector))
	}

	private func selectionBlock(mask: UInt8, name: String) -> [UInt8] {
		var block: [UInt8] = [0, 74, 0, 1, 0, 0, 0, mask, 0, 0, 0, 0]
		block += Array(name.utf8)
		block += [UInt8](repeating: 0, count: 76 - block.count)
		return block
	}

	/// Runs establish() against the script and checks the session works after.
	private func establish(socket: ScriptedSocket,
						   chooser: @escaping AppleChooser) async throws -> SessionConnection {
		let connection = SessionConnection(wrapping: socket)

		try await VNCProtocol.AppleSession.establish(connection: connection, wrapKey: wrapKey,
													 credential: credential, chooser: chooser)
		XCTAssertTrue(connection.isEncrypted)

		// The client's next message is a record the Mac can open.
		try await connection.write(data: Data([3, 0, 0, 0, 0, 0, 0, 10, 0, 10]))
		let record = try XCTUnwrap(socket.written.last)
		let mac = AppleRecordCodec(key: sessionKey, initialVector: vector)
		XCTAssertEqual(try mac.open(Array(record[2...])), [3, 0, 0, 0, 0, 0, 0, 10, 0, 10])

		// And a record from the Mac reads back as plain bytes.
		socket.inbound += try mac.seal([2, 0, 0, 0])
		let readBack = try await connection.read(length: 4)
		XCTAssertEqual([UInt8](readBack), [2, 0, 0, 0])

		return connection
	}

	typealias AppleChooser = VNCProtocol.AppleSession.Chooser

	func testPlainRekey() async throws {
		let socket = ScriptedSocket()
		let update = try rekeyUpdate()
		socket.onWrite = { data in
			if data.count == 78 {
				XCTAssertEqual(Array(data.prefix(4)), [0x21, 0, 0, 62])
				XCTAssertEqual(Array(data.suffix(12)), [0x12, 0, 0, 1, 0, 1, 0, 1, 0, 0, 0, 1])
				socket.inbound += [0x14, 0, 0, 0, 0, 0, 0, 0] + update // status message first
			}
		}

		_ = try await establish(socket: socket) { _ in XCTFail("no selection expected"); return .cancel }
		XCTAssertEqual(socket.written[1], [0x12, 0, 0, 2, 0, 1, 0, 0])
	}

	func testShareConsole() async throws {
		let socket = ScriptedSocket()
		let update = try rekeyUpdate()
		socket.onWrite = { data in
			switch data.count {
				case 78: socket.inbound += self.selectionBlock(mask: 5, name: "Test User")
				case 74:
					XCTAssertEqual(Array(data.prefix(10)), [0, 72, 0, 2, 0, 0, 0, 0, 0, 0])
					XCTAssertEqual(Array(data[10..<19]), Array("Test User".utf8))
					XCTAssertEqual(Array(data[19...]), [UInt8](repeating: 0, count: 55))
					socket.inbound += [0, 4, 1, 2, 3, 4] + update // unknown answer, then rekey
				default: break
			}
		}

		var seen: VNCSessionSelectionRequest?
		_ = try await establish(socket: socket) { request in seen = request; return .shareConsole }

		XCTAssertEqual(seen?.mask, 5)
		XCTAssertEqual(seen?.canShareConsole, true)
		XCTAssertEqual(seen?.canUseOwnSession, false)
		XCTAssertEqual(seen?.consoleUserName, "Test User")
		XCTAssertEqual(seen?.defaultChoice, .shareConsole)
	}

	func testOwnSession() async throws {
		let socket = ScriptedSocket()
		let update = try rekeyUpdate()
		let ecb = try AES(key: wrapKey, blockMode: ECB(), padding: .noPadding)
		socket.onWrite = { data in
			switch data.count {
				case 78: socket.inbound += self.selectionBlock(mask: 2, name: "")
				case 202:
					XCTAssertEqual(Array(data.prefix(10)), [0, 200, 0, 2, 0, 0, 0, 0, 2, 0])
					XCTAssertEqual(Array(data[10..<74]), [UInt8](repeating: 0, count: 64))
					let user = try ecb.decrypt(Array(data[74..<138]))
					let password = try ecb.decrypt(Array(data[138..<202]))
					XCTAssertEqual(Array(user.prefix(5)), Array("mike".utf8) + [0])
					XCTAssertEqual(Array(password.prefix(7)), Array("secret".utf8) + [0])
					socket.inbound += [9, 9] + update
				default: break
			}
		}

		_ = try await establish(socket: socket) { $0.defaultChoice }
	}

	func testCancelAndUnofferedChoice() async throws {
		for (choice, mask) in [(VNCSessionSelectionChoice.cancel, UInt8(5)), (.ownSession, 5)] {
			let socket = ScriptedSocket()
			socket.onWrite = { data in
				if data.count == 78 { socket.inbound += self.selectionBlock(mask: mask, name: "x") }
			}

			do {
				try await VNCProtocol.AppleSession.establish(connection: SessionConnection(wrapping: socket), wrapKey: wrapKey,
															 credential: credential, chooser: { _ in choice })
				XCTFail("expected failure")
			} catch VNCError.authentication(let error) {
				switch (choice, error) {
					case (.cancel, .appleSessionSelectionDeclined), (.ownSession, .appleSessionSelectionRequired): break
					default: XCTFail("wrong error \(error)")
				}
			}
		}
	}
}
