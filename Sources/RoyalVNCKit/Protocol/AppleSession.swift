// Switching on Apple's encrypted session after a type 33 or 36 login.
//
// After ServerInit the client sends two cleartext messages: ViewerInfo and
// SetEncryption command 1. The Mac answers with a framebuffer update that
// holds the rekey: a session key and an initial vector, wrapped under a key
// made from the login. The client unwraps them, sends SetEncryption command 2
// in the clear, and from then on both sides speak in records.
//
// Sometimes (the spec's best fit: when nobody is signed in at the console)
// the Mac sends a session-selection block first. The client answers with
// "share the console" or "log in to my own session", then the rekey follows.
//
// Written from docs/protocols/apple-auth-spec.md sections 6 to 8.
//
// ── Change log (newest first) ──────────────────────────────────────────────
//  v1.3  2026-10-18  Share-console, live on mm2018: approval worked, but
//                    unknown bytes came before the rekey, so the client now
//                    scans for the rekey after a selection. The reply's name
//                    is shown to the console user as the requester, so it
//                    carries the login account's name.
//  v1.2  2026-10-18  Live on mm2018: the block comes straight after ServerInit,
//                    flagged there, and must be answered before ViewerInfo.
//                    The Mac's answer is length-prefixed. Mask bit 2 offers
//                    the own-session reply, which opened a new session.
//  v1.1  2026-10-18  Answers the session-selection block (spec 6, approved
//                    4304071 plus 8f81667): share-console and auto-login
//                    replies, then a search for the rekey past the Mac's
//                    reply, whose bytes the spec does not give. Fixed the
//                    mask offset.
//  v1.0  2026-10-18  New. ViewerInfo, command 1, rekey parsing, command 2,
//                    and detection of the session-selection block.
// ───────────────────────────────────────────────────────────────────────────

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol {
	enum AppleSession {
		/// Encoding number of the rectangle that carries the rekey.
		private static let rekeyEncoding: Int32 = 1103

		/// Rectangles the Mac may send ahead of the rekey. Each is a 2-byte
		/// length and that many bytes, and is skipped.
		private static let skippableEncodings: Set<Int32> = [1010, 1011]

		/// First two bytes of the session-selection block: its own length, 74.
		private static let sessionSelectionLength: UInt16 = 74

		/// Asks the app which session to use when the Mac offers a choice.
		typealias Chooser = (VNCSessionSelectionRequest) async -> VNCSessionSelectionChoice

		/// How long to wait for the person at the console to approve sharing.
		static let approvalTimeout: TimeInterval = 90

		/// Answers any session selection, sends the two cleartext messages,
		/// reads the rekey and starts the encrypted record layer.
		/// `selectionExpected` comes from ServerInit (see ServerInit.swift).
		static func establish(connection: SessionConnection,
							  wrapKey: [UInt8],
							  credential: VNCUsernamePasswordCredential,
							  chooser: Chooser,
							  selectionExpected: Bool = false,
							  logger: VNCLogger? = nil) async throws {
			if selectionExpected {
				// The block comes straight after ServerInit, and the Mac reads
				// the client's next bytes as the answer. Answer it first.
				let length = try await connection.readUInt16()

				guard length == sessionSelectionLength else {
					throw VNCError.protocol(.invalidData)
				}

				let block = [UInt8](try await connection.readBuffered(length: Int(length)))

				try await answerSessionSelection(parseSessionSelection(block),
												 connection: connection,
												 wrapKey: wrapKey,
												 credential: credential,
												 chooser: chooser,
												 logger: logger)
			}

			try await connection.write(data: Data(viewerInfo + setEncryptionStart))

			// After a share-console approval, mm2018 sent bytes of unknown
			// layout before the rekey. Scan past them to the rekey rectangle.
			var rekey: FirstReply = selectionExpected
				? .rekey(try await searchForRekey(connection: connection, logger: logger))
				: try await readRekey(connection: connection, logger: logger)

			if case .sessionSelection(let request) = rekey {
				// A Mac that sent the block without marking ServerInit. Kept
				// for safety; the Mac has already read ViewerInfo as an answer.
				try await answerSessionSelection(request,
												 connection: connection,
												 wrapKey: wrapKey,
												 credential: credential,
												 chooser: chooser,
												 logger: logger)

				rekey = .rekey(try await searchForRekey(connection: connection, logger: logger))
			}

			guard case .rekey(let wrapped) = rekey else {
				throw VNCError.protocol(.invalidData)
			}

			let codec: AppleRecordCodec

			do {
				codec = try AppleRecordCodec.fromRekey(wrapKey: wrapKey,
													   wrappedKey: Array(wrapped.prefix(16)),
													   wrappedVector: Array(wrapped.suffix(16)))
			} catch {
				throw VNCError.authentication(.encryptionFailed)
			}

			// Command 2 is the last cleartext message. It is not a record.
			try await connection.write(data: Data(setEncryptionSwitch))

			connection.enableEncryption(codec)

			logger?.logDebug("Apple session: encryption on")
		}

		/// Asks the app, sends the matching reply, and waits for the Mac's
		/// answer. A person may have to approve, so this can take a while.
		private static func answerSessionSelection(_ request: VNCSessionSelectionRequest,
												   connection: SessionConnection,
												   wrapKey: [UInt8],
												   credential: VNCUsernamePasswordCredential,
												   chooser: Chooser,
												   logger: VNCLogger?) async throws {
			let choice = await chooser(request)

			logger?.logDebug("Apple session: session selection mask \(request.mask), choice \(choice)")

			let reply: [UInt8]

			switch choice {
				case .shareConsole where request.canShareConsole:
					// The Mac shows this name to the person at the console as
					// the one asking (seen on mm2018), so send the login account.
					reply = shareConsoleReply(requesterName: credential.username)
				case .ownSession where request.canUseOwnSession:
					reply = try ownSessionReply(credential: credential, wrapKey: wrapKey)
				case .cancel:
					throw VNCError.authentication(.appleSessionSelectionDeclined)
				default:
					throw VNCError.authentication(.appleSessionSelectionRequired)
			}

			try await connection.write(data: Data(reply))

			let watchdog = Task {
				try await Task.sleep(nanoseconds: UInt64(approvalTimeout * 1_000_000_000))
				connection.cancel()
			}
			defer { watchdog.cancel() }

			do {
				// Seen on mm2018 for the own-session reply: a 2-byte length (80),
				// then the body, starting with version 1. Its meaning is not known.
				let length = Int(try await connection.readUInt16())
				let answer = [UInt8](try await connection.readBuffered(length: length))

				logger?.logDebug("Apple session: session-selection answer, \(length) bytes, starts \(answer.prefix(4).map { String(format: "%02x", $0) }.joined())")
			} catch {
				// The Mac closes the connection to decline.
				throw VNCError.authentication(.appleSessionSelectionDeclined)
			}
		}

		private enum FirstReply {
			case rekey([UInt8])
			case sessionSelection(VNCSessionSelectionRequest)
		}

		/// Reads server messages until the rekey or a session-selection block.
		private static func readRekey(connection: SessionConnection,
									  logger: VNCLogger?) async throws -> FirstReply {
			while true {
				let first = try await connection.readUInt8()

				// A short status message, 8 bytes. Skip it.
				if first == 0x14 {
					try await connection.readPadding(length: 7)

					continue
				}

				let second = try await connection.readUInt8()

				if UInt16(first) << 8 | UInt16(second) == sessionSelectionLength {
					let block = [UInt8](try await connection.readBuffered(length: Int(sessionSelectionLength)))

					return .sessionSelection(parseSessionSelection(block))
				}

				// Otherwise a framebuffer update: type 0, one pad byte, a rectangle count.
				guard first == 0, second == 0 else {
					throw VNCError.protocol(.unsupportedServerToClientMessage(messageType: first))
				}

				let rectangles = Int(try await connection.readUInt16())

				for _ in 0..<rectangles {
					_ = try await connection.readBuffered(length: 8) // x, y, width, height

					let encoding = try await connection.readInt32()

					if encoding == rekeyEncoding {
						let body = [UInt8](try await connection.readBuffered(length: 36))

						// Four bytes of generation counter, then the wrapped key and vector.
						return .rekey(Array(body[4...]))
					}

					guard skippableEncodings.contains(encoding) else {
						throw VNCError.protocol(.invalidData)
					}

					let length = Int(try await connection.readUInt16())

					_ = try await connection.readBuffered(length: length)
				}
			}
		}

		/// After a session-selection reply the Mac sends an answer of unknown
		/// layout, then the rekey. Scan for the rekey rectangle's header: zero
		/// geometry and encoding 1103.
		private static func searchForRekey(connection: SessionConnection,
										   logger: VNCLogger?) async throws -> [UInt8] {
			let signature: [UInt8] = [0, 0, 0, 0, 0, 0, 0, 0, 0x00, 0x00, 0x04, 0x4F]
			var window: [UInt8] = []
			var skipped = 0

			while skipped < 65_536 {
				window.append(try await connection.readUInt8())

				if window.count > signature.count {
					window.removeFirst()
					skipped += 1
				}

				if window == signature {
					// What came before the update header (4 bytes) was the Mac's answer.
					logger?.logDebug("Apple session: skipped \(max(0, skipped - 4)) bytes before the rekey")

					let body = [UInt8](try await connection.readBuffered(length: 36))

					return Array(body[4...])
				}
			}

			throw VNCError.protocol(.invalidData)
		}

		/// The 74 bytes after the block's own length: version (2), mask (4),
		/// zero (4), the console user's name (64, NUL-padded).
		private static func parseSessionSelection(_ block: [UInt8]) -> VNCSessionSelectionRequest {
			let mask = block[2..<6].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
			let nameBytes = block[10..<74].prefix { $0 != 0 }

			// Bit 0: share the console. Bit 1 (spec) or bit 2 (seen on mm2018,
			// mask 5, which accepted the own-session reply): own session.
			return VNCSessionSelectionRequest(canShareConsole: mask & 0x1 != 0,
											  canUseOwnSession: mask & 0x6 != 0,
											  consoleUserName: String(decoding: nameBytes, as: UTF8.self),
											  mask: mask)
		}

		/// Share-console reply: length 72, version 2, four zeros, command 0,
		/// a zero, then a name, NUL-padded. The spec says the console user's
		/// name; mm2018 displays it as the requester's, so we send the login
		/// account's.
		private static func shareConsoleReply(requesterName: String) -> [UInt8] {
			var body: [UInt8] = [0x00, 0x02, 0, 0, 0, 0, 0x00, 0x00]
			body += Array(Array(requesterName.utf8).prefix(63))
			body += [UInt8](repeating: 0, count: 72 - body.count)

			return [0x00, 72] + body
		}

		/// Auto-login reply: length 200, version 2, four zeros, command 2, a
		/// zero, 64 zeros, then the account name and the password, each padded
		/// to 64 bytes and encrypted with AES-128-ECB under the wrap key.
		private static func ownSessionReply(credential: VNCUsernamePasswordCredential,
											wrapKey: [UInt8]) throws -> [UInt8] {
			func sealed(_ text: String) throws -> [UInt8] {
				var field = Array(Array(text.utf8).prefix(63))
				field += [UInt8](repeating: 0, count: 64 - field.count)

				guard let encrypted = Data(field).aes128ECBEncrypted(withKey: Data(wrapKey)) else {
					throw VNCError.authentication(.encryptionFailed)
				}

				return [UInt8](encrypted)
			}

			var body: [UInt8] = [0x00, 0x02, 0, 0, 0, 0, 0x02, 0x00]
			body += [UInt8](repeating: 0, count: 64)
			body += try sealed(credential.username)
			body += try sealed(credential.password)

			return [0x00, 200] + body
		}

		// MARK: Cleartext messages
		/// ViewerInfo, 66 bytes: the viewer's identity and capability mask.
		private static var viewerInfo: [UInt8] {
			var message: [UInt8] = [0x21, 0x00, 0x00, 62, 0x00, 0x01]

			message += be32(2) // viewer application id, the value Apple's viewer uses
			message += be32(6) + be32(1) + be32(0) // viewer version
			message += be32(15) + be32(3) + be32(0) // operating system version

			var mask = [UInt8](repeating: 0, count: 32)
			mask[0] = 0xB0
			mask[2] = 0x0C
			mask[3] = 0x03
			mask[4] = 0x90
			mask[10] = 0x40

			return message + mask
		}

		/// SetEncryption command 1: offer AES-128, 12 bytes.
		private static let setEncryptionStart: [UInt8] = [
			0x12, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01
		]

		/// SetEncryption command 2: switch to the new key, 8 bytes.
		private static let setEncryptionSwitch: [UInt8] = [
			0x12, 0x00, 0x00, 0x02, 0x00, 0x01, 0x00, 0x00
		]

		private static func be32(_ value: UInt32) -> [UInt8] {
			[UInt8(value >> 24), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
		}
	}
}
