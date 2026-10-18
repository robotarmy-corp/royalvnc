// Switching on Apple's encrypted session after a type 33 or 36 login.
//
// After ServerInit the client sends two cleartext messages: ViewerInfo and
// SetEncryption command 1. The Mac answers with a framebuffer update that
// holds the rekey: a session key and an initial vector, wrapped under a key
// made from the login. The client unwraps them, sends SetEncryption command 2
// in the clear, and from then on both sides speak in records.
//
// When another account is signed in at the console, the Mac sends a
// session-selection block instead of the rekey. That is not supported yet.
//
// Written from docs/protocols/apple-auth-spec.md sections 6 to 8.
//
// ── Change log (newest first) ──────────────────────────────────────────────
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

		/// Sends the two cleartext messages, reads the rekey and starts the
		/// encrypted record layer on the connection.
		static func establish(connection: SessionConnection,
							  wrapKey: [UInt8],
							  logger: VNCLogger? = nil) async throws {
			try await connection.write(data: Data(viewerInfo + setEncryptionStart))

			let rekey = try await readRekey(connection: connection, logger: logger)

			let codec: AppleRecordCodec

			do {
				codec = try AppleRecordCodec.fromRekey(wrapKey: wrapKey,
													   wrappedKey: Array(rekey.prefix(16)),
													   wrappedVector: Array(rekey.suffix(16)))
			} catch {
				throw VNCError.authentication(.encryptionFailed)
			}

			// Command 2 is the last cleartext message. It is not a record.
			try await connection.write(data: Data(setEncryptionSwitch))

			connection.enableEncryption(codec)

			logger?.logDebug("Apple session: encryption on")
		}

		/// Reads server messages until the rekey arrives. Returns its 32
		/// wrapped bytes: the key, then the initial vector.
		private static func readRekey(connection: SessionConnection,
									  logger: VNCLogger?) async throws -> [UInt8] {
			while true {
				let first = try await connection.readUInt8()

				// A short status message, 8 bytes. Skip it.
				if first == 0x14 {
					try await connection.readPadding(length: 7)

					continue
				}

				let second = try await connection.readUInt8()

				if UInt16(first) << 8 | UInt16(second) == sessionSelectionLength {
					// 2 bytes of version, then a mask of what the Mac offers.
					let block = [UInt8](try await connection.readBuffered(length: Int(sessionSelectionLength)))
					let mask = block.count >= 8 ? block[4..<8].reduce(0) { $0 << 8 | Int($1) } : -1

					// The block ends in the console user's name, which is
					// personal data. It is not logged.
					logger?.logDebug("Apple session: session selection offered, mask \(mask)")

					throw VNCError.authentication(.appleSessionSelectionRequired)
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
						return Array(body[4...])
					}

					guard skippableEncodings.contains(encoding) else {
						throw VNCError.protocol(.invalidData)
					}

					let length = Int(try await connection.readUInt16())

					_ = try await connection.readBuffered(length: length)
				}
			}
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
