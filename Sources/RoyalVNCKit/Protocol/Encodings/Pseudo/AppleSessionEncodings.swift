// Rectangles an Apple Mac may put in a framebuffer update during an encrypted
// session (types 33 and 36): a later rekey (1103), and two Apple rectangles
// (1010, 1011) that carry a 2-byte length and data this client skips.
//
// Written from docs/protocols/apple-auth-spec.md section 8.
//
// ── Change log (newest first) ──────────────────────────────────────────────
//  v1.0  2026-10-18  New. A mid-session rekey would otherwise end the
//                    connection as an unknown encoding.
// ───────────────────────────────────────────────────────────────────────────

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol {
	struct AppleRekeyEncoding: VNCReceivablePseudoEncoding {
		static let number: VNCEncodingType = 1103

		let encodingType = Self.number
	}

	struct AppleSkippedEncoding: VNCReceivablePseudoEncoding {
		let encodingType: VNCEncodingType
	}
}

extension VNCProtocol.AppleRekeyEncoding {
	func receive(_ rectangle: VNCProtocol.Rectangle,
				 framebuffer: VNCFramebuffer,
				 connection: NetworkConnectionReading,
				 logger: VNCLogger) async throws {
		// Generation counter (4), wrapped key (16), wrapped vector (16).
		let body = [UInt8](try await connection.readBuffered(length: 36))
		let generation = body[0..<4].reduce(UInt32(0)) { $0 << 8 | UInt32($1) }

		guard let session = connection as? SessionConnection, session.isEncrypted else {
			throw VNCError.protocol(.invalidData)
		}

		logger.logInfo("Apple session: rekey during the session, generation \(generation). Applying it as the spec describes (unverified).")

		try session.rekey(wrappedKey: Array(body[4..<20]), wrappedVector: Array(body[20..<36]))
	}
}

extension VNCProtocol.AppleSkippedEncoding {
	func receive(_ rectangle: VNCProtocol.Rectangle,
				 framebuffer: VNCFramebuffer,
				 connection: NetworkConnectionReading,
				 logger: VNCLogger) async throws {
		let length = Int(try await connection.readUInt16())

		_ = try await connection.readBuffered(length: length)

		logger.logDebug("Apple session: skipped a \(encodingType) rectangle of \(length) bytes")
	}
}
