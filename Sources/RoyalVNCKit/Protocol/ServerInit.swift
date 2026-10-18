// ServerInit: framebuffer size, pixel format, desktop name.
//
// ── Change log (newest first, robotarmy-corp fork) ─────────────────────────
//  v1.1  2026-10-18  `lenientName`: Apple's Macs start the name with non-text
//                    bytes, so the strict UTF-8 read fails. Decode what is
//                    there and replace what is not text.
//  v1.0  (upstream)  As inherited from royalapplications/royalvnc 2026-09-21.
// ───────────────────────────────────────────────────────────────────────────

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol {
	struct ServerInit {
		let framebufferWidth: UInt16
		let framebufferHeight: UInt16

		let pixelFormat: PixelFormat

		let name: String
	}
}

extension VNCProtocol.ServerInit {
	static func receive(connection: NetworkConnectionReading,
						isTightSecurityEnabled: Bool,
						lenientName: Bool = false) async throws -> Self {
		guard !isTightSecurityEnabled else {
			// TODO: When Tight Security is enabled there are addtional fields
			// See https://github.com/rfbproto/rfbproto/blob/master/rfbproto.rst#serverinit
			throw VNCError.protocol(.notImplemented(feature: "Tight Security"))
		}

		let frameBufferWidth = try await connection.readUInt16()
		let frameBufferHeight = try await connection.readUInt16()

		let pixelFormat = try await VNCProtocol.PixelFormat.receive(connection: connection)

		let name: String

		if lenientName {
			let length = Int(try await connection.readUInt32())
			let bytes = try await connection.readBuffered(length: length)

			name = String(decoding: bytes, as: UTF8.self)
		} else {
			name = try await connection.readString(encoding: .utf8)
		}

		return .init(framebufferWidth: frameBufferWidth,
					 framebufferHeight: frameBufferHeight,
					 pixelFormat: pixelFormat,
					 name: name)
	}
}
