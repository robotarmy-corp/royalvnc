// The connection the rest of the library talks to.
//
// It wraps the real socket connection and passes everything straight through,
// until the handshake installs a record codec (Apple's encrypted session).
// From then on writes become encrypted records and reads decrypt them, so the
// framebuffer, input and cursor code needs no change.
//
// One writer at a time: the handshake, then the send loop. Records are numbered
// in the order they are sealed, so two concurrent writers could reorder them.
//
// ── Change log (newest first) ──────────────────────────────────────────────
//  v1.0  2026-10-18  New. Pass-through connection with an optional Apple
//                    record codec switched on after the rekey.
// ───────────────────────────────────────────────────────────────────────────

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

import Dispatch

#if canImport(Network)
import Network
#endif

final class SessionConnection: NetworkConnection {
	private let inner: any NetworkConnection

	private var codec: AppleRecordCodec?

	/// Decrypted bytes not yet handed to a reader.
	private var plaintext = Data()

	init(settings: NetworkConnectionSettings) {
#if canImport(Network)
		self.inner = NWConnection(settings: settings)
#else
		self.inner = SocketNetworkConnection(settings: settings)
#endif
	}

	/// Wraps an existing connection. For tests.
	init(wrapping inner: any NetworkConnection) {
		self.inner = inner
	}

	/// Switches this connection to encrypted records. Everything read or
	/// written from now on goes through the codec.
	func enableEncryption(_ codec: AppleRecordCodec) {
		self.codec = codec
	}

	var isEncrypted: Bool { codec != nil }

	// MARK: NetworkConnection
	var status: NetworkConnectionStatus { inner.status }
	var isReady: Bool { inner.isReady }

	func setStatusUpdateHandler(_ statusUpdateHandler: NetworkConnectionStatusUpdateHandler?) {
		inner.setStatusUpdateHandler(statusUpdateHandler)
	}

	func cancel() {
		inner.cancel()
	}

	func start(queue: DispatchQueue) {
		inner.start(queue: queue)
	}

	// MARK: Reading
	func read(minimumLength: Int,
			  maximumLength: Int) async throws -> Data {
		guard let codec else {
			return try await inner.read(minimumLength: minimumLength,
										maximumLength: maximumLength)
		}

		while plaintext.count < minimumLength {
			try await readRecord(codec)
		}

		let count = min(maximumLength, plaintext.count)
		let chunk = Data(plaintext.prefix(count))

		plaintext = Data(plaintext.dropFirst(count))

		return chunk
	}

	private func readRecord(_ codec: AppleRecordCodec) async throws {
		let header = try await inner.readBuffered(length: 2)
		let length = Int(header[header.startIndex]) << 8 | Int(header[header.startIndex + 1])

		guard length > 0, length % 16 == 0 else {
			throw AppleRecordError.invalidLength
		}

		let ciphertext = try await inner.readBuffered(length: length)

		plaintext.append(contentsOf: try codec.open([UInt8](ciphertext)))
	}

	// MARK: Writing
	func write(data: Data) async throws {
		guard let codec else {
			return try await inner.write(data: data)
		}

		// One message per record. Larger ones are split at the record limit.
		var offset = data.startIndex

		repeat {
			let end = min(offset + AppleRecordCodec.maximumBodyLength, data.endIndex)
			let record = try codec.seal([UInt8](data[offset..<end]))

			try await inner.write(data: Data(record))

			offset = end
		} while offset < data.endIndex
	}
}
