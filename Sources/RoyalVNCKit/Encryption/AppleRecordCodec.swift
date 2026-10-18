// The encrypted record layer of an Apple Screen Sharing session.
//
// After a type 33 or 36 login and the rekey, every byte in both directions
// travels in records. A record is a 2-byte length and AES-128-CBC ciphertext.
// The plaintext holds the message, filler to a 16-byte boundary, and a SHA-1
// check over a record counter and the plaintext before it.
//
// Each direction keeps its own CBC chain (the last ciphertext block is the
// next initial vector) and its own counter. This class holds both.
//
// Written from docs/protocols/apple-auth-spec.md sections 8 and 9.
//
// ── Change log (newest first) ──────────────────────────────────────────────
//  v1.0  2026-10-18  New. Seal and open records, strict sequence numbers,
//                    and unwrapping of the session key from the rekey.
// ───────────────────────────────────────────────────────────────────────────

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@_implementationOnly import CryptoSwift

enum AppleRecordError: Error {
	case invalidLength
	case integrityCheckFailed(expectedSequence: UInt32)
	case cipherFailure
	case invalidRekey
}

final class AppleRecordCodec {
	/// Size of the SHA-1 check at the end of every record.
	private static let checkLength = 20
	private static let blockLength = 16

	/// Largest message body one record can carry: the length field is 16 bits
	/// and the plaintext is padded up to a whole number of blocks.
	static let maximumBodyLength = 65_535 / blockLength * blockLength - 2 - checkLength

	private let key: [UInt8]

	private let sendLock = NSLock()
	private var sendVector: [UInt8]
	private var sendSequence: UInt32 = 0

	private var receiveVector: [UInt8]
	private var receiveSequence: UInt32 = 0

	/// Both directions start from the same key and initial vector.
	init(key: [UInt8], initialVector: [UInt8]) {
		self.key = key
		self.sendVector = initialVector
		self.receiveVector = initialVector
	}

	/// Unwraps the session key and initial vector from the rekey body:
	/// two 16-byte values, each AES-128-ECB under the wrap key.
	static func fromRekey(wrapKey: [UInt8],
						  wrappedKey: [UInt8],
						  wrappedVector: [UInt8]) throws -> AppleRecordCodec {
		guard wrapKey.count == 16, wrappedKey.count == 16, wrappedVector.count == 16 else {
			throw AppleRecordError.invalidRekey
		}

		do {
			let ecb = try AES(key: wrapKey, blockMode: ECB(), padding: .noPadding)

			let key = try ecb.decrypt(wrappedKey)
			let vector = try ecb.decrypt(wrappedVector)

			return AppleRecordCodec(key: key, initialVector: vector)
		} catch {
			throw AppleRecordError.invalidRekey
		}
	}

	/// Wraps one message body in a record, ready to put on the wire.
	func seal(_ body: [UInt8]) throws -> [UInt8] {
		precondition(body.count <= Self.maximumBodyLength)

		sendLock.lock()
		defer { sendLock.unlock() }

		var plaintext: [UInt8] = [UInt8(body.count >> 8), UInt8(body.count & 0xFF)] + body

		// Filler so that the whole plaintext, check included, is whole blocks.
		let unpadded = plaintext.count + Self.checkLength
		let filler = (Self.blockLength - unpadded % Self.blockLength) % Self.blockLength

		plaintext += [UInt8](repeating: 0, count: filler)
		plaintext += AppleHash.sha1(Self.sequenceBytes(sendSequence) + plaintext)

		do {
			let cipher = try AES(key: key, blockMode: CBC(iv: sendVector), padding: .noPadding)
			let ciphertext = try cipher.encrypt(plaintext)

			sendVector = Array(ciphertext.suffix(Self.blockLength))
			sendSequence &+= 1

			return [UInt8(ciphertext.count >> 8), UInt8(ciphertext.count & 0xFF)] + ciphertext
		} catch {
			throw AppleRecordError.cipherFailure
		}
	}

	/// Decrypts one record's ciphertext and returns the message body.
	/// The chain advances even when the check fails, so the stream stays aligned.
	func open(_ ciphertext: [UInt8]) throws -> [UInt8] {
		guard !ciphertext.isEmpty, ciphertext.count % Self.blockLength == 0 else {
			throw AppleRecordError.invalidLength
		}

		let plaintext: [UInt8]

		do {
			let cipher = try AES(key: key, blockMode: CBC(iv: receiveVector), padding: .noPadding)

			plaintext = try cipher.decrypt(ciphertext)
		} catch {
			throw AppleRecordError.cipherFailure
		}

		receiveVector = Array(ciphertext.suffix(Self.blockLength))

		let sequence = receiveSequence
		receiveSequence &+= 1

		guard plaintext.count >= 2 + Self.checkLength else {
			throw AppleRecordError.invalidLength
		}

		let checked = plaintext.count - Self.checkLength
		let expected = AppleHash.sha1(Self.sequenceBytes(sequence) + plaintext[0..<checked])

		guard Array(plaintext[checked...]) == expected else {
			throw AppleRecordError.integrityCheckFailed(expectedSequence: sequence)
		}

		let bodyLength = Int(plaintext[0]) << 8 | Int(plaintext[1])

		guard 2 + bodyLength <= checked else {
			throw AppleRecordError.invalidLength
		}

		return Array(plaintext[2..<2 + bodyLength])
	}

	private static func sequenceBytes(_ sequence: UInt32) -> [UInt8] {
		[UInt8(sequence >> 24), UInt8((sequence >> 16) & 0xFF), UInt8((sequence >> 8) & 0xFF), UInt8(sequence & 0xFF)]
	}
}
