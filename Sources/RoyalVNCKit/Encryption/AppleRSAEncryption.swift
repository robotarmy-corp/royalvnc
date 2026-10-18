// RSA encryption with PKCS#1 v1.5 padding (RSAES-PKCS1-v1_5, RFC 8017),
// under a public key given as SubjectPublicKeyInfo DER.
//
// Type 33 sends the account name to the Mac encrypted under the Mac's RSA
// key. Done by hand on big numbers so it works on every platform the library
// builds for. Only encryption is needed. There is no private key here.
//
// ── Change log (newest first) ──────────────────────────────────────────────
//  v1.0  2026-10-18  New. SPKI parser and PKCS#1 v1.5 encryption for the
//                    type 33 identity envelope.
// ───────────────────────────────────────────────────────────────────────────

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@_implementationOnly import CryptoSwift

enum AppleRSAError: Error {
	case invalidKey
	case messageTooLong
}

struct AppleRSAPublicKey {
	let modulus: BigUInteger
	let exponent: BigUInteger

	/// Length of the modulus in bytes: the length of every ciphertext.
	let byteLength: Int

	/// Parses SubjectPublicKeyInfo: SEQUENCE { SEQUENCE { algorithm }, BIT STRING { SEQUENCE { INTEGER n, INTEGER e } } }.
	init(spki: [UInt8]) throws {
		var outer = DERReader(spki)
		var info = try outer.readElement(tag: 0x30)

		_ = try info.readElement(tag: 0x30) // algorithm identifier

		var bitString = try info.readElement(tag: 0x03)
		let unusedBits = try bitString.readByte()

		guard unusedBits == 0 else { throw AppleRSAError.invalidKey }

		var keyBody = DERReader(bitString.remaining)
		var pair = try keyBody.readElement(tag: 0x30)

		let modulusBytes = try pair.readElement(tag: 0x02).remaining
		let exponentBytes = try pair.readElement(tag: 0x02).remaining

		let modulus = BigUInteger(Data(modulusBytes))
		let exponent = BigUInteger(Data(exponentBytes))

		guard modulus > BigUInteger(1) << 511, exponent > 1 else {
			throw AppleRSAError.invalidKey
		}

		self.modulus = modulus
		self.exponent = exponent
		self.byteLength = (modulus.bitWidth + 7) / 8
	}

	/// PKCS#1 v1.5 encryption (block type 2, random non-zero padding).
	/// The `padding` argument exists so tests can fix the random bytes.
	func encrypt(_ message: [UInt8],
				 padding: [UInt8]? = nil) throws -> [UInt8] {
		let paddingLength = byteLength - message.count - 3

		guard paddingLength >= 8 else { throw AppleRSAError.messageTooLong }

		var filler = padding ?? []

		if padding == nil {
			var generator = SystemRandomNumberGenerator()

			filler = (0..<paddingLength).map { _ in UInt8.random(in: 1...255, using: &generator) }
		}

		guard filler.count == paddingLength, !filler.contains(0) else {
			throw AppleRSAError.invalidKey
		}

		let block: [UInt8] = [0x00, 0x02] + filler + [0x00] + message
		let encrypted = BigUInteger(Data(block)).power(exponent, modulus: modulus)
		let bytes = [UInt8](encrypted.serialize())

		return [UInt8](repeating: 0, count: byteLength - bytes.count) + bytes
	}
}

/// A minimal reader for DER (binary ASN.1) with definite lengths.
struct DERReader {
	private let bytes: [UInt8]
	private var position = 0

	init(_ bytes: [UInt8]) {
		self.bytes = bytes
	}

	var remaining: [UInt8] {
		Array(bytes[position...])
	}

	mutating func readByte() throws -> UInt8 {
		guard position < bytes.count else { throw AppleRSAError.invalidKey }

		defer { position += 1 }

		return bytes[position]
	}

	/// Reads one element with the given tag and returns a reader over its contents.
	mutating func readElement(tag: UInt8) throws -> DERReader {
		guard try readByte() == tag else { throw AppleRSAError.invalidKey }

		var length = Int(try readByte())

		if length & 0x80 != 0 {
			let lengthBytes = length & 0x7F

			guard lengthBytes > 0, lengthBytes <= 3 else { throw AppleRSAError.invalidKey }

			length = 0
			for _ in 0..<lengthBytes {
				length = length << 8 | Int(try readByte())
			}
		}

		guard position + length <= bytes.count else { throw AppleRSAError.invalidKey }

		defer { position += length }

		return DERReader(Array(bytes[position..<position + length]))
	}
}
