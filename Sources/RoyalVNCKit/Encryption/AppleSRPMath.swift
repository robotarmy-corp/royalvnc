// The arithmetic of Apple's SRP login (RFB security types 33 and 36).
//
// SRP-6a (Secure Remote Password, RFC 5054) with the 4096-bit group and
// SHA-512, plus Apple's changes: the password is stretched with PBKDF2 first,
// the user name is left out of the private value and of the proof, and every
// big number is padded to 512 bytes inside every hash.
//
// This file knows nothing about sockets. Framing is in AppleSRPLogin.swift.
// Written from docs/protocols/apple-auth-spec.md section 4 and RFC 5054.
//
// ── Change log (newest first) ──────────────────────────────────────────────
//  v1.0  2026-10-18  New. Client side of the exchange, the server proof
//                    check and the session wrap key, for types 33 and 36.
// ───────────────────────────────────────────────────────────────────────────

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

#if canImport(CommonCrypto)
import CommonCrypto
#endif

@_implementationOnly import CryptoSwift

enum AppleSRPError: Error {
	case invalidParameters
	case iterationCountTooHigh
	case keyDerivationFailed
}

/// Secure random bytes from the system generator.
func appleSecureRandomBytes(_ count: Int) -> [UInt8] {
	var generator = SystemRandomNumberGenerator()

	return (0..<count).map { _ in UInt8.random(in: 0...255, using: &generator) }
}

/// SHA-512, SHA-256 and SHA-1 over a byte array.
enum AppleHash {
	static func sha512(_ parts: [UInt8]...) -> [UInt8] {
		Digest.sha512(Array(parts.joined()))
	}

	static func sha256(_ bytes: [UInt8]) -> [UInt8] {
		Digest.sha256(bytes)
	}

	static func sha1(_ bytes: [UInt8]) -> [UInt8] {
		Digest.sha1(bytes)
	}
}

/// PBKDF2-HMAC-SHA512 (RFC 8018).
enum AppleKeyDerivation {
	static func pbkdf2SHA512(password: [UInt8],
							 salt: [UInt8],
							 iterations: Int,
							 keyLength: Int) throws -> [UInt8] {
#if canImport(CommonCrypto)
		// The system routine is many times faster than a Swift one.
		var derived = [UInt8](repeating: 0, count: keyLength)

		let status = password.withUnsafeBufferPointer { passwordBuffer in
			salt.withUnsafeBufferPointer { saltBuffer in
				derived.withUnsafeMutableBufferPointer { derivedBuffer in
					passwordBuffer.baseAddress!.withMemoryRebound(to: Int8.self,
																   capacity: password.count) { passwordPointer in
						CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
											 passwordPointer,
											 password.count,
											 saltBuffer.baseAddress,
											 salt.count,
											 CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512),
											 UInt32(iterations),
											 derivedBuffer.baseAddress,
											 keyLength)
					}
				}
			}
		}

		guard status == Int32(kCCSuccess) else {
			throw AppleSRPError.keyDerivationFailed
		}

		return derived
#else
		do {
			let kdf = try PKCS5.PBKDF2(password: password,
									   salt: salt,
									   iterations: iterations,
									   keyLength: keyLength,
									   variant: .sha2(.sha512))

			return try kdf.calculate()
		} catch {
			throw AppleSRPError.keyDerivationFailed
		}
#endif
	}
}

/// What the server sends as its SRP challenge.
struct AppleSRPChallenge {
	let modulus: [UInt8]
	let generator: [UInt8]
	let salt: [UInt8]
	let serverPublicValue: [UInt8]
	let iterations: UInt64
	let options: [UInt8]
}

/// One run of the client side of the exchange.
final class AppleSRPClient {
	/// Length of the group modulus, and of every padded number.
	static let width = 512

	/// RFC 5054 appendix A, 4096-bit group.
	static let rfc5054Modulus: [UInt8] = hexBytes("""
	FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200CBBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A92108011A723C12A787E6D788719A10BDBA5B2699C327186AF4E23C1A946834B6150BDA2583E9CA2AD44CE8DBBBC2DB04DE8EF92E8EFC141FBECAA6287C59474E6BC05D99B2964FA090C3A2233BA186515BE7ED1F612970CEE2D7AFB81BDD762170481CD0069127D5B05AA993B4EA988D8FDDC186FFB7DC90A6C08F4DF435C934063199FFFFFFFFFFFFFFFF
	""")

	/// Refuse a server that asks for more than this many PBKDF2 rounds.
	static let maximumIterations: UInt64 = 1_000_000

	let challenge: AppleSRPChallenge

	private let n: BigUInteger
	private let g: BigUInteger
	private let b: BigUInteger
	private let a: BigUInteger

	/// The client public value, padded to 512 bytes.
	let publicValue: [UInt8]

	private(set) var clientProof: [UInt8] = []
	private(set) var sessionKey: [UInt8] = []

	init(challenge: AppleSRPChallenge,
		 exponent: [UInt8]? = nil) throws {
		self.challenge = challenge

		// The group must be the one we expect, and B must not be zero mod N.
		guard challenge.modulus == Self.rfc5054Modulus,
			  challenge.generator == [5],
			  challenge.salt.count > 0,
			  challenge.serverPublicValue.count > 0,
			  challenge.serverPublicValue.count <= Self.width else {
			throw AppleSRPError.invalidParameters
		}

		guard challenge.iterations > 0,
			  challenge.iterations <= Self.maximumIterations else {
			throw AppleSRPError.iterationCountTooHigh
		}

		let n = BigUInteger(Data(challenge.modulus))
		let g = BigUInteger(5)
		let b = BigUInteger(Data(challenge.serverPublicValue))

		guard b % n != 0 else {
			throw AppleSRPError.invalidParameters
		}

		// The secret exponent: 256 bits, top bit set.
		var secret = exponent ?? appleSecureRandomBytes(32)
		if exponent == nil { secret[0] |= 0x80 }

		let a = BigUInteger(Data(secret))
		let bigA = g.power(a, modulus: n)

		self.n = n
		self.g = g
		self.b = b
		self.a = a
		self.publicValue = Self.padded(bigA)
	}

	/// Works out the session key and the client proof. This is the slow step.
	func computeProof(password: String) throws {
		let paddedN = Self.padded(n)
		let paddedG = Self.padded(g)
		let paddedB = Self.padded(b)
		let salt = challenge.salt

		// Stretch the password.
		let stretched = try AppleKeyDerivation.pbkdf2SHA512(password: Array(password.utf8),
															salt: salt,
															iterations: Int(challenge.iterations),
															keyLength: 128)

		// x = H(salt | H(":" | P)). The user name is not part of it.
		let inner = AppleHash.sha512([0x3A], stretched)
		let x = BigUInteger(Data(AppleHash.sha512(salt, inner)))

		let k = BigUInteger(Data(AppleHash.sha512(paddedN, paddedG)))
		let u = BigUInteger(Data(AppleHash.sha512(publicValue, paddedB)))

		// S = (B - k * g^x) ^ (a + u * x) mod N
		let gx = g.power(x, modulus: n)
		let kgx = (k * gx) % n
		let base = (b % n + n - kgx) % n
		let exponent = a + u * x
		let s = base.power(exponent, modulus: n)

		let key = AppleHash.sha512(Self.padded(s))

		// M1 = H( H(N) xor H(g) | H("") | salt | A | B | K )
		let hashN = AppleHash.sha512(paddedN)
		let hashG = AppleHash.sha512(paddedG)
		let xored = zip(hashN, hashG).map { $0 ^ $1 }
		let emptyHash = AppleHash.sha512([])

		sessionKey = key
		clientProof = AppleHash.sha512(xored, emptyHash, salt, publicValue, paddedB, key)
	}

	/// True when the server's proof is the one we expect: H(A | M1 | K).
	func verifyServerProof(_ proof: [UInt8]) -> Bool {
		guard !clientProof.isEmpty else { return false }

		let expected = AppleHash.sha512(publicValue, clientProof, sessionKey)

		// Constant time, so a fake server learns nothing from timing.
		guard expected.count == proof.count else { return false }

		var difference: UInt8 = 0
		for (left, right) in zip(expected, proof) { difference |= left ^ right }

		return difference == 0
	}

	/// The key that unwraps the session key: first 16 bytes of SHA-256(K).
	var wrapKey: [UInt8] {
		Array(AppleHash.sha256(sessionKey).prefix(16))
	}

	static func padded(_ value: BigUInteger) -> [UInt8] {
		let bytes = [UInt8](value.serialize())

		guard bytes.count < width else { return bytes }

		return [UInt8](repeating: 0, count: width - bytes.count) + bytes
	}
}

private func hexBytes(_ hex: String) -> [UInt8] {
	let digits = Array(hex.filter { !$0.isWhitespace }.utf8)
	var bytes: [UInt8] = []
	bytes.reserveCapacity(digits.count / 2)

	func value(_ digit: UInt8) -> UInt8 {
		digit <= 0x39 ? digit - 0x30 : (digit | 0x20) - 0x61 + 10
	}

	var index = 0
	while index + 1 < digits.count {
		bytes.append(value(digits[index]) << 4 | value(digits[index + 1]))
		index += 2
	}

	return bytes
}
