// Tests for Apple's SRP logins (types 33 and 36) and the encrypted session.
//
// The login tests run the client against a scripted in-memory Mac that speaks
// the framing in docs/protocols/apple-auth-spec.md. That proves the client
// agrees with the spec and with its own arithmetic. It does not prove Apple's
// Mac agrees: the live test (AppleLoginLiveTest) does that.
//
// ── Change log (newest first) ──────────────────────────────────────────────
//  v1.0  2026-10-18  New. PBKDF2 vectors, RSA against the system, SRP round
//                    trip, both login framings with good, bad and refused
//                    passwords, record codec, and the rekey.
// ───────────────────────────────────────────────────────────────────────────

import XCTest
import Security
@testable import RoyalVNCKit
@_implementationOnly import CryptoSwift

private func hex(_ bytes: [UInt8]) -> String {
	bytes.map { String(format: "%02x", $0) }.joined()
}

final class AppleKeyDerivationTests: XCTestCase {
	func testPBKDF2SHA512KnownAnswers() throws {
		let one = try AppleKeyDerivation.pbkdf2SHA512(password: Array("password".utf8), salt: Array("salt".utf8),
													  iterations: 1, keyLength: 64)
		XCTAssertEqual(hex(one), "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce")

		let two = try AppleKeyDerivation.pbkdf2SHA512(password: Array("password".utf8), salt: Array("salt".utf8),
													  iterations: 2, keyLength: 64)
		XCTAssertEqual(hex(two), "e1d9c16aa681708a45f5c7c4e215ceb66e011a2e9f0040713f18aefdb866d53cf76cab2868a39b9f7840edce4fef5a82be67335c77a6068e04112754f27ccf4e")
	}

	func testSystemAndCryptoSwiftAgree() throws {
		let system = try AppleKeyDerivation.pbkdf2SHA512(password: Array("pässword".utf8), salt: [1, 2, 3, 4],
														 iterations: 50, keyLength: 128)
		let swift = try PKCS5.PBKDF2(password: Array("pässword".utf8), salt: [1, 2, 3, 4], iterations: 50,
									 keyLength: 128, variant: .sha2(.sha512)).calculate()
		XCTAssertEqual(system, swift)
	}
}

final class AppleModulusTests: XCTestCase {
	func testRFC5054Modulus() {
		let modulus = AppleSRPClient.rfc5054Modulus
		XCTAssertEqual(modulus.count, 512)
		XCTAssertEqual(hex(Array(modulus.prefix(12))), "ffffffffffffffffc90fdaa2")
		XCTAssertEqual(hex(Array(modulus.suffix(8))), "ffffffffffffffff")
	}
}

/// A 2048-bit RSA key from the system, with its public half as SPKI DER.
struct SystemRSAKey {
	let privateKey: SecKey
	let spki: [UInt8]

	init() throws {
		var error: Unmanaged<CFError>?
		let attributes: [CFString: Any] = [kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048]

		guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error),
			  let publicKey = SecKeyCopyPublicKey(key),
			  let pkcs1 = SecKeyCopyExternalRepresentation(publicKey, &error) as Data? else {
			throw error!.takeRetainedValue()
		}

		// SPKI header for a 2048-bit RSA key: SEQUENCE, algorithm rsaEncryption, BIT STRING.
		let header: [UInt8] = [0x30, 0x82, 0x01, 0x22, 0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D,
							   0x01, 0x01, 0x01, 0x05, 0x00, 0x03, 0x82, 0x01, 0x0F, 0x00]

		self.privateKey = key
		self.spki = header + [UInt8](pkcs1)
	}

	func decrypt(_ ciphertext: [UInt8]) -> [UInt8]? {
		SecKeyCreateDecryptedData(privateKey, .rsaEncryptionPKCS1, Data(ciphertext) as CFData, nil).map { [UInt8]($0 as Data) }
	}
}

final class AppleRSATests: XCTestCase {
	func testEncryptionDecryptsWithTheSystem() throws {
		let key = try SystemRSAKey()
		let parsed = try AppleRSAPublicKey(spki: key.spki)
		XCTAssertEqual(parsed.byteLength, 256)

		let message = Array("identity block".utf8)
		let ciphertext = try parsed.encrypt(message)

		XCTAssertEqual(ciphertext.count, 256)
		XCTAssertEqual(key.decrypt(ciphertext), message)
	}

	func testRejectsGarbageAndOversizeMessages() throws {
		XCTAssertThrowsError(try AppleRSAPublicKey(spki: [0x30, 0x03, 0x01, 0x02, 0x03]))

		let parsed = try AppleRSAPublicKey(spki: try SystemRSAKey().spki)
		XCTAssertThrowsError(try parsed.encrypt([UInt8](repeating: 1, count: 246))) // 256 - 11 + 1
		XCTAssertNoThrow(try parsed.encrypt([UInt8](repeating: 1, count: 245)))
	}
}

// MARK: - A scripted Mac

/// The server side of Apple's SRP login, built from the same maths.
final class ScriptedMac {
	let variant: VNCProtocol.AppleSRPVariant
	let password: String
	/// What to do after a valid proof.
	var finalResult: UInt32 = 0
	var corruptServerProof = false

	let rsaKey: SystemRSAKey?
	private(set) var receivedUsername: String?
	private(set) var writes: [[UInt8]] = []

	private let n = BigUInteger(Data(AppleSRPClient.rfc5054Modulus))
	private let g = BigUInteger(5)
	private let salt = appleSecureRandomBytes(32)
	private let iterations = 1000
	private let b = BigUInteger(Data(appleSecureRandomBytes(32)))
	private var bigB = BigUInteger(0)
	private var verifier = BigUInteger(0)
	private let options = Array("mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2".utf8)

	private(set) var wrapKey: [UInt8] = []

	var inbound: [UInt8] = []

	init(variant: VNCProtocol.AppleSRPVariant, password: String) throws {
		self.variant = variant
		self.password = password
		self.rsaKey = variant == .rsaWrapped ? try SystemRSAKey() : nil
	}

	private func u16(_ v: Int) -> [UInt8] { [UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)] }
	private func u32(_ v: Int) -> [UInt8] { [UInt8(v >> 24 & 0xFF), UInt8(v >> 16 & 0xFF), UInt8(v >> 8 & 0xFF), UInt8(v & 0xFF)] }

	func receive(_ data: [UInt8]) throws {
		writes.append(data)

		switch (variant, writes.count) {
			case (.rsaWrapped, 1):
				XCTAssertEqual(data.count, 15)
				XCTAssertEqual(Array(data.prefix(1)), [33])
				XCTAssertEqual(Array(data[1...]), u32(10) + [1, 0] + Array("RSA1".utf8) + [0, 0, 0, 0])
				let spki = rsaKey!.spki
				let block = [0, 1] + u32(spki.count) + spki + [0]
				inbound += u32(block.count) + block

			case (.rsaWrapped, 2):
				XCTAssertEqual(data.count, 654)
				XCTAssertEqual(Array(data[0..<14]), u32(650) + [1, 0] + Array("RSA1".utf8) + [0, 2, 1, 0])
				XCTAssertEqual(Array(data[270...]), [UInt8](repeating: 0, count: 384))
				let identity = try XCTUnwrap(rsaKey!.decrypt(Array(data[14..<270])))
				receivedUsername = try parseIdentity(identity)
				try sendChallenge()

			case (.cleartext, 1):
				XCTAssertEqual(data[0], 36)
				let count = Int(data[1]) << 24 | Int(data[2]) << 16 | Int(data[3]) << 8 | Int(data[4])
				XCTAssertEqual(count, data.count - 5)
				receivedUsername = try parseIdentity(Array(data[5...]))
				try sendChallenge()

			default:
				try handleProof(data)
		}
	}

	private func parseIdentity(_ identity: [UInt8]) throws -> String {
		XCTAssertEqual(Int(identity[3]), identity.count - 4) // length of the rest
		let nameLength = Int(identity[4]) << 24 | Int(identity[5]) << 16 | Int(identity[6]) << 8 | Int(identity[7])
		XCTAssertEqual(identity.count, nameLength + 11)
		XCTAssertEqual(Array(identity.suffix(3)), [0, 0, 0])
		return String(decoding: identity[8..<8 + nameLength], as: UTF8.self)
	}

	private func sendChallenge() throws {
		let stretched = try AppleKeyDerivation.pbkdf2SHA512(password: Array(password.utf8), salt: salt,
															iterations: iterations, keyLength: 128)
		let inner = AppleHash.sha512([0x3A], stretched)
		let x = BigUInteger(Data(AppleHash.sha512(salt, inner)))
		verifier = g.power(x, modulus: n)

		let k = BigUInteger(Data(AppleHash.sha512(AppleSRPClient.padded(n), AppleSRPClient.padded(g))))
		bigB = (k * verifier + g.power(b, modulus: n)) % n

		var fields: [UInt8] = [0]
		fields += u16(512) + AppleSRPClient.rfc5054Modulus
		fields += u16(1) + [5]
		fields += [UInt8(salt.count)] + salt
		fields += u16(512) + AppleSRPClient.padded(bigB)
		fields += (0..<8).map { UInt8(iterations >> ((7 - $0) * 8) & 0xFF) }
		fields += u16(options.count) + options

		switch variant {
			case .rsaWrapped:
				let block = u32(2) + u16(fields.count + 4) + u16(0) + u16(fields.count) + fields
				// count minus 6 is the second field: block is 10 + fields
				var framed = block
				framed[4] = UInt8((block.count - 6) >> 8 & 0xFF)
				framed[5] = UInt8((block.count - 6) & 0xFF)
				inbound += u32(framed.count) + framed
			case .cleartext:
				let block = u32(fields.count) + fields
				inbound += u32(block.count) + block
		}
	}

	private func handleProof(_ data: [UInt8]) throws {
		// Pull the inner block out of the wire packet.
		let inner: [UInt8]
		switch variant {
			case .rsaWrapped:
				let innerLength = Int(data[16]) << 8 | Int(data[17])
				XCTAssertEqual(data.count, 18 + innerLength + 384, "packet size")
				inner = Array(data[18..<18 + innerLength])
			case .cleartext:
				let innerLength = Int(data[4]) << 24 | Int(data[5]) << 16 | Int(data[6]) << 8 | Int(data[7])
				XCTAssertEqual(data.count, 8 + innerLength)
				inner = Array(data[8...])
		}

		var cursor = BlockCursor(inner)
		let aBytes = try cursor.bytes(count: Int(try cursor.uint16()))
		let m1 = try cursor.bytes(count: Int(try cursor.byte()))
		let echoedOptions = try cursor.bytes(count: Int(try cursor.uint16()))
		let random = try cursor.bytes(count: Int(try cursor.byte()))
		XCTAssertTrue(cursor.isAtEnd)
		XCTAssertEqual(aBytes.count, 512)
		XCTAssertEqual(echoedOptions, options)
		XCTAssertEqual(random.count, 16)

		let bigA = BigUInteger(Data(aBytes))
		let u = BigUInteger(Data(AppleHash.sha512(AppleSRPClient.padded(bigA), AppleSRPClient.padded(bigB))))
		let s = ((bigA * verifier.power(u, modulus: n)) % n).power(b, modulus: n)
		let key = AppleHash.sha512(AppleSRPClient.padded(s))

		let hashN = AppleHash.sha512(AppleSRPClient.padded(n))
		let hashG = AppleHash.sha512(AppleSRPClient.padded(g))
		let expected = AppleHash.sha512(zip(hashN, hashG).map { $0 ^ $1 }, AppleHash.sha512([]), salt,
										AppleSRPClient.padded(bigA), AppleSRPClient.padded(bigB), key)

		guard expected == m1 else {
			// Wrong password: a small failure code, no block.
			inbound += u32(variant == .rsaWrapped ? 6 : 1)
			return
		}

		var m2 = AppleHash.sha512(AppleSRPClient.padded(bigA), m1, key)
		if corruptServerProof { m2[0] ^= 1 }
		wrapKey = Array(AppleHash.sha256(key).prefix(16))

		let tail: [UInt8] = [64] + m2 + [16] + appleSecureRandomBytes(16) + u16(0) + u32(0)

		switch variant {
			case .rsaWrapped:
				var block = u32(2) + u16(tail.count + 4) + u16(0) + u16(tail.count) + tail
				block[4] = UInt8((block.count - 6) >> 8 & 0xFF)
				block[5] = UInt8((block.count - 6) & 0xFF)
				inbound += u32(block.count) + block
			case .cleartext:
				let block = u32(tail.count) + tail
				inbound += u32(block.count) + block
		}

		inbound += u32(Int(finalResult))
	}
}

/// A connection whose far end is a ScriptedMac.
final class ScriptedConnection: NetworkConnectionReading, NetworkConnectionWriting {
	let mac: ScriptedMac

	init(mac: ScriptedMac) { self.mac = mac }

	func read(minimumLength: Int, maximumLength: Int) async throws -> Data {
		guard mac.inbound.count >= minimumLength else { throw VNCError.connection(.closed) }

		let count = min(maximumLength, mac.inbound.count)
		defer { mac.inbound.removeFirst(count) }

		return Data(mac.inbound.prefix(count))
	}

	func write(data: Data) async throws {
		try mac.receive([UInt8](data))
	}
}

final class AppleSRPLoginTests: XCTestCase {
	private func run(_ variant: VNCProtocol.AppleSRPVariant, password: String, mac: ScriptedMac) async throws -> VNCProtocol.AppleSRPAuthentication.Outcome {
		let connection = ScriptedConnection(mac: mac)
		let credential = VNCUsernamePasswordCredential(username: "tést", password: password)

		return try await VNCProtocol.AppleSRPAuthentication(variant: variant).perform(connection: connection, credential: credential)
	}

	private func assertLogin(_ variant: VNCProtocol.AppleSRPVariant, file: StaticString = #filePath, line: UInt = #line) async throws {
		let mac = try ScriptedMac(variant: variant, password: "correct horse")
		let outcome = try await run(variant, password: "correct horse", mac: mac)

		XCTAssertEqual(mac.receivedUsername, "tést", file: file, line: line)
		XCTAssertEqual(outcome.wrapKey, mac.wrapKey, file: file, line: line)
		XCTAssertEqual(outcome.wrapKey.count, 16, file: file, line: line)
	}

	func testType33Login() async throws { try await assertLogin(.rsaWrapped) }
	func testType36Login() async throws { try await assertLogin(.cleartext) }

	func testWrongPasswordIsReportedAsLoginFailed() async throws {
		for variant in [VNCProtocol.AppleSRPVariant.rsaWrapped, .cleartext] {
			let mac = try ScriptedMac(variant: variant, password: "correct horse")

			do {
				_ = try await run(variant, password: "wrong", mac: mac)
				XCTFail("expected failure")
			} catch VNCError.authentication(.appleLoginFailed) {
			}
		}
	}

	func testCorrectPasswordRefusedByTheMac() async throws {
		let mac = try ScriptedMac(variant: .rsaWrapped, password: "pw")
		mac.finalResult = 1

		do {
			_ = try await run(.rsaWrapped, password: "pw", mac: mac)
			XCTFail("expected refusal")
		} catch VNCError.authentication(.appleLoginRefused) {
		}
	}

	func testFakeServerProofIsRejected() async throws {
		let mac = try ScriptedMac(variant: .cleartext, password: "pw")
		mac.corruptServerProof = true

		do {
			_ = try await run(.cleartext, password: "pw", mac: mac)
			XCTFail("expected proof failure")
		} catch VNCError.authentication(.appleServerProofInvalid) {
		}
	}

	func testClientRefusesUnknownGroupAndHugeIterationCounts() throws {
		func challenge(modulus: [UInt8]? = nil, iterations: UInt64 = 1000) -> AppleSRPChallenge {
			AppleSRPChallenge(modulus: modulus ?? AppleSRPClient.rfc5054Modulus, generator: [5], salt: [1, 2, 3],
							  serverPublicValue: [UInt8](repeating: 7, count: 512), iterations: iterations, options: [])
		}

		XCTAssertNoThrow(try AppleSRPClient(challenge: challenge()))
		XCTAssertThrowsError(try AppleSRPClient(challenge: challenge(modulus: [UInt8](repeating: 0xFF, count: 512))))
		XCTAssertThrowsError(try AppleSRPClient(challenge: challenge(iterations: 1_000_001)))
		XCTAssertThrowsError(try AppleSRPClient(challenge: AppleSRPChallenge(modulus: AppleSRPClient.rfc5054Modulus, generator: [5], salt: [1],
																				  serverPublicValue: [0], iterations: 10, options: [])))
	}
}

// MARK: - Records and the rekey

final class AppleRecordCodecTests: XCTestCase {
	private let key = [UInt8](0..<16)
	private let vector = [UInt8](100..<116)

	func testRecordsRoundTripAndChain() throws {
		let sender = AppleRecordCodec(key: key, initialVector: vector)
		let receiver = AppleRecordCodec(key: key, initialVector: vector)

		for length in [0, 1, 6, 10, 11, 14, 16, 30, 1000, AppleRecordCodec.maximumBodyLength] {
			let body = (0..<length).map { UInt8($0 & 0xFF) }
			let record = try sender.seal(body)
			let ciphertextLength = Int(record[0]) << 8 | Int(record[1])

			XCTAssertEqual(ciphertextLength, record.count - 2)
			XCTAssertEqual(ciphertextLength % 16, 0)
			XCTAssertEqual(try receiver.open(Array(record[2...])), body, "length \(length)")
		}
	}

	func testPlaintextLayoutAndCheck() throws {
		// A 6-byte body: 2 + 6 + 20 = 28, so 4 filler bytes make 32.
		let sender = AppleRecordCodec(key: key, initialVector: vector)
		let record = try sender.seal([1, 2, 3, 4, 5, 6])
		XCTAssertEqual(record.count, 2 + 32)

		let plain = try AES(key: key, blockMode: CBC(iv: vector), padding: .noPadding).decrypt(Array(record[2...]))
		XCTAssertEqual(Array(plain[0..<8]), [0, 6, 1, 2, 3, 4, 5, 6])
		XCTAssertEqual(Array(plain[8..<12]), [0, 0, 0, 0])
		XCTAssertEqual(Array(plain[12...]), Digest.sha1([0, 0, 0, 0] + plain[0..<12]))
	}

	func testSequenceNumbersAreStrictAndTamperingIsCaught() throws {
		let sender = AppleRecordCodec(key: key, initialVector: vector)
		let first = try sender.seal([1])
		let second = try sender.seal([2])

		// Records out of order fail the counter check.
		let outOfOrder = AppleRecordCodec(key: key, initialVector: vector)
		XCTAssertThrowsError(try outOfOrder.open(Array(second[2...])))

		var flipped = Array(first[2...])
		flipped[3] ^= 0x40
		XCTAssertThrowsError(try AppleRecordCodec(key: key, initialVector: vector).open(flipped))

		XCTAssertThrowsError(try AppleRecordCodec(key: key, initialVector: vector).open([1, 2, 3]))
	}

	func testRekeyUnwrapsKeyAndVector() throws {
		let wrapKey = [UInt8](repeating: 9, count: 16)
		let ecb = try AES(key: wrapKey, blockMode: ECB(), padding: .noPadding)
		let codec = try AppleRecordCodec.fromRekey(wrapKey: wrapKey,
												   wrappedKey: try ecb.encrypt(key),
												   wrappedVector: try ecb.encrypt(vector))
		let direct = AppleRecordCodec(key: key, initialVector: vector)

		XCTAssertEqual(try codec.seal([1, 2, 3]), try direct.seal([1, 2, 3]))
	}
}
