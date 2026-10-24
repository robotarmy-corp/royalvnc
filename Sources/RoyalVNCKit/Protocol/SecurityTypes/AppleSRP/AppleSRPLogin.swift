// Apple's SRP login messages: RFB security types 33 and 36.
//
// Type 33 asks the Mac for its RSA public key, sends the account name
// encrypted under it, then runs SRP. Type 36 sends the account name in the
// clear and runs the same SRP. The arithmetic is in AppleSRPMath.swift.
//
// Written from docs/protocols/apple-auth-spec.md sections 3 and 5.
//
// ── Change log (newest first) ──────────────────────────────────────────────
//  v1.1  2026-10-24  Trims white space from the user name. A trailing space,
//                    which iOS adds after a keyboard suggestion, made a
//                    correct login fail as a wrong password.
//  v1.0  2026-10-18  New. Both login types, the server proof check, and the
//                    SecurityResult. Sends the selector byte in the same
//                    write as the first message, as the spec requires.
// ───────────────────────────────────────────────────────────────────────────

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCProtocol {
	/// Which of Apple's two SRP logins.
	enum AppleSRPVariant {
		/// Type 33: RSA-wrapped identity, then SRP.
		case rsaWrapped
		/// Type 36: identity in the clear, then SRP.
		case cleartext

		var selector: UInt8 {
			switch self {
				case .rsaWrapped: 33
				case .cleartext: 36
			}
		}
	}

	struct AppleSRPAuthentication {
		/// What the login leaves behind for the encrypted session.
		struct Outcome {
			/// Unwraps the session key sent in the rekey.
			let wrapKey: [UInt8]
		}

		let variant: AppleSRPVariant

		/// Bytes of the 10-byte header on type 33 blocks.
		private static let envelopeHeaderLength = 10
		private static let blockSizeRange = 16...4096
		private static let paddingLength = 384
		private static let tag = Array("RSA1".utf8)
		private static let version: [UInt8] = [0x01, 0x00]
	}
}

// MARK: - Login
extension VNCProtocol.AppleSRPAuthentication {
	/// Runs the whole login, including the SecurityResult.
	func perform(connection: NetworkConnectionReading & NetworkConnectionWriting,
				 credential: VNCUsernamePasswordCredential,
				 logger: VNCLogger? = nil) async throws -> Outcome {
		let username = Array(credential.appleAccountName.utf8)

		let challengeBlock: [UInt8]

		switch variant {
			case .rsaWrapped:
				challengeBlock = try await requestChallengeRSAWrapped(connection: connection,
																		 username: username)
			case .cleartext:
				challengeBlock = try await requestChallengeCleartext(connection: connection,
																	 username: username)
		}

		let challenge = try parseChallenge(challengeBlock)

		logger?.logDebug("Apple SRP: challenge received, \(challenge.iterations) PBKDF2 rounds")

		let client: AppleSRPClient

		do {
			client = try AppleSRPClient(challenge: challenge)
			try client.computeProof(password: credential.password)
		} catch {
			throw VNCError.authentication(.securityHandshakingFailed(reason: "\(error)"))
		}

		try await connection.write(data: Data(proofPacket(client: client)))

		// Either a block with the server proof, or a small failure code.
		let first = try await connection.readUInt32()

		guard Self.blockSizeRange.contains(Int(first)) else {
			throw VNCError.authentication(.appleLoginFailed)
		}

		let finalBlock = [UInt8](try await connection.readBuffered(length: Int(first)))
		let serverProof = try parseFinalBlock(finalBlock)

		guard client.verifyServerProof(serverProof) else {
			throw VNCError.authentication(.appleServerProofInvalid)
		}

		let result = try await connection.readUInt32()

		guard result == 0 else {
			throw VNCError.authentication(.appleLoginRefused)
		}

		return Outcome(wrapKey: client.wrapKey)
	}
}

// MARK: - First messages and the challenge
private extension VNCProtocol.AppleSRPAuthentication {
	func requestChallengeRSAWrapped(connection: NetworkConnectionReading & NetworkConnectionWriting,
									username: [UInt8]) async throws -> [UInt8] {
		// Selector and the 14-byte key request, in one write.
		var request: [UInt8] = [variant.selector]
		request += uint32(10) + Self.version + Self.tag + uint16(0) + uint16(0)

		try await connection.write(data: Data(request))

		let keyBlock = [UInt8](try await readBlock(connection: connection))

		// Two bytes, a 4-byte DER length, then the key. A trailing byte is ignored.
		guard keyBlock.count >= 6 else { throw VNCError.protocol(.invalidData) }

		let derLength = Int(keyBlock[2]) << 24 | Int(keyBlock[3]) << 16 | Int(keyBlock[4]) << 8 | Int(keyBlock[5])

		guard derLength > 0, 6 + derLength <= keyBlock.count else {
			throw VNCError.protocol(.invalidData)
		}

		let publicKey: AppleRSAPublicKey

		do {
			publicKey = try AppleRSAPublicKey(spki: Array(keyBlock[6..<6 + derLength]))
		} catch {
			throw VNCError.protocol(.invalidData)
		}

		// The identity: length of the rest, name length, name, three zero bytes.
		let identity = identityBlock(username: username)

		let ciphertext: [UInt8]

		do {
			ciphertext = try publicKey.encrypt(identity)
		} catch {
			throw VNCError.authentication(.encryptionFailed)
		}

		let count = Self.envelopeHeaderLength + ciphertext.count + Self.paddingLength

		var packet: [UInt8] = uint32(UInt32(count)) + Self.version + Self.tag
		packet += uint16(2) + uint16(UInt16(ciphertext.count)) + ciphertext
		packet += [UInt8](repeating: 0, count: Self.paddingLength)

		try await connection.write(data: Data(packet))

		return [UInt8](try await readBlock(connection: connection))
	}

	func requestChallengeCleartext(connection: NetworkConnectionReading & NetworkConnectionWriting,
								   username: [UInt8]) async throws -> [UInt8] {
		let identity = identityBlock(username: username)

		// Selector, count, identity: one write. The Mac closes the connection
		// if the selector arrives alone.
		let packet: [UInt8] = [variant.selector] + uint32(UInt32(identity.count)) + identity

		try await connection.write(data: Data(packet))

		return [UInt8](try await readBlock(connection: connection))
	}

	func identityBlock(username: [UInt8]) -> [UInt8] {
		let count = UInt32(username.count)

		return uint32(count + 7) + uint32(count) + username + [0, 0, 0]
	}

	func readBlock(connection: NetworkConnectionReading) async throws -> Data {
		let count = Int(try await connection.readUInt32())

		guard Self.blockSizeRange.contains(count) else {
			throw VNCError.protocol(.invalidData)
		}

		return try await connection.readBuffered(length: count)
	}

	/// Where the variable fields start, after the type's own header.
	func fieldsOffset(of block: [UInt8]) throws -> Int {
		switch variant {
			case .rsaWrapped:
				// Header: the value 2, count minus 6, zero, count minus 10.
				guard block.count > Self.envelopeHeaderLength,
					  Int(block[4]) << 8 | Int(block[5]) == block.count - 6,
					  Int(block[8]) << 8 | Int(block[9]) == block.count - 10 else {
					throw VNCError.protocol(.invalidData)
				}

				return Self.envelopeHeaderLength

			case .cleartext:
				// Header: one 4-byte length equal to count minus 4.
				guard block.count > 4,
					  Int(readUInt32(block, at: 0)) == block.count - 4 else {
					throw VNCError.protocol(.invalidData)
				}

				return 4
		}
	}

	func parseChallenge(_ block: [UInt8]) throws -> AppleSRPChallenge {
		var cursor = BlockCursor(block, offset: try fieldsOffset(of: block))

		_ = try cursor.byte() // control flag

		let modulus = try cursor.bytes(count: Int(try cursor.uint16()))
		let generator = try cursor.bytes(count: Int(try cursor.uint16()))
		let salt = try cursor.bytes(count: Int(try cursor.byte()))
		let serverPublicValue = try cursor.bytes(count: Int(try cursor.uint16()))
		let iterations = try cursor.uint64()
		let options = try cursor.bytes(count: Int(try cursor.uint16()))

		// The fields must end exactly at the end of the block.
		guard cursor.isAtEnd else { throw VNCError.protocol(.invalidData) }

		return AppleSRPChallenge(modulus: modulus,
								 generator: generator,
								 salt: salt,
								 serverPublicValue: serverPublicValue,
								 iterations: iterations,
								 options: options)
	}
}

// MARK: - Proof and final block
private extension VNCProtocol.AppleSRPAuthentication {
	func proofPacket(client: AppleSRPClient) -> [UInt8] {
		let options = client.challenge.options

		// Inner block: A, M1, the options string unchanged, a client random.
		var inner: [UInt8] = uint16(UInt16(client.publicValue.count)) + client.publicValue
		inner += [UInt8(client.clientProof.count)] + client.clientProof
		inner += uint16(UInt16(options.count)) + options
		inner += [16] + appleSecureRandomBytes(16)

		switch variant {
			case .rsaWrapped:
				let count = Self.envelopeHeaderLength + 4 + inner.count + Self.paddingLength

				var packet: [UInt8] = uint32(UInt32(count)) + Self.version + Self.tag
				packet += uint16(2) + uint16(UInt16(inner.count + 4))
				packet += uint16(0) + uint16(UInt16(inner.count)) + inner
				packet += [UInt8](repeating: 0, count: Self.paddingLength)

				return packet

			case .cleartext:
				return uint32(UInt32(inner.count + 4)) + uint32(UInt32(inner.count)) + inner
		}
	}

	/// Returns the server proof M2 from the final block.
	func parseFinalBlock(_ block: [UInt8]) throws -> [UInt8] {
		var cursor = BlockCursor(block, offset: try fieldsOffset(of: block))

		let proof = try cursor.bytes(count: Int(try cursor.byte()))
		_ = try cursor.bytes(count: Int(try cursor.byte())) // server random
		_ = try cursor.bytes(count: Int(try cursor.uint16())) // empty string
		_ = try cursor.uint32()

		guard cursor.isAtEnd, proof.count == 64 else {
			throw VNCError.protocol(.invalidData)
		}

		return proof
	}
}

// MARK: - Account name
extension VNCUsernamePasswordCredential {
	/// The user name with leading and trailing white space removed. iOS adds
	/// a space after a tapped keyboard suggestion, and the Mac then refuses
	/// the login as a wrong password (seen on mm2018, 2026-10-24). Mac account
	/// names never start or end with a space. The password is never trimmed.
	var appleAccountName: String {
		var characters = Substring(username)

		while characters.first?.isWhitespace == true { characters.removeFirst() }
		while characters.last?.isWhitespace == true { characters.removeLast() }

		return String(characters)
	}
}

// MARK: - Byte helpers
private func uint16(_ value: UInt16) -> [UInt8] {
	[UInt8(value >> 8), UInt8(value & 0xFF)]
}

private func uint32(_ value: UInt32) -> [UInt8] {
	[UInt8(value >> 24), UInt8((value >> 16) & 0xFF), UInt8((value >> 8) & 0xFF), UInt8(value & 0xFF)]
}

private func readUInt32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
	bytes[offset..<offset + 4].reduce(0) { $0 << 8 | UInt32($1) }
}

/// Reads big-endian fields from a block, failing instead of running off the end.
struct BlockCursor {
	private let bytes: [UInt8]
	private var position: Int

	init(_ bytes: [UInt8], offset: Int = 0) {
		self.bytes = bytes
		self.position = offset
	}

	var isAtEnd: Bool { position == bytes.count }

	mutating func bytes(count: Int) throws -> [UInt8] {
		guard count >= 0, position + count <= bytes.count else {
			throw VNCError.protocol(.invalidData)
		}

		defer { position += count }

		return Array(bytes[position..<position + count])
	}

	mutating func byte() throws -> UInt8 {
		try bytes(count: 1)[0]
	}

	mutating func uint16() throws -> UInt16 {
		try bytes(count: 2).reduce(0) { $0 << 8 | UInt16($1) }
	}

	mutating func uint32() throws -> UInt32 {
		try bytes(count: 4).reduce(0) { $0 << 8 | UInt32($1) }
	}

	mutating func uint64() throws -> UInt64 {
		try bytes(count: 8).reduce(0) { $0 << 8 | UInt64($1) }
	}
}
