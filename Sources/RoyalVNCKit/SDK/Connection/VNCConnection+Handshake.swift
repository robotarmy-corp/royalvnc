// The RFB handshake: version, security type choice, authentication.
//
// ── Change log (newest first, robotarmy-corp fork) ─────────────────────────
//  v1.4  2026-10-18  With settings.appleSessionSelection, answers an Apple
//                    server's "RFB 003.889" with the same banner (spec 1). Live on mm2018,
//                    a 3.8 answer kept the Mac from offering session
//                    selection; Apple's own client answers 3.889. Reads
//                    ServerInit's flag for a following session-selection
//                    block and passes it to the session setup.
//  v1.3  2026-10-18  Passes the login and the app's session-selection
//                    handler to the Apple session setup.
//  v1.2  2026-10-18  Apple SRP logins (types 33 and 36). They send the selector
//                    together with their first message, send ClientInit 0xC1,
//                    and switch on the encrypted session before SetPixelFormat.
//  v1.1  2026-10-17  decideSecurityType honours settings.preferredSecurityTypes
//                    before falling back to the built-in order.
//  v1.0  (upstream)  As inherited from royalapplications/royalvnc 2026-09-21.
// ───────────────────────────────────────────────────────────────────────────

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// MARK: - Entry Point for Handshaking Phase
extension VNCConnection {
	func handshake() async throws {
		try await receiveProtocolVersion()
	}
}

// MARK: - Handshaking Phase Implementation
private extension VNCConnection {
	func receiveProtocolVersion() async throws {
		let protocolVersion: VNCProtocol.ProtocolVersion

		do {
			protocolVersion = try await VNCProtocol.ProtocolVersion.receive(connection: connection)

			logger.logDebug("Received Server Protocol Version: \(protocolVersion.protocolVersion)")

			state.serverProtocolVersion = protocolVersion
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Receive Protocol Version",
																 underlyingError: error)
		}

		try await sendProtocolVersion(serverProtocolVersion: protocolVersion)
	}

	func sendProtocolVersion(serverProtocolVersion: VNCProtocol.ProtocolVersion) async throws {
		do {
			let clientProtocolVersion: VNCProtocol.ProtocolVersion
			let maxSupportedProtocolVersion = maxSupportedProtocolVersion

			// The max. protocol version we currently support is 3.8, so check if the server is within those limits, otherwise downgrade to 3.8
			if serverProtocolVersion.isAppleRemoteDesktop, settings.appleSessionSelection {
				// Apple's Screen Sharing: echo its banner. Apple's extensions,
				// session selection among them, depend on it.
				clientProtocolVersion = serverProtocolVersion
			} else if serverProtocolVersion.majorVersion <= maxSupportedProtocolVersion.majorVersion,
			   serverProtocolVersion.minorVersion <= maxSupportedProtocolVersion.minorVersion {
				// Server reported a protocol version equal or lower to 3.8, use it
				clientProtocolVersion = serverProtocolVersion
			} else {
				// Server reported a protocol version higher than 3.8, so make sure we use 3.8 and not any higher protocol version that the server offered
				clientProtocolVersion = .init(majorVersion: maxSupportedProtocolVersion.majorVersion,
											  minorVersion: maxSupportedProtocolVersion.minorVersion)
			}

			try await VNCProtocol.ProtocolVersion.send(connection: connection,
													   protocolVersion: clientProtocolVersion)

			logger.logDebug("Sent Client Protocol Version: \(clientProtocolVersion.protocolVersion)")

			state.agreedProtocolVersion = clientProtocolVersion
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send Protocol Version",
																 underlyingError: error)
		}

		try await receiveNumberOfSecurityTypes()
	}

	func receiveNumberOfSecurityTypes() async throws {
		let number: UInt8

		do {
			let numberOfSecurityTypes = try await VNCProtocol.NumberOfSecurityTypes.receive(connection: connection)
			number = numberOfSecurityTypes.number

			logger.logDebug("Reveived Number of Security Types: \(number)")
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Receive Number of Security Types",
																 underlyingError: error)
		}

		guard number > 0 else {
			let reason = try? await VNCProtocol.NumberOfSecurityTypes.receiveFailureReason(connection: connection)

			throw VNCError.authentication(.serverOfferedNoAuthTypes(reason: reason))
		}

		try await receiveSecurityTypes(number: number)
	}

	func receiveSecurityTypes(number: UInt8) async throws {
		let securityTypes: VNCProtocol.SecurityTypes

		do {
			securityTypes = try await VNCProtocol.SecurityTypes.receive(connection: connection,
																		number: number)

			logger.logDebug("Received Security Types: \(securityTypes.securityTypes.map({ "\($0)" }))")
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Receive Security Types",
																 underlyingError: error)
		}

		try await decideSecurityType(supportedTypes: securityTypes)
	}

	func decideSecurityType(supportedTypes: VNCProtocol.SecurityTypes) async throws {
		let chosenSecurityType: VNCProtocol.SecurityType

		let supportedSecurityTypes = supportedTypes.securityTypes

		// The types this library can actually authenticate with.
		let implemented: [VNCProtocol.SecurityType] = [.none, .diffieHellman, .ultraVNCMSLogonII, .vnc, .tight, .apple33, .apple36]

		let preferred = settings.preferredSecurityTypes
			.compactMap { VNCProtocol.SecurityType(rawValue: $0) }
			.first { supportedSecurityTypes.contains($0) && implemented.contains($0) }

		if let preferred {
			chosenSecurityType = preferred
		} else if !settings.preferredSecurityTypes.isEmpty {
			// The caller asked for specific types and the server offers none of them.
			throw VNCError.authentication(.clientCouldNotDecideOnSecurityType)
		} else if supportedSecurityTypes.contains(.none) {
			chosenSecurityType = .none
		} else if supportedSecurityTypes.contains(.diffieHellman) {
			chosenSecurityType = .diffieHellman
		} else if supportedSecurityTypes.contains(.ultraVNCMSLogonII) {
			chosenSecurityType = .ultraVNCMSLogonII
		} else if supportedSecurityTypes.contains(.vnc) {
			chosenSecurityType = .vnc
		} else if supportedSecurityTypes.contains(.tight) {
			chosenSecurityType = .tight
		} else {
			chosenSecurityType = .invalid
		}

		guard chosenSecurityType != .invalid,
			  supportedTypes.securityTypes.contains(chosenSecurityType) else {
			throw VNCError.authentication(.clientCouldNotDecideOnSecurityType)
		}

		try await sendAuthenticationData(securityType: chosenSecurityType)
	}

	func sendAuthenticationData(securityType: VNCProtocol.SecurityType) async throws {
		// Apple's SRP logins send the selector in the same write as their first message.
		if securityType == .apple33 || securityType == .apple36 {
			try await performAppleSRPAuthentication(securityType: securityType)

			return
		}

		do {
			try await VNCProtocol.SecurityTypes.send(connection: connection,
													 securityType: securityType.rawValue)
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send Authentication Data",
																 underlyingError: error)
		}

		logger.logDebug("Sent Security Type: \(securityType)")

		let shouldRequestSecurityTypeResult: Bool

		switch securityType {
			case .none:
				if let protocolVersion = state.agreedProtocolVersion {
					// Only servers 3.8+ send a security result when no authentication is configured
					shouldRequestSecurityTypeResult = protocolVersion.is3Point8OrHigher
				} else {
					shouldRequestSecurityTypeResult = true
				}
			case .vnc:
				shouldRequestSecurityTypeResult = true

				try await performVNCAuthentication()
			case .diffieHellman:
				shouldRequestSecurityTypeResult = true

				try await performARDAuthentication()
			case .ultraVNCMSLogonII:
				shouldRequestSecurityTypeResult = true

				try await performUltraVNCMSLogonIIAuthentication()
//			case .tight:
//				shouldRequestSecurityTypeResult = true
//				isTightSecurityEnabled = true
//
//				// TODO: Implement
			default:
				shouldRequestSecurityTypeResult = true
		}

		if shouldRequestSecurityTypeResult {
			try await receiveSecurityTypeResult()
		}

		try await sendClientInit()
	}

	func performAppleSRPAuthentication(securityType: VNCProtocol.SecurityType) async throws {
		let variant: VNCProtocol.AppleSRPVariant = securityType == .apple33 ? .rsaWrapped : .cleartext

		logger.logDebug("Using Security Type: \(securityType)")

		let credential = try await askDelegateForUsernamePasswordCredential(authenticationType: .appleRemoteDesktop)

		let outcome: VNCProtocol.AppleSRPAuthentication.Outcome

		do {
			outcome = try await VNCProtocol.AppleSRPAuthentication(variant: variant)
				.perform(connection: connection, credential: credential, logger: logger)
		} catch let error as VNCError {
			throw error
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Apple SRP Login",
																 underlyingError: error)
		}

		logger.logDebug("Apple SRP login succeeded")

		appleCredential = credential

		try await sendClientInit(appleWrapKey: outcome.wrapKey)
	}

	func performVNCAuthentication() async throws {
		let auth = try await VNCProtocol.VNCAuthentication.receive(connection: connection)

		let credential = try await askDelegateForPasswordCredential(authenticationType: auth.authenticationType)

		try await auth.send(connection: connection,
							credential: credential)
	}

	func performARDAuthentication() async throws {
		let auth = try await VNCProtocol.ARDAuthentication.receive(connection: connection)

		let credential = try await askDelegateForUsernamePasswordCredential(authenticationType: auth.authenticationType)

		try await auth.send(connection: connection,
							credential: credential)
	}

	func performUltraVNCMSLogonIIAuthentication() async throws {
		let auth = try await VNCProtocol.UltraVNCMSLogonIIAuthentication.receive(connection: connection)

		let credential = try await askDelegateForUsernamePasswordCredential(authenticationType: auth.authenticationType)

		try await auth.send(connection: connection,
							credential: credential)
	}

	func receiveSecurityTypeResult() async throws {
		let result: VNCProtocol.SecurityResult

		do {
			result = try await VNCProtocol.SecurityResult.receive(connection: connection)
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Receive Security Type Result",
																 underlyingError: error)
		}

		guard let actualResult = result.result else {
			throw VNCError.protocol(.invalidData)
		}

		logger.logDebug("Received Security Type Result: \(actualResult)")

		guard actualResult == .ok else {
			let reason: String?

			// Only servers 3.8+ send a reason
			if let protocolVersion = state.agreedProtocolVersion,
			   protocolVersion.is3Point8OrHigher {
				reason = try? await VNCProtocol.SecurityResult.receiveFailureReason(connection: connection)
			} else {
				reason = nil
			}

			throw VNCError.authentication(.securityHandshakingFailed(reason: reason))
		}
	}

	func sendClientInit(appleWrapKey: [UInt8]? = nil) async throws {
		let isShared = settings.isShared

		do {
			if appleWrapKey != nil {
				// Apple's viewer sends 0xC1: the shared flag plus its own flags.
				try await connection.write(value: 0xC1)
			} else {
				try await VNCProtocol.ClientInit.send(connection: connection,
													  isShared: isShared)
			}
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send Client Init",
																 underlyingError: error)
		}

		logger.logDebug("Sent Client Init")

		try await receiveServerInit(appleWrapKey: appleWrapKey)
	}

	func receiveServerInit(appleWrapKey: [UInt8]? = nil) async throws {
		let serverInit: VNCProtocol.ServerInit

		do {
			serverInit = try await VNCProtocol.ServerInit.receive(connection: connection,
																  isTightSecurityEnabled: state.isTightSecurityEnabled,
																  lenientName: appleWrapKey != nil)
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Receive Server Init",
																 underlyingError: error)
		}

		logger.logDebug("Received Server Init \(serverInit)")

		if let appleWrapKey {
			// Everything after this point travels in encrypted records.
			let handler = sessionSelectionHandler

			// Observed on mm2018: bit 0x04 of byte 5 of the name field is set
			// when a session-selection block follows ServerInit.
			let field = serverInit.appleNameField
			let selectionExpected = field.count > 5 && field[5] & 0x04 != 0

			try await VNCProtocol.AppleSession.establish(connection: connection,
														 wrapKey: appleWrapKey,
														 credential: appleCredential ?? VNCUsernamePasswordCredential(username: "", password: ""),
														 chooser: { request in
				guard let handler else { return request.defaultChoice }

				return await withCheckedContinuation { continuation in
					handler(request) { continuation.resume(returning: $0) }
				}
			},
														 selectionExpected: selectionExpected,
														 logger: logger)
			appleCredential = nil
		}

		state.framebufferWidth = serverInit.framebufferWidth
		state.framebufferHeight = serverInit.framebufferHeight
		state.desktopName = serverInit.name

		let serverPixelFormat = serverInit.pixelFormat

		// Force our own pixel format
		let clientPixelFormat = VNCProtocol.PixelFormat(depth: settings.colorDepth.rawValue)

		logger.logDebug("Forcing pixel format: \(clientPixelFormat)")

		// Use server pixel format
//		let clientPixelFormat = serverPixelFormat

		state.serverPixelFormat = serverPixelFormat
		state.pixelFormat = clientPixelFormat

		do {
			try await sendSetPixelFormat(clientPixelFormat)
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send Set Pixel Format",
																 underlyingError: error)
		}

		let supportedEncodingTypes = try orderedEncodingTypes()

		do {
			try await sendSetEncodings(supportedEncodingTypes)
		} catch {
			throw VNCError.ConnectionError.closedDuringHandshake(handshakingPhase: "Send Set Encodings",
																 underlyingError: error)
		}

		let framebufferSize = VNCSize(width: serverInit.framebufferWidth,
									  height: serverInit.framebufferHeight)

        let newFramebuffer = try VNCFramebuffer(logger: logger,
                                                size: framebufferSize,
                                                screens: [ ],
                                                pixelFormat: clientPixelFormat,
                                                allocator: framebufferAllocator)

		newFramebuffer.delegate = self

		self.framebuffer = newFramebuffer

		clientToServerMessageQueue.clear()

		notifyDelegateAboutFramebufferCreation(newFramebuffer)
	}

	func sendSetPixelFormat(_ pixelFormat: VNCProtocol.PixelFormat) async throws {
		let sendPixelFormatMessage = VNCProtocol.SetPixelFormat(pixelFormat: pixelFormat)

		try await sendPixelFormatMessage.send(connection: connection)
	}

	func sendSetEncodings(_ encodings: [VNCEncodingType]) async throws {
		let setEncodingsMessage = VNCProtocol.SetEncodings(encodingTypes: encodings)

		try await setEncodingsMessage.send(connection: connection)
	}
}
