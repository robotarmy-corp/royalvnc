// Authentication errors.
//
// ── Change log (newest first, robotarmy-corp fork) ─────────────────────────
//  v1.1  2026-10-18  Cases for Apple's SRP login (types 33 and 36): wrong
//                    password, a correct password the Mac still refuses, a
//                    server proof that does not check out, and the session
//                    prompt shown when another account is at the console.
//  v1.0  (upstream)  As inherited from royalapplications/royalvnc 2026-09-21.
// ───────────────────────────────────────────────────────────────────────────

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

public extension VNCError {
	enum AuthenticationError: Error, LocalizedError {
		case serverOfferedNoAuthTypes(reason: String?)
		case clientCouldNotDecideOnSecurityType
		case securityHandshakingFailed(reason: String?)
		case noAuthenticationDataProvided
		case ardAuthenticationFailed
		case ultraVNCMSLogonIIAuthenticationFailed
		case encryptionFailed
		case appleLoginFailed
		case appleLoginRefused
		case appleServerProofInvalid
		case appleSessionSelectionRequired

		// MARK: - LocalizedError
		public var errorDescription: String? {
			// TODO: Localize
			switch self {
				case .serverOfferedNoAuthTypes(let reason):
					return combinedErrorDescription("The Server offered no authentication types.",
													reason: reason)
				case .clientCouldNotDecideOnSecurityType:
					return "The Client could not decide on a Security Type."
				case .securityHandshakingFailed(let reason):
					return combinedErrorDescription("Security handshaking failed.",
													reason: reason)
				case .noAuthenticationDataProvided:
					return "No authentication data was provided."
				case .ardAuthenticationFailed:
					return "Apple Remote Desktop authentication failed."
				case .ultraVNCMSLogonIIAuthenticationFailed:
					return "UltraVNC MS-Logon II authentication failed."
				case .encryptionFailed:
					return "Encryption failed."
				case .appleLoginFailed:
					return "The Mac did not accept the user name or password."
				case .appleLoginRefused:
					return "The password is right, but the Mac refused this account. It may not be allowed to use Screen Sharing."
				case .appleServerProofInvalid:
					return "The Mac's answer did not prove it knows the password. Not connecting."
				case .appleSessionSelectionRequired:
					return "Another account is signed in at the Mac. Choosing a session is not supported yet."
			}
		}
	}
}

private extension VNCError.AuthenticationError {
	func combinedErrorDescription(_ baseErrorDescription: String,
								  reason: String?) -> String {
		let unwrappedReason: String

		if let reason = reason {
			unwrappedReason = reason
		} else {
			unwrappedReason = ""
		}

		return "\(baseErrorDescription)\(unwrappedReason.isEmpty ? "" : " Reason provided by the Server: \(unwrappedReason)")"
	}
}
