// The choice a Mac can offer after an Apple login (types 33 and 36):
// share the screen of the person at the console, once they approve, or log
// in to a session of the login account's own.
//
// The app answers through VNCConnection.sessionSelectionHandler. Without a
// handler the library picks for itself: its own session if offered, else
// asking to share the console.
//
// ── Change log (newest first) ──────────────────────────────────────────────
//  v1.0  2026-10-18  New. Request and choice types for the session-selection
//                    block (docs/protocols/apple-auth-spec.md section 6).
// ───────────────────────────────────────────────────────────────────────────

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// What the Mac offers.
public struct VNCSessionSelectionRequest: Sendable {
	/// Ask the person at the console to approve sharing their screen.
	public let canShareConsole: Bool

	/// Log in to the login account's own session, with nobody's approval.
	public let canUseOwnSession: Bool

	/// Display name of the person at the console. Empty when nobody is signed
	/// in. Personal data: show it, do not log or store it.
	public let consoleUserName: String

	/// The raw offer mask, for diagnostics.
	public let mask: UInt32
}

public enum VNCSessionSelectionChoice: Sendable {
	case shareConsole
	case ownSession
	case cancel
}

public typealias VNCSessionSelectionHandler = @Sendable (_ request: VNCSessionSelectionRequest,
														 _ completion: @escaping @Sendable (VNCSessionSelectionChoice) -> Void) -> Void

public extension VNCSessionSelectionRequest {
	/// The library's own pick when the app gives no handler.
	var defaultChoice: VNCSessionSelectionChoice {
		if canUseOwnSession { return .ownSession }
		if canShareConsole { return .shareConsole }
		return .cancel
	}
}
