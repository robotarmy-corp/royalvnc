// Clipboard redirection: watching the local pasteboard and sending changes.
//
// ── Change log (newest first, robotarmy-corp fork) ─────────────────────────
//  v1.1  2026-10-24  No local pasteboard watching when
//                    settings.isClipboardMonitoringEnabled is false.
//  v1.0  (upstream)  As inherited from royalapplications/royalvnc 2026-09-21.
// ───────────────────────────────────────────────────────────────────────────

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension VNCConnection {
	func startMonitoringClipboard() {
		guard settings.isClipboardRedirectionEnabled,
			  settings.isClipboardMonitoringEnabled else { return }

		clipboardMonitor.startMonitoring()
	}

	func stopMonitoringClipboard() {
		guard settings.isClipboardRedirectionEnabled else { return }

		clipboardMonitor.stopMonitoring()
	}
}

// MARK: - VNCClipboardMonitorDelegate
extension VNCConnection: VNCClipboardMonitorDelegate {
	func clipboardMonitorShouldMonitor(_ clipboardMonitor: VNCClipboardMonitor) -> Bool {
		let isConnected = connectionState.status == .connected

		return isConnected
	}

	func clipboardMonitor(_ clipboardMonitor: VNCClipboardMonitor,
						  didChangeText text: String) {
		logger.logDebug("Clipboard Monitor did change text")

		guard settings.isClipboardRedirectionEnabled else { return }

		enqueueClientCutTextMessage(text)
	}
}
